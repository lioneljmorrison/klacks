package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lioneljmorrison/klacks/client"
)

func testApp(t *testing.T) (*app, *bytes.Buffer) {
	t.Helper()
	var out bytes.Buffer
	ks, err := freshKeys()
	if err != nil {
		t.Fatal(err)
	}
	return &app{
		name:    "t",
		user:    [16]byte{1},
		rooms:   make(map[[16]byte]*roomInfo),
		out:     &out,
		keys:    ks,
		keyPath: filepath.Join(t.TempDir(), "dev.json"),
	}, &out
}

// A room record exists as soon as /members, /invite or /remove touches the
// room; none of them subscribes. /send must still subscribe, or the CLI
// sends into a room it never hears back from.
func TestRoomRecordDoesNotCountAsSubscribed(t *testing.T) {
	a, _ := testApp(t)
	room := [16]byte{9}
	a.recordMember(room, [16]byte{2}) // what /invite and /members leave behind
	if !a.needsSubscribe(room) {
		t.Fatal("a room only recorded by /invite or /members reads as subscribed")
	}
	a.markSubscribed(room)
	if a.needsSubscribe(room) {
		t.Fatal("a subscribed room still needs subscribing")
	}
}

// A new connection carries no subscriptions: after /drop and /dial every
// room needs subscribing again.
func TestDialForgetsSubscriptions(t *testing.T) {
	a, _ := testApp(t)
	room := [16]byte{9}
	a.markSubscribed(room)
	a.forgetSubscriptions()
	if !a.needsSubscribe(room) {
		t.Fatal("a room subscribed on the old connection reads as subscribed on the new one")
	}
}

// The pump re-prints the prompt after every inbox event, rejected ones
// included, and does not promise that new messages decrypt.
func TestPumpRejectedLine(t *testing.T) {
	a, out := testApp(t)
	c, err := client.NewClient("http://test.invalid", a.user, [16]byte{3})
	if err != nil {
		t.Fatal(err)
	}
	a.c = c
	done := a.pump()
	c.Inbox <- client.Received{Room: [16]byte{9}, Seq: 3, Err: errors.New("decrypt: message authentication failed")}
	// Wait for the line before closing: Close also closes Errs, and the
	// pump may take that branch first and exit before reading Inbox.
	var got string
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		a.outMu.Lock()
		got = out.String()
		a.outMu.Unlock()
		if strings.Contains(got, "[rejected]") && strings.HasSuffix(got, "t>> ") {
			break
		}
	}
	c.Close()
	<-done

	if !strings.HasSuffix(got, "t>> ") {
		t.Fatalf("no prompt after a rejected line; output:\n%q", got)
	}
	if strings.Contains(got, "new messages work") {
		t.Fatalf("rejection text promises new messages decrypt, which is false after a restart:\n%s", got)
	}
}

// /create's summary names the other members; the creator is "you".
func TestOtherMembersExcludesSelf(t *testing.T) {
	self := uuidString([16]byte{1})
	got := otherMembers([]string{self, "b", "c"}, self)
	if strings.Join(got, ",") != "b,c" {
		t.Fatalf("otherMembers = %v, want [b c]", got)
	}
}

// The device's state — key file and session snapshot — is saved owner-only
// next to each other, and a restart restores the sessions from it.
func TestStateSavedAndRestored(t *testing.T) {
	a, _ := testApp(t)
	a.device = [16]byte{2}
	ks := a.keys
	var err error
	if a.c, err = clientFromKeys("http://test.invalid", a.user, a.device, ks); err != nil {
		t.Fatal(err)
	}
	if err := a.saveState(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{a.keyPath, sessionsPath(a.keyPath)} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("%s not saved: %v", p, err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v, want 0600", p, fi.Mode().Perm())
		}
	}
	c2, err := clientFromKeys("http://test.invalid", a.user, a.device, ks)
	if err != nil {
		t.Fatal(err)
	}
	if err := restoreSessions(c2, a.keyPath); err != nil {
		t.Fatalf("restore: %v", err)
	}
}

// With no saved sessions (a first run, or -fresh) restoring is a no-op.
func TestRestoreWithoutSavedSessions(t *testing.T) {
	c, err := client.NewClient("http://test.invalid", [16]byte{1}, [16]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	if err := restoreSessions(c, filepath.Join(t.TempDir(), "none.json")); err != nil {
		t.Fatalf("restore without a file: %v", err)
	}
}

// One device runs in one process at a time. Two processes with the same
// keys build the same sessions from the same incoming messages and then
// seal at the same chain positions — the same key and nonce twice.
func TestSecondProcessForSameDeviceRefused(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "dev.json")
	release, err := lockDevice(keyPath)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	if _, err := lockDevice(keyPath); err == nil {
		t.Fatal("a second process for the same device was allowed to start")
	}
	release()
	again, err := lockDevice(keyPath)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	again()
}

// /replenish and the pump's per-delivery save both write the key state:
// they must not race (run with -race), and the replenished keys must be
// on disk afterwards.
func TestReplenishDoesNotRaceDeliverySaves(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	a, _ := testApp(t)
	a.base = srv.URL
	a.httpc = srv.Client()
	c, err := clientFromKeys(srv.URL, a.user, [16]byte{3}, a.keys)
	if err != nil {
		t.Fatal(err)
	}
	a.c = c
	stop := make(chan struct{})
	saved := make(chan struct{})
	go func() {
		defer close(saved)
		for {
			select {
			case <-stop:
				return
			default:
				if err := a.saveState(); err != nil {
					t.Error(err)
					return
				}
			}
		}
	}()
	for i := 0; i < 5; i++ {
		a.cmdReplenish(context.Background(), []string{"3"})
	}
	close(stop)
	<-saved
	ks, err := loadKeys(a.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(ks.OneTimePrekeys), c.OneTimePrekeysHeld(); got != want {
		t.Fatalf("key file holds %d one-time prekeys, client holds %d", got, want)
	}
}

// saveState writes the sessions before the key file: a crash between the
// two must not leave a key file that has dropped a consumed one-time
// prekey while the session built from it never reached the disk. A
// sessions write that fails therefore leaves the key file untouched.
func TestSaveStateWritesSessionsBeforeKeys(t *testing.T) {
	a, _ := testApp(t)
	c, err := clientFromKeys("http://test.invalid", a.user, [16]byte{3}, a.keys)
	if err != nil {
		t.Fatal(err)
	}
	a.c = c
	if err := saveKeys(a.keyPath, a.keys); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(a.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	a.keys.Registered = true // a change the next save would write
	// A directory where the sessions file goes makes its rename fail.
	if err := os.Mkdir(sessionsPath(a.keyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sessionsPath(a.keyPath), "x"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.saveState(); err == nil {
		t.Fatal("saveState succeeded with an unwritable sessions file")
	}
	after, err := os.ReadFile(a.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("the key file was rewritten although the sessions write failed")
	}
}

// /replenish saves the new private halves before uploading the public
// ones: a crash in between must not leave keys on the server this device
// can never answer. A save that fails therefore uploads nothing.
func TestReplenishSavesBeforeUpload(t *testing.T) {
	uploads := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uploads++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	a, out := testApp(t)
	a.base = srv.URL
	a.httpc = srv.Client()
	c, err := clientFromKeys(srv.URL, a.user, [16]byte{3}, a.keys)
	if err != nil {
		t.Fatal(err)
	}
	a.c = c
	// A directory where the sessions file goes makes saveState fail.
	if err := os.MkdirAll(filepath.Join(sessionsPath(a.keyPath), "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	a.cmdReplenish(context.Background(), []string{"3"})
	if uploads != 0 {
		t.Fatalf("uploaded %d time(s) although saving the keys failed: %s", uploads, out)
	}
}

// S-42: after a restart, /join and /resume pick up where the device left
// off — the last seq its restored client state consumed — not from 0, so
// the room's history is not shown again.
func TestResumePointFromRestoredState(t *testing.T) {
	a, _ := testApp(t)
	c, err := client.NewClient("http://test.invalid", [16]byte{1}, [16]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	room := [16]byte{9}
	state := `{"v":2,"sessions":[],"fallbacks":[],"rooms":[{"room":[9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"started":true,"last_seq":7,"seen":[{"seq":7,"id":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}]}]}`
	if err := c.RestoreState([]byte(state)); err != nil {
		t.Fatal(err)
	}
	a.c = c
	if got := a.resumePoint(room); got != 7 {
		t.Fatalf("resumePoint = %d; want 7", got)
	}
	if got := a.resumePoint([16]byte{8}); got != 0 {
		t.Fatalf("resumePoint of an unknown room = %d; want 0", got)
	}
}

// S-49: room seen sets go to an append-only log next to the state file,
// not into it: a save writes only what is new. A state saved before S-49
// (seen sets inside) migrates on the first save, and a restart restores
// the seen sets from the log.
func TestSeenLog(t *testing.T) {
	a, _ := testApp(t)
	a.device = [16]byte{2}
	var err error
	if a.c, err = clientFromKeys("http://test.invalid", a.user, a.device, a.keys); err != nil {
		t.Fatal(err)
	}
	room := [16]byte{9}
	legacy := `{"v":2,"sessions":[],"fallbacks":[],"rooms":[{"room":[9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"started":true,"last_seq":2,` +
		`"seen":[{"seq":1,"id":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]},{"seq":2,"id":[2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}]}]}`
	if err := a.c.RestoreState([]byte(legacy)); err != nil {
		t.Fatal(err)
	}
	for range 2 { // the second save logs nothing new
		if err := a.saveState(); err != nil {
			t.Fatal(err)
		}
	}
	state, err := os.ReadFile(sessionsPath(a.keyPath))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(state), `"seen":[{`) {
		t.Errorf("state file still carries seen entries: %s", state)
	}
	logb, err := os.ReadFile(seenLogPath(a.keyPath))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(logb), "\n"); n != 2 {
		t.Errorf("seen log has %d lines; want 2:\n%s", n, logb)
	}
	// A torn last line (a crash mid-append) is ignored.
	f, err := os.OpenFile(seenLogPath(a.keyPath), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"room":[9,0`)
	_ = f.Close()

	c2, err := clientFromKeys("http://test.invalid", a.user, a.device, a.keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := restoreSessions(c2, a.keyPath); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if seq, ok := c2.LastSeq(room); !ok || seq != 2 {
		t.Errorf("LastSeq = %d, %v; want 2", seq, ok)
	}
	full, err := c2.MarshalState()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(full), `"seq":1`) || !strings.Contains(string(full), `"seq":2`) {
		t.Errorf("restored state lacks the logged seen entries: %s", full)
	}
}
