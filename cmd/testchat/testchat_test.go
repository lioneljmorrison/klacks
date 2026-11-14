package main

import (
	"bytes"
	"errors"
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
