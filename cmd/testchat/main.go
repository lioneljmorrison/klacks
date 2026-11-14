// Command testchat is an interactive CLI test client for the klacks chat
// server. It registers one device with the reference E2EE client (package
// client), drives messaging commands from stdin over a WebSocket, and
// manages rooms through the server's dev-only REST endpoints
// (/v1/dev/rooms) — so it is a pure wire client: no database access, no
// KLACKS_* store configuration.
//
// Run it against a live dev stack:
//
//	make up migrate-up run   # dev server listening on :8090
//	go run ./cmd/testchat -user alice
//
// Human-readable names resolve to UUIDs deterministically (internal/names,
// mirrored by the browser test client): -user alice is one user everywhere,
// /create standup is one room everywhere. Canonical UUIDs are accepted
// anywhere a name is.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/lioneljmorrison/klacks/client"
	"github.com/lioneljmorrison/klacks/internal/names"
)

// cmdTimeout bounds every shell command's network work: a hung server must
// not hang the prompt.
const cmdTimeout = 15 * time.Second

func main() {
	var (
		base    = flag.String("base", "http://localhost:8090", "chat server base URL (REST and WebSocket)")
		userS   = flag.String("user", "", "user name or UUID; default: a fresh random v4")
		deviceS = flag.String("device", "", "device name or UUID under -user; default: the name \"cli\"")
		name    = flag.String("name", "testchat", "display label used in the prompt")
		fresh   = flag.Bool("fresh", false, "discard this device's saved keys and generate new ones")
		debug   = flag.Bool("debug", false, "verbose diagnostics on stderr")
	)
	flag.Parse()

	// -user alice is one user everywhere; empty stays a fresh random v4,
	// echoed so a later run can reuse it with -user/-device. The device
	// defaults to "cli" under the resolved user, so the same -user name
	// yields the same identity on every run.
	userStr, err := resolveUserString(*userS)
	if err != nil {
		fmt.Fprintln(os.Stderr, "testchat:", err)
		os.Exit(2)
	}
	user, err := parseUUID(userStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "testchat:", err)
		os.Exit(2)
	}
	deviceStr := *deviceS
	if deviceStr == "" {
		deviceStr = "cli"
	}
	deviceStr = names.Device(userStr, deviceStr)
	device, err := parseUUID(deviceStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "testchat:", err)
		os.Exit(2)
	}

	// The device's keys persist on disk: the same name is the same device
	// every run, so peers' sessions survive restarts. -fresh starts over.
	keyPath, err := keyFilePath(user, device)
	if err != nil {
		fmt.Fprintln(os.Stderr, "testchat:", err)
		os.Exit(2)
	}
	// Before reading or replacing anything: a second copy of this device
	// must not start, not even with -fresh (it would swap the keys under
	// the running one).
	release, err := lockDevice(keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "testchat:", err)
		os.Exit(2)
	}
	defer release()
	var ks *keyState
	if !*fresh {
		ks, err = loadKeys(keyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "testchat: saved keys unusable (%v); run with -fresh to start over\n", err)
			os.Exit(2)
		}
	}
	if ks == nil {
		// New keys make any saved sessions meaningless: drop them.
		if err := os.Remove(sessionsPath(keyPath)); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(os.Stderr, "testchat:", err)
			os.Exit(2)
		}
		ks, err = freshKeys()
		if err != nil {
			fmt.Fprintln(os.Stderr, "testchat:", err)
			os.Exit(2)
		}
		if err := saveKeys(keyPath, ks); err != nil {
			fmt.Fprintln(os.Stderr, "testchat:", err)
			os.Exit(2)
		}
	}

	a := &app{
		base:    strings.TrimSuffix(*base, "/"),
		name:    *name,
		user:    user,
		device:  device,
		debug:   *debug,
		httpc:   &http.Client{},
		rooms:   make(map[[16]byte]*roomInfo),
		keys:    ks,
		keyPath: keyPath,
		out:     os.Stdout,
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := a.run(context.Background(), log); err != nil {
		log.Error("testchat", "err", err)
		os.Exit(1)
	}
}

// resolveUserString resolves the -user flag: a canonical UUID passes
// through (lowercased), anything else is a name under the shared namespace.
func resolveUserString(s string) (string, error) {
	if s == "" {
		u, err := randomUUID()
		if err != nil {
			return "", err
		}
		return uuidString(u), nil
	}
	if names.IsUUID(s) {
		return strings.ToLower(s), nil
	}
	return names.User(s), nil
}

// app is one test session: the client and the shell's shared state.
type app struct {
	base   string
	name   string
	user   [16]byte
	device [16]byte
	debug  bool
	httpc  *http.Client

	// keys and keyPath back this device's persisted key material; keys is
	// re-saved whenever the client's prekeys change (/replenish).
	keys    *keyState
	keyPath string

	c *client.Client
	// registered is set during startup only, before the shell runs, so it
	// needs no lock.
	registered bool

	mu        sync.Mutex // guards connected, dialed and the room bookkeeping
	connected bool
	dialed    bool
	rooms     map[[16]byte]*roomInfo
	// subscribed holds the rooms subscribed on the current connection. A
	// room record (rooms) is not a subscription: /members, /invite and
	// /remove create one without subscribing. A new connection starts
	// with none.
	subscribed map[[16]byte]bool

	outMu sync.Mutex
	out   io.Writer // the shell's output, os.Stdout outside tests

	saveMu sync.Mutex // serializes saveState (shell sends, pump deliveries)
}

// run wires the session, serves the shell until /quit, EOF or SIGINT, and
// cleans everything up. Setup that makes messaging impossible (a dead
// server) degrades to warnings instead: the shell stays up so the user can
// /status, retry with /register and /dial, or /quit.
func (a *app) run(ctx context.Context, log *slog.Logger) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// SIGINT joins /quit: cancel in-flight commands and unblock the stdin
	// scanner (closing os.Stdin makes its blocked Read fail), then fall
	// through to the same cleanup.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)
	go func() {
		select {
		case <-sig:
			a.outf("")
			a.outf("interrupted — quitting (use /quit for a clean exit)")
			cancel()
			_ = os.Stdin.Close()
		case <-ctx.Done():
		}
	}()

	c, err := clientFromKeys(a.base, a.user, a.device, a.keys)
	if err != nil {
		return fmt.Errorf("build client: %w", err)
	}
	// The sessions saved by the last run: peers keep sealing over them, so
	// restoring them is what lets their messages decrypt after a restart.
	if err := restoreSessions(c, a.keyPath); err != nil {
		return fmt.Errorf("saved sessions unusable (%w); run with -fresh to start over", err)
	}
	// Save before every publish: see saveState.
	c.SetBeforePublish(a.saveState)
	a.c = c

	a.outf("user %s  device %s  base %s", uuidString(a.user), uuidString(a.device), a.base)
	pumpDone := a.pump()

	regCtx, regCancel := context.WithTimeout(ctx, cmdTimeout)
	// The bundle registers once per device: the keys are persisted, so the
	// server's copy stays valid across runs, and re-uploading it wholesale
	// would resurrect one-time prekeys peers have already consumed. A
	// server whose data was wiped (make nuke) needs /register by hand.
	if a.keys.Registered {
		a.registered = true
		a.outf("bundle already registered (keys restored from %s); /register re-uploads it", a.keyPath)
	} else if err := c.Register(regCtx); err != nil {
		a.outf("register failed: %v", err)
		a.outf("is the dev server running at %s? messaging needs a registered device — /register once it is", a.base)
	} else {
		a.keys.Registered = true
		if err := saveKeys(a.keyPath, a.keys); err != nil {
			a.outf("registered, but saving the key state failed: %v", err)
		}
		a.registered = true
		a.outf("registered device %s for user %s", uuidString(a.device), uuidString(a.user))
	}
	regCancel()

	if err := a.dial(ctx); err != nil {
		a.outf("dial failed: %v (use /dial to retry)", err)
	}

	a.outf("type /help for commands")
	a.shell(ctx)
	return a.shutdown(pumpDone)
}

// dial connects the WebSocket and marks the session connected. Dialing
// again after /drop replaces the connection: keys, sessions and room
// bookkeeping all survive.
func (a *app) dial(ctx context.Context) error {
	if err := a.c.Dial(ctx); err != nil {
		return err
	}
	a.forgetSubscriptions()
	a.mu.Lock()
	a.connected = true
	a.dialed = true
	a.mu.Unlock()
	return nil
}

// needsSubscribe reports whether room is not subscribed on the current
// connection.
func (a *app) needsSubscribe(room [16]byte) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return !a.subscribed[room]
}

// markSubscribed records a subscribe or resume of room on the current
// connection.
func (a *app) markSubscribed(room [16]byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.subscribed == nil {
		a.subscribed = make(map[[16]byte]bool)
	}
	a.subscribed[room] = true
}

// forgetSubscriptions drops every subscription: the server keeps them per
// connection, so a new connection has none.
func (a *app) forgetSubscriptions() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.subscribed = nil
}

// friendlyReject turns the reference client's rejection errors into plain
// sentences. The common one: a message sealed over a session this device
// no longer holds — its saved sessions were discarded (-fresh) or lost.
func friendlyReject(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "message authentication failed"):
		return "sealed over a session this device no longer holds (-fresh, or its saved sessions were lost), so it can't decrypt"
	case strings.Contains(msg, "none held"):
		return "it used a one-time prekey this process no longer holds"
	default:
		return msg
	}
}

// pump prints inbox and error events as they arrive and tracks the furthest
// seq seen per room for /resume's default. It exits when Close closes the
// client's channels.
func (a *app) pump() <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case r, ok := <-a.c.Inbox:
				if !ok {
					return
				}
				a.noteSeq(r.Room, r.Seq)
				// The delivery advanced (or created) a session: save it.
				if err := a.saveState(); err != nil {
					a.outf("saving state failed: %v", err)
				}
				if r.Err != nil {
					a.outf("[rejected] room=%s seq=%d sender=%s: %s",
						uuidString(r.Room), r.Seq, uuidString(r.Sender), friendlyReject(r.Err))
					a.prompt()
					continue
				}
				a.outf("[room %s seq=%d] %s: %s",
					uuidString(r.Room), r.Seq, uuidString(r.Sender), r.Plaintext)
				a.prompt()
			case err, ok := <-a.c.Errs:
				if !ok {
					return
				}
				a.outf("server: %v", err)
			}
		}
	}()
	return done
}

// shell reads commands from stdin until /quit, EOF (Ctrl-D) or a closed
// stdin (SIGINT). Each command runs under its own timeout so a hung server
// cannot hang the prompt.
func (a *app) shell(ctx context.Context) {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for {
		a.prompt()
		if !in.Scan() {
			return // EOF, or stdin closed by SIGINT
		}
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		cmdCtx, cancel := context.WithTimeout(ctx, cmdTimeout)
		cont := a.handle(cmdCtx, line)
		cancel()
		if !cont {
			return
		}
	}
}

// shutdown closes the client (which closes Inbox and Errs once its read
// loop has exited), syncs the keyfile with whatever prekeys initiations
// consumed this run, and waits for the pump. A session that never dialed
// skips Close: with no connection there is nothing to close.
func (a *app) shutdown(pumpDone <-chan struct{}) error {
	a.mu.Lock()
	dialed := a.dialed
	a.mu.Unlock()
	if a.c != nil && dialed {
		a.c.Close()
	}
	select {
	case <-pumpDone:
	case <-time.After(2 * time.Second):
	}
	if a.c != nil {
		if err := a.saveState(); err != nil {
			a.outf("saving state failed: %v", err)
		}
	}
	return nil
}

// rest does one JSON REST call against the dev server with this device's
// identity headers — the same dev auth the prekey endpoints use.
func (a *app) rest(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("X-Klacks-User", uuidString(a.user))
	req.Header.Set("X-Klacks-Device", uuidString(a.device))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, string(data))
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("%s %s: %w", method, path, err)
		}
	}
	return nil
}
