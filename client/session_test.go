package client

// Session-level loopback: two clients over the real prekey REST layer (an
// in-memory device store behind httpapi), delivering envelopes to each
// other the way the wire would. The WebSocket itself is exercised by the
// end-to-end integration test (S-26).

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/lioneljmorrison/klacks/internal/api/httpapi"
	"github.com/lioneljmorrison/klacks/internal/auth"
	"github.com/lioneljmorrison/klacks/internal/config"
	"github.com/lioneljmorrison/klacks/internal/protocol"
	"github.com/lioneljmorrison/klacks/internal/store"
)

// memDevices is an in-memory DeviceStore: the upload/fetch/consume
// semantics the server implements, minus the database.
type memDevices struct {
	mu      sync.Mutex
	bundles map[[32]byte]store.Bundle
	prekeys map[[32]byte][]store.OneTimePrekey
}

func deviceKey(user, device [16]byte) [32]byte {
	var k [32]byte
	copy(k[:16], user[:])
	copy(k[16:], device[:])
	return k
}

func (m *memDevices) UploadBundle(_ context.Context, user, device [16]byte, b store.Bundle, prekeys []store.OneTimePrekey) error {
	if err := store.ValidateBundle(b); err != nil {
		return fmt.Errorf("devices: %w: %w", store.ErrInvalidBundle, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bundles[deviceKey(user, device)] = b
	m.prekeys[deviceKey(user, device)] = prekeys
	return nil
}

func (m *memDevices) AddOneTimePrekeys(_ context.Context, user, device [16]byte, prekeys []store.OneTimePrekey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := deviceKey(user, device)
	if _, ok := m.bundles[k]; !ok {
		return store.ErrDeviceNotFound
	}
	m.prekeys[k] = append(m.prekeys[k], prekeys...)
	return nil
}

// Bundle fetch consumes one prekey, never handing the same one twice.
func (m *memDevices) Bundle(_ context.Context, user, device [16]byte) (store.Bundle, store.Taken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := deviceKey(user, device)
	b, ok := m.bundles[k]
	if !ok {
		return store.Bundle{}, store.Taken{}, fmt.Errorf("devices: %x/%x: %w", user, device, store.ErrDeviceNotFound)
	}
	var taken store.Taken
	if len(m.prekeys[k]) > 0 {
		taken.OneTimePrekey = m.prekeys[k][0]
		m.prekeys[k] = m.prekeys[k][1:]
	}
	taken.Remaining = len(m.prekeys[k])
	return b, taken, nil
}

func (m *memDevices) ListDevices(_ context.Context, user [16]byte) ([]store.Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Device
	for k, b := range m.bundles {
		var u, d [16]byte
		copy(u[:], k[:16])
		copy(d[:], k[16:])
		if u != user {
			continue
		}
		out = append(out, store.Device{UserID: u, DeviceID: d, Bundle: b})
	}
	return out, nil
}

// restDevices serves the prekey endpoints over memDevices.
func restDevices(t *testing.T) string {
	t.Helper()
	srv := httpapi.NewServer(config.HTTP{}, httpapi.NewHealth(nil, 0, nil),
		nil, httpapi.NewDevices(auth.Dev{}, &memDevices{
			bundles: make(map[[32]byte]store.Bundle),
			prekeys: make(map[[32]byte][]store.OneTimePrekey),
		}, nil), testLogger())
	ts := newTestServer(t, srv.Handler())
	return ts.URL
}

// deliverOf builds the deliver frame a server would send for a sealed
// envelope.
func deliverOf(room [16]byte, seq int64, sender *Client, e encryptResult) protocol.Deliver {
	return protocol.Deliver{
		RoomID:     protocol.UUID(room),
		Seq:        seq,
		MessageID:  protocol.UUID(e.MessageID),
		SenderID:   protocol.UUID(sender.user),
		DeviceID:   protocol.UUID(sender.device),
		Header:     e.Header,
		Ciphertext: e.Ciphertext,
	}
}

func TestSessionLoopback(t *testing.T) {
	base := restDevices(t)
	ctx := context.Background()
	alice, err := NewClient(base, [16]byte{1}, [16]byte{0xA1})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewClient(base, [16]byte{2}, [16]byte{0xB1})
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.Register(ctx); err != nil {
		t.Fatal(err)
	}
	if err := bob.Register(ctx); err != nil {
		t.Fatal(err)
	}

	room := [16]byte{9}
	peerBob := Peer{User: bob.user, Device: bob.device}
	peerAlice := Peer{User: alice.user, Device: alice.device}

	// Alice's first message establishes the session and consumes one of
	// Bob's one-time prekeys.
	e, err := alice.sealFor(ctx, room, peerBob, []byte("hello bob"))
	if err != nil {
		t.Fatal(err)
	}
	alice.handleDeliver(deliverOf(room, 1, alice, e)) // her own echo: not for her
	select {
	case r := <-alice.Inbox:
		t.Fatalf("own echo leaked: %+v", r)
	default:
	}
	bob.handleDeliver(deliverOf(room, 1, alice, e))
	got := inbox(t, bob)
	if string(got.Plaintext) != "hello bob" || got.Err != nil {
		t.Fatalf("bob got %+v", got)
	}

	// Bob replies through his own session (he initiates one to Alice).
	e2, err := bob.sealFor(ctx, room, peerAlice, []byte("hi alice"))
	if err != nil {
		t.Fatal(err)
	}
	bob.handleDeliver(deliverOf(room, 2, bob, e2))
	alice.handleDeliver(deliverOf(room, 2, bob, e2))
	got = inbox(t, alice)
	if string(got.Plaintext) != "hi alice" || got.Err != nil {
		t.Fatalf("alice got %+v", got)
	}

	// A few more rounds, interleaved, over the established sessions. The
	// server delivers a publish back to its sender too (protocol.md), so
	// each client also takes its own echo: not for its device, dropped
	// for decryption, but part of the room's seq stream for ordering.
	for i := 0; i < 5; i++ {
		seqA, seqB := int64(3+2*i), int64(4+2*i)
		ea, err := alice.sealFor(ctx, room, peerBob, []byte(fmt.Sprintf("a%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		alice.handleDeliver(deliverOf(room, seqA, alice, ea)) // own echo
		bob.handleDeliver(deliverOf(room, seqA, alice, ea))
		if r := inbox(t, bob); string(r.Plaintext) != fmt.Sprintf("a%d", i) || r.Err != nil {
			t.Fatalf("round %d: bob got %+v", i, r)
		}
		eb, err := bob.sealFor(ctx, room, peerAlice, []byte(fmt.Sprintf("b%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		bob.handleDeliver(deliverOf(room, seqB, bob, eb)) // own echo
		alice.handleDeliver(deliverOf(room, seqB, bob, eb))
		if r := inbox(t, alice); string(r.Plaintext) != fmt.Sprintf("b%d", i) || r.Err != nil {
			t.Fatalf("round %d: alice got %+v", i, r)
		}
	}

	// Bob's one-time prekey was consumed exactly once: his fetch count
	// went 10 -> 9 at Alice's initiation.
	if c := bob.OneTimePrekeysHeld(); c != 9 {
		t.Fatalf("bob holds %d one-time prekeys, want 9", c)
	}
}

// inbox waits for one event, failing on timeout.
func inbox(t *testing.T, c *Client) Received {
	t.Helper()
	select {
	case r, ok := <-c.Inbox:
		if !ok {
			t.Fatal("inbox closed")
		}
		return r
	default:
		t.Fatal("no inbox event")
		return Received{}
	}
}

func TestSessionRejectsTamperedEnvelope(t *testing.T) {
	base := restDevices(t)
	ctx := context.Background()
	alice, err := NewClient(base, [16]byte{1}, [16]byte{0xA1})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewClient(base, [16]byte{2}, [16]byte{0xB1})
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.Register(ctx); err != nil {
		t.Fatal(err)
	}
	if err := bob.Register(ctx); err != nil {
		t.Fatal(err)
	}
	room := [16]byte{9}
	peerBob := Peer{User: bob.user, Device: bob.device}

	e, err := alice.sealFor(ctx, room, peerBob, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	d := deliverOf(room, 1, alice, e)

	// Flip one byte of the stored sender_id: the delivered frame differs
	// from what the envelope bound, and the AEAD check must fail.
	badSender := d
	badSender.SenderID = protocol.UUID([16]byte{0xEE})
	bob.handleDeliver(badSender)
	if r := inbox(t, bob); r.Err == nil || r.Plaintext != nil {
		t.Fatalf("tampered sender_id: %+v", r)
	}

	// Flip a ciphertext byte.
	badCT := d
	badCT.Ciphertext = append([]byte(nil), d.Ciphertext...)
	badCT.Ciphertext[0] ^= 0xFF
	bob.handleDeliver(badCT)
	if r := inbox(t, bob); r.Err == nil || r.Plaintext != nil {
		t.Fatalf("tampered ciphertext: %+v", r)
	}

	// The session is untouched: the honest delivery still decrypts.
	bob.handleDeliver(d)
	if r := inbox(t, bob); r.Err != nil || string(r.Plaintext) != "hello" {
		t.Fatalf("honest delivery after tamper attempts: %+v", r)
	}

	// A repeated message id at a different seq is a tampered stream.
	dup := d
	dup.Seq = 7
	bob.handleDeliver(dup)
	if r := inbox(t, bob); r.Err == nil {
		t.Fatalf("message id reused at a different seq: %+v", r)
	}

	// A gap in the room's seq stream is a tampered stream too.
	gap := deliverOf(room, 5, alice, e)
	gap.MessageID = protocol.UUID([16]byte{0xDD})
	gap.Ciphertext = nil // must not reach decryption; ordering fails first
	bob.handleDeliver(gap)
	if r := inbox(t, bob); r.Err == nil {
		t.Fatalf("gap accepted: %+v", r)
	}
}

// newTestServer runs h on an httptest server for the test's lifetime.
func newTestServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts
}

// testLogger discards; NewServer requires a logger.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
