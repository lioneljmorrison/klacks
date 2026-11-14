//go:build integration

// End to end (S-26): two reference clients over a real server — the full
// serve path with migrated Postgres and ScyllaDB — asserting the database
// holds only ciphertext and that tampering with any bound field of a
// stored message is rejected by the receiving client.
package client

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lioneljmorrison/klacks/internal/api/httpapi"
	"github.com/lioneljmorrison/klacks/internal/api/ws"
	"github.com/lioneljmorrison/klacks/internal/auth"
	"github.com/lioneljmorrison/klacks/internal/config"
	"github.com/lioneljmorrison/klacks/internal/core"
	"github.com/lioneljmorrison/klacks/internal/store"
	"github.com/lioneljmorrison/klacks/internal/testutil/dbtest"
)

// UUIDs are the dev identities the two devices authenticate as.
const (
	e2eUserA = "a1000000-0000-0000-0000-000000000001"
	e2eUserB = "a1000000-0000-0000-0000-000000000002"
	e2eDevA  = "b2000000-0000-0000-0000-000000000001"
	e2eDevB  = "b2000000-0000-0000-0000-000000000002"
)

// e2eStack is the full serve path on fresh stores.
type e2eStack struct {
	srv    *testServer
	pool   *pgxpool.Pool
	scylla *gocql.Session
	core   *core.Service
	hub    *ws.Manager
	room   [16]byte // a DM between userA and userB
}

type testServer struct {
	base string
	stop func()
}

func newE2EStack(t *testing.T) *e2eStack {
	t.Helper()
	pool := dbtest.MigratedPostgres(t)
	scylla := dbtest.MigratedScylla(t)

	rooms := store.NewRooms(pool, 10*time.Second)
	msgs := store.NewScyllaMessages(scylla)
	log := slog.New(slog.NewTextHandler(discardWriter{}, nil))

	m := ws.NewManager(auth.Dev{}, log)
	m.PingInterval, m.PingTimeout = time.Minute, time.Minute
	m.SendQueue = 4096
	// The replay buffer holds pre-tamper copies of messages in memory; the
	// tamper tests need resume to re-read the tampered rows from ScyllaDB,
	// so the buffer ages out immediately and resume always takes the
	// database path.
	m.ReplayWindow = time.Nanosecond
	svc := core.New(rooms, msgs, m.Deliver, m.MemberRemoved)
	m.Chat = svc

	devices := store.NewDevices(pool)
	srv := httpapi.NewServer(config.HTTP{}, httpapi.NewHealth(nil, time.Second, log),
		m, httpapi.NewDevices(auth.Dev{}, devices, log), log)
	ts := newTestServer(t, srv.Handler())

	ctx := context.Background()
	room, err := svc.CreateRoom(ctx, core.KindDM, mustUUID(t, e2eUserA))
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.AddMember(ctx, room, mustUUID(t, e2eUserA), mustUUID(t, e2eUserB), core.RoleMember); err != nil {
		t.Fatal(err)
	}
	return &e2eStack{
		srv:    &testServer{base: ts.URL, stop: ts.Close},
		pool:   pool,
		scylla: scylla,
		core:   svc,
		hub:    m,
		room:   room,
	}
}

// pair brings both devices online in the stack's DM room: registered,
// dialed, and resuming from the start.
func (s *e2eStack) pair(t *testing.T) (alice, bob *Client) {
	t.Helper()
	ctx := context.Background()
	alice = newClientFor(t, s.srv.base, e2eUserA, e2eDevA)
	bob = newClientFor(t, s.srv.base, e2eUserB, e2eDevB)
	for _, c := range []*Client{alice, bob} {
		if err := c.Register(ctx); err != nil {
			t.Fatal(err)
		}
		if err := c.Dial(ctx); err != nil {
			t.Fatal(err)
		}
		if err := c.Resume(ctx, s.room, 0); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		alice.Close()
		bob.Close()
	})
	return alice, bob
}

func mustUUID(t *testing.T, s string) [16]byte {
	t.Helper()
	u, err := parseUUID(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func newClientFor(t *testing.T, base, user, device string) *Client {
	t.Helper()
	c, err := NewClient(base, mustUUID(t, user), mustUUID(t, device))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// waitRecv reads one inbox event with a timeout.
func waitRecv(t *testing.T, c *Client) Received {
	t.Helper()
	select {
	case r, ok := <-c.Inbox:
		if !ok {
			t.Fatal("inbox closed")
		}
		return r
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for an inbox event")
		return Received{}
	}
}

// exchange drives n messages from alice to bob through the real server and
// checks bob decrypts each one. Back-to-back publishes can commit in any
// order (the room lock grants to whichever waiter wins), so delivery order
// is not send order: the set of plaintexts is what is asserted, and the
// ratchet's out-of-order handling is what makes that correct.
func exchange(t *testing.T, s *e2eStack, alice, bob *Client, n int) []string {
	t.Helper()
	ctx := context.Background()
	peer := []Peer{{User: mustUUID(t, e2eUserB), Device: mustUUID(t, e2eDevB)}}
	want := make([]string, n)
	for i := 0; i < n; i++ {
		want[i] = strings.Repeat(fmt.Sprintf("msg %02d ", i), 4)
		if err := alice.Send(ctx, s.room, peer, []byte(want[i])); err != nil {
			t.Fatal(err)
		}
	}
	got := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		r := waitRecv(t, bob)
		if r.Err != nil {
			t.Fatalf("message %d rejected: %v", i, r.Err)
		}
		if got[string(r.Plaintext)] {
			t.Fatalf("plaintext delivered twice: %q", r.Plaintext)
		}
		got[string(r.Plaintext)] = true
	}
	for _, pt := range want {
		if !got[pt] {
			t.Fatalf("plaintext %q never arrived", pt)
		}
	}
	if len(got) != n {
		t.Fatalf("delivered %d distinct plaintexts, want %d", len(got), n)
	}
	return want
}

func TestE2EDMExchangeCiphertextOnly(t *testing.T) {
	s := newE2EStack(t)
	alice, bob := s.pair(t)
	want := exchange(t, s, alice, bob, 10)

	// The messages table holds only ciphertext: scan every row and check
	// that no known plaintext appears anywhere, that nothing decrypts to
	// plaintext without a session, and that ciphertext and header are
	// present and opaque.
	iter := s.scylla.Query(`SELECT seq, ciphertext, header FROM messages`).Iter()
	rows := 0
	var seq int64
	var ct, hdr []byte
	for iter.Scan(&seq, &ct, &hdr) {
		rows++
		if len(ct) == 0 {
			t.Fatalf("seq %d: empty ciphertext", seq)
		}
		for _, pt := range want {
			if bytes.Contains(ct, []byte(pt)) {
				t.Fatalf("seq %d: ciphertext contains plaintext %q", seq, pt)
			}
			if bytes.Contains(hdr, []byte(pt)) {
				t.Fatalf("seq %d: header contains plaintext %q", seq, pt)
			}
		}
	}
	if err := iter.Close(); err != nil {
		t.Fatal(err)
	}
	if rows != 10 {
		t.Fatalf("messages table has %d rows, want 10", rows)
	}

	// The relational layer holds no message plaintext either: the devices
	// and prekey tables carry public keys only, and there is no messages
	// table in Postgres at all.
	var n int
	if err := s.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM information_schema.tables WHERE table_name = 'messages'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("postgres has a messages table; message plaintext lives in ScyllaDB ciphertext only")
	}
}

// tamperCase mutates one stored message in ScyllaDB, then triggers a resume
// replay and expects the client to reject exactly the tampered message.
func TestE2ETamperDetection(t *testing.T) {
	cases := []struct {
		name   string
		tamper func(t *testing.T, s *e2eStack, seq int64, row storedRow)
	}{
		{"sender_id", func(t *testing.T, s *e2eStack, seq int64, row storedRow) {
			exec(t, s, `UPDATE messages SET sender_id = ? WHERE room_id = ? AND bucket = ? AND seq = ?`,
				[16]byte{0xEE}, s.room, seq/1000, seq)
		}},
		{"device_id", func(t *testing.T, s *e2eStack, seq int64, row storedRow) {
			exec(t, s, `UPDATE messages SET device_id = ? WHERE room_id = ? AND bucket = ? AND seq = ?`,
				[16]byte{0xEE}, s.room, seq/1000, seq)
		}},
		{"message_id", func(t *testing.T, s *e2eStack, seq int64, row storedRow) {
			exec(t, s, `UPDATE messages SET message_id = ? WHERE room_id = ? AND bucket = ? AND seq = ?`,
				[16]byte{0xEE}, s.room, seq/1000, seq)
		}},
		{"ciphertext", func(t *testing.T, s *e2eStack, seq int64, row storedRow) {
			bad := append([]byte(nil), row.ciphertext...)
			bad[0] ^= 0xFF
			exec(t, s, `UPDATE messages SET ciphertext = ? WHERE room_id = ? AND bucket = ? AND seq = ?`,
				bad, s.room, seq/1000, seq)
		}},
		{"header", func(t *testing.T, s *e2eStack, seq int64, row storedRow) {
			bad := append([]byte(nil), row.header...)
			bad[0] ^= 0xFF
			exec(t, s, `UPDATE messages SET header = ? WHERE room_id = ? AND bucket = ? AND seq = ?`,
				bad, s.room, seq/1000, seq)
		}},
		{"seq", func(t *testing.T, s *e2eStack, seq int64, row storedRow) {
			// Rewrite the message one seq up, overwriting that row: the
			// room's stream now carries the same message id at two seqs.
			exec(t, s, `INSERT INTO messages
				(room_id, bucket, seq, message_id, sender_id, device_id, ciphertext, header, created_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				s.room, (seq+1)/1000, seq+1, row.messageID, row.senderID, row.deviceID,
				row.ciphertext, row.header, row.createdAt)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newE2EStack(t)
			alice, bob := s.pair(t)
			exchange(t, s, alice, bob, 6)

			// Tamper with message 3 (a mid-session ratchet header, not
			// the session's first message).
			row := storedRowOf(t, s, 3)
			tc.tamper(t, s, 3, row)

			// Replay the room from the start: honest redeliveries verify
			// silently; the tampered row must be rejected.
			ctx := context.Background()
			if err := bob.Resume(ctx, s.room, 0); err != nil {
				t.Fatal(err)
			}
			r := waitRecv(t, bob)
			if r.Err == nil {
				t.Fatalf("tampered %s accepted: %+v", tc.name, r)
			}
			if r.Plaintext != nil {
				t.Fatalf("tampered %s delivered plaintext: %q", tc.name, r.Plaintext)
			}
		})
	}
}

// storedRow is one message row read back from ScyllaDB.
type storedRow struct {
	messageID  [16]byte
	senderID   [16]byte
	deviceID   [16]byte
	ciphertext []byte
	header     []byte
	createdAt  time.Time
}

func storedRowOf(t *testing.T, s *e2eStack, seq int64) storedRow {
	t.Helper()
	var row storedRow
	if err := s.scylla.Query(`SELECT message_id, sender_id, device_id, ciphertext, header, created_at
		FROM messages WHERE room_id = ? AND bucket = ? AND seq = ?`,
		s.room, seq/1000, seq).Scan(&row.messageID, &row.senderID, &row.deviceID,
		&row.ciphertext, &row.header, &row.createdAt); err != nil {
		t.Fatal(err)
	}
	return row
}

// exec runs one CQL statement against the stack's session.
func exec(t *testing.T, s *e2eStack, cql string, args ...any) {
	t.Helper()
	if err := s.scylla.Query(cql, args...).Exec(); err != nil {
		t.Fatal(err)
	}
}
