// Command meetings is the plan's toy meeting-scheduler embedder: it imports
// pkg/chat, schedules a meeting as a chat room, adds its attendees, posts
// its invite, and watches every message arrive through Subscribe. Run it
// against a migrated stack:
//
//	make up migrate-up
//	go run ./examples/meetings
//
// Configuration follows the server's KLACKS_* variables (see .env.example),
// overridable by flags.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/lioneljmorrison/klacks/pkg/chat"
)

func main() {
	pgDSN := flag.String("postgres-dsn",
		env("KLACKS_POSTGRES_DSN", "postgres://klacks:klacks@localhost:55432/klacks?sslmode=disable"),
		"PostgreSQL DSN; both stores must be migrated")
	hosts := flag.String("scylla-hosts",
		env("KLACKS_SCYLLA_HOSTS", "localhost:9042"),
		"comma-separated ScyllaDB hosts")
	keyspace := flag.String("scylla-keyspace",
		env("KLACKS_SCYLLA_KEYSPACE", "klacks"),
		"ScyllaDB keyspace")
	user := flag.String("scylla-user", os.Getenv("KLACKS_SCYLLA_USERNAME"),
		"ScyllaDB username, when the cluster has auth enabled")
	pass := flag.String("scylla-password", os.Getenv("KLACKS_SCYLLA_PASSWORD"),
		"ScyllaDB password, when the cluster has auth enabled")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := config{
		postgresDSN:    *pgDSN,
		scyllaHosts:    splitHosts(*hosts),
		scyllaKeyspace: *keyspace,
		scyllaUsername: *user,
		scyllaPassword: *pass,
	}
	if err := run(context.Background(), log, cfg); err != nil {
		log.Error("meetings", "err", err)
		os.Exit(1)
	}
}

// config is the run's store configuration.
type config struct {
	postgresDSN    string
	scyllaHosts    []string
	scyllaKeyspace string
	scyllaUsername string
	scyllaPassword string
}

// run schedules one meeting and reads it back end to end. Everything is
// random per run: the scheduler's identity and its users are just UUIDs —
// nothing registers them; a real embedder derives them from its own
// accounts.
func run(ctx context.Context, log *slog.Logger, cfg config) error {
	actor := chat.UserID(mustID(log, "actor"))
	organizer, alice, bob, late :=
		chat.UserID(mustID(log, "organizer")), chat.UserID(mustID(log, "alice")),
		chat.UserID(mustID(log, "bob")), chat.UserID(mustID(log, "late"))

	svc, err := chat.Open(ctx, chat.Config{
		PostgresDSN:    cfg.postgresDSN,
		ScyllaHosts:    cfg.scyllaHosts,
		ScyllaKeyspace: cfg.scyllaKeyspace,
		ScyllaUsername: cfg.scyllaUsername,
		ScyllaPassword: cfg.scyllaPassword,
		// Must exceed ScyllaTimeout: a publish holds the room lock across
		// its ScyllaDB write.
		ScyllaTimeout:   5 * time.Second,
		RoomLockTimeout: 10 * time.Second,
		Actor:           actor,
		Log:             log,
	})
	if err != nil {
		return fmt.Errorf("open chat service: %w", err)
	}
	defer svc.Close()

	s := NewScheduler(svc, actor)

	// Scheduling the meeting creates its room, adds its attendees and
	// posts its invite.
	m, inviteSeq, err := s.CreateMeeting(ctx, "Sprint planning", organizer, alice, bob)
	if err != nil {
		return fmt.Errorf("schedule meeting: %w", err)
	}
	log.Info("meeting scheduled", "room", uuid(m.ID), "attendees", len(m.Attendees), "invite_seq", inviteSeq)

	// Watching the room replays what it has, then delivers live.
	msgs, err := svc.Subscribe(ctx, m.ID, 0)
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}

	// The invite, replayed from seq 0.
	invite := <-msgs
	log.Info("replayed", "seq", invite.Seq, "sender", uuid(invite.SenderID), "body", string(invite.Ciphertext))

	// A late attendee joins; the update arrives live.
	m, joinSeq, err := s.AddAttendee(ctx, m, late)
	if err != nil {
		return fmt.Errorf("add late attendee: %w", err)
	}
	join := <-msgs
	log.Info("live", "seq", join.Seq, "sender", uuid(join.SenderID), "body", string(join.Ciphertext))

	// Any member may post; the organizer wraps up.
	if _, err := svc.PostMessage(ctx, m.ID, organizer, chat.EncryptedPayload{
		MessageID:  mustID(log, "message"),
		DeviceID:   mustID(log, "device"),
		Ciphertext: []byte("see you there"),
		Header:     []byte("note/v1"),
	}); err != nil {
		return fmt.Errorf("post note: %w", err)
	}
	note := <-msgs
	log.Info("live", "seq", note.Seq, "sender", uuid(note.SenderID), "body", string(note.Ciphertext))

	// Seqs are gap-free per room and start at 1 — the end-to-end check.
	if invite.Seq != inviteSeq || join.Seq != joinSeq || note.Seq != 3 {
		return fmt.Errorf("unexpected seqs: invite %d (want %d), join %d (want %d), note %d (want 3)",
			invite.Seq, inviteSeq, join.Seq, joinSeq, note.Seq)
	}
	log.Info("done", "meeting", m.Title, "room", uuid(m.ID), "messages", note.Seq)
	return nil
}

// env returns the variable's value, or fallback when unset or empty.
func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// mustID generates one random ID, exiting on failure.
func mustID(log *slog.Logger, what string) [16]byte {
	u, err := randomUUID()
	if err != nil {
		log.Error("generate id", "what", what, "err", err)
		os.Exit(1)
	}
	return u
}

// splitHosts splits a comma-separated host list.
func splitHosts(s string) []string {
	var hosts []string
	for _, h := range strings.Split(s, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts
}
