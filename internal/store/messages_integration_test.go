//go:build integration

package store_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/lioneljmorrison/klacks/internal/store"
	"github.com/lioneljmorrison/klacks/internal/testutil/dbtest"
)

func id(b byte) store.UUID { return store.UUID{15: b} }

func msg(room store.UUID, seq int64) store.Message {
	return store.Message{
		RoomID:     room,
		Seq:        seq,
		MessageID:  id(byte(seq)),
		SenderID:   id(0xb1),
		DeviceID:   id(0xc1),
		Ciphertext: []byte{byte(seq >> 8), byte(seq)},
		Header:     []byte("hdr"),
		CreatedAt:  time.UnixMilli(1_700_000_000_000 + seq).UTC(),
	}
}

func collect(t *testing.T, ms store.MessageStore, room store.UUID, after, hi int64) []store.Message {
	t.Helper()
	var out []store.Message
	for m, err := range ms.Range(context.Background(), room, after, hi) {
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

func TestMessagesRangeAcrossBuckets(t *testing.T) {
	ms := store.NewScyllaMessages(dbtest.MigratedScylla(t))
	ctx := context.Background()
	room, other := id(0xa1), id(0xa2)
	n := store.BucketSize

	// Rows on both sides of the bucket boundary at n, including some above
	// hi standing in for uncommitted orphans.
	ts := int64(1)
	for seq := n - 5; seq <= n+5; seq++ {
		if err := ms.Insert(ctx, msg(room, seq), ts); err != nil {
			t.Fatal(err)
		}
		ts++
	}
	if err := ms.Insert(ctx, msg(other, n), ts); err != nil {
		t.Fatal(err)
	}

	after, hi := n-4, n+2
	got := collect(t, ms, room, after, hi)
	if len(got) != int(hi-after) {
		t.Fatalf("got %d messages, want %d", len(got), hi-after)
	}
	for i, m := range got {
		want := msg(room, after+1+int64(i))
		if m.Seq != want.Seq {
			t.Fatalf("message %d has seq %d, want %d (order or bounds wrong)", i, m.Seq, want.Seq)
		}
		if m.RoomID != want.RoomID || m.MessageID != want.MessageID || m.SenderID != want.SenderID ||
			m.DeviceID != want.DeviceID || !bytes.Equal(m.Ciphertext, want.Ciphertext) ||
			!bytes.Equal(m.Header, want.Header) || !m.CreatedAt.Equal(want.CreatedAt) {
			t.Fatalf("seq %d round trip:\n got  %+v\n want %+v", m.Seq, m, want)
		}
	}

	if got := collect(t, ms, room, hi, hi); len(got) != 0 {
		t.Fatalf("caught-up cursor returned %d messages", len(got))
	}
	if got := collect(t, ms, id(0xa3), 0, n+5); len(got) != 0 {
		t.Fatalf("empty room returned %d messages", len(got))
	}
}

// TestMessagesOverwriteByTimestamp checks the orphan rule of plan §3.3c: for
// the same seq, the write with the higher explicit timestamp wins whatever
// order the writes arrive in.
func TestMessagesOverwriteByTimestamp(t *testing.T) {
	ms := store.NewScyllaMessages(dbtest.MigratedScylla(t))
	ctx := context.Background()
	room := id(0xa1)
	write := func(payload string, ts int64) {
		t.Helper()
		m := msg(room, 7)
		m.Ciphertext = []byte(payload)
		if err := ms.Insert(ctx, m, ts); err != nil {
			t.Fatal(err)
		}
	}
	read := func() string {
		t.Helper()
		got := collect(t, ms, room, 6, 7)
		if len(got) != 1 {
			t.Fatalf("got %d messages, want 1", len(got))
		}
		return string(got[0].Ciphertext)
	}

	write("orphan", 10)
	write("stale", 5)
	if got := read(); got != "orphan" {
		t.Fatalf("lower timestamp overwrote: got %q", got)
	}
	write("retry", 20)
	if got := read(); got != "retry" {
		t.Fatalf("higher timestamp did not overwrite: got %q", got)
	}
}

func TestMessagesRejectsBadArguments(t *testing.T) {
	ms := store.NewScyllaMessages(dbtest.MigratedScylla(t))
	ctx := context.Background()
	if err := ms.Insert(ctx, msg(id(1), 0), 1); err == nil {
		t.Error("seq 0 accepted")
	}
	if err := ms.Insert(ctx, msg(id(1), 1), 0); err == nil {
		t.Error("write timestamp 0 accepted")
	}
	var rangeErr error
	for _, err := range ms.Range(ctx, id(1), -1, 5) {
		rangeErr = err
	}
	if rangeErr == nil {
		t.Error("negative cursor accepted")
	}
}
