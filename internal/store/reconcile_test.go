package store

import (
	"context"
	"iter"
	"testing"
)

// seqStore serves rows at the given seqs.
type seqStore struct{ seqs map[int64]bool }

func (s seqStore) Insert(context.Context, Message, int64) error { return nil }

func (s seqStore) Range(_ context.Context, room UUID, after, hi int64) iter.Seq2[Message, error] {
	return func(yield func(Message, error) bool) {
		for seq := after + 1; seq <= hi; seq++ {
			if s.seqs[seq] && !yield(Message{RoomID: room, Seq: seq}, nil) {
				return
			}
		}
	}
}

func run(from, to int64, skip ...int64) seqStore {
	s := seqStore{seqs: map[int64]bool{}}
	for i := from; i <= to; i++ {
		s.seqs[i] = true
	}
	for _, k := range skip {
		delete(s.seqs, k)
	}
	return s
}

func TestContiguousTop(t *testing.T) {
	for name, tc := range map[string]struct {
		s     seqStore
		after int64
		want  int64
	}{
		"nothing above":          {run(1, 5), 5, 5},
		"empty room":             {run(1, 0), 0, 0},
		"short run":              {run(1, 5), 2, 5},
		"across many buckets":    {run(1, 3*BucketSize+17), 0, 3*BucketSize + 17},
		"exactly a bucket":       {run(1, BucketSize), 0, BucketSize},
		"stops at a gap":         {run(1, 2500, 1500), 0, 1499},
		"gap right above":        {run(1, 10, 6), 5, 5},
		"rows only past the gap": {run(8, 10), 5, 5},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := contiguousTop(context.Background(), tc.s, UUID{1}, tc.after)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("contiguousTop(after %d) = %d; want %d", tc.after, got, tc.want)
			}
		})
	}
}
