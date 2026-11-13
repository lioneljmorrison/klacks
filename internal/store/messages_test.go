package store

import "testing"

func TestBucketRange(t *testing.T) {
	const n = 1000
	tests := []struct {
		name        string
		after, hi   int64
		first, last int64
		ok          bool
	}{
		{"empty room", 0, 0, 0, 0, false},
		{"caught up", 42, 42, 0, 0, false},
		{"cursor ahead of hi", 50, 42, 0, 0, false},
		{"from start, one row", 0, 1, 0, 0, true},
		{"within bucket 0", 0, 998, 0, 0, true},
		{"hi at N-1", 0, n - 1, 0, 0, true},
		{"hi at N", 0, n, 0, 1, true},
		{"hi at N+1", 0, n + 1, 0, 1, true},
		{"after at N-2: next seq N-1", n - 2, n + 5, 0, 1, true},
		{"after at N-1: next seq N", n - 1, n + 5, 1, 1, true},
		{"after at N: next seq N+1", n, n + 5, 1, 1, true},
		{"exactly one bucket boundary row", n - 1, n, 1, 1, true},
		{"many buckets", 1500, 4200, 1, 4, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first, last, ok := bucketRange(tt.after, tt.hi, n)
			if ok != tt.ok || (ok && (first != tt.first || last != tt.last)) {
				t.Fatalf("bucketRange(%d, %d, %d) = %d, %d, %t; want %d, %d, %t",
					tt.after, tt.hi, n, first, last, ok, tt.first, tt.last, tt.ok)
			}
		})
	}
}

func TestBucket(t *testing.T) {
	for seq, want := range map[int64]int64{1: 0, BucketSize - 1: 0, BucketSize: 1, 2*BucketSize + 7: 2} {
		if got := bucket(seq); got != want {
			t.Errorf("bucket(%d) = %d, want %d", seq, got, want)
		}
	}
}
