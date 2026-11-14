package store

import "testing"

// FuzzBucketRange checks the resume read's partition range (plan §3.3b,
// S-35): for any cursor and watermark, the buckets first..last cover exactly
// the seqs in (after, hi], none missing and none extra.
func FuzzBucketRange(f *testing.F) {
	for _, s := range [][3]int64{
		{0, 0, 1000}, {0, 1, 1000}, {998, 1000, 1000}, {999, 1000, 1000},
		{1000, 1001, 1000}, {1500, 4200, 1000}, {0, 1 << 40, 1000}, {5, 4, 1}, {7, 7, 3},
		{0, 1<<63 - 1, 1<<63 - 1}, {1<<63 - 2, 1<<63 - 1, 1 << 62},
	} {
		f.Add(s[0], s[1], s[2])
	}
	f.Fuzz(func(t *testing.T, after, hi, n int64) {
		// Domain: cursors are validated non-negative (protocol, Range),
		// and N is a positive constant.
		if after < 0 || hi < 0 || n < 1 {
			t.Skip()
		}
		first, last, ok := bucketRange(after, hi, n)
		if hi <= after {
			if ok {
				t.Fatalf("(%d, %d] is empty but ok", after, hi)
			}
			return
		}
		if !ok {
			t.Fatalf("(%d, %d] is not empty but !ok", after, hi)
		}
		// None missing: the range's lowest and highest seqs (and so,
		// buckets being contiguous, every seq between) fall inside.
		if b := (after + 1) / n; b < first || b > last {
			t.Fatalf("seq %d (bucket %d) outside %d..%d", after+1, b, first, last)
		}
		if b := hi / n; b < first || b > last {
			t.Fatalf("seq %d (bucket %d) outside %d..%d", hi, b, first, last)
		}
		// None extra: the first and last buckets each hold a seq in range.
		// Bucket b holds [b*n, b*n+n-1]; it misses (after, hi] when
		// b*n > hi or b*n+n-1 <= after, written as b*n <= after-(n-1) so
		// nothing overflows (b*n <= hi here, and after-(n-1) >= -MaxInt64).
		holdsNone := func(b int64) bool { lo := b * n; return lo > hi || lo <= after-(n-1) }
		if holdsNone(first) {
			t.Fatalf("first bucket %d holds no seq in (%d, %d] at n=%d", first, after, hi, n)
		}
		if holdsNone(last) {
			t.Fatalf("last bucket %d holds no seq in (%d, %d] at n=%d", last, after, hi, n)
		}
		if first > last {
			t.Fatalf("first %d > last %d", first, last)
		}
	})
}
