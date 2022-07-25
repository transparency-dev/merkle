//go:build go1.18

package testonly

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func FuzzConsistencyProofAgainstReferenceImplementation(f *testing.F) {
	for size := 0; size <= 8; size++ {
		for end := 0; end <= size; end++ {
			for begin := 0; begin <= end; begin++ {
				f.Add(uint64(size), uint64(begin), uint64(end))
			}
		}
	}
	f.Fuzz(func(t *testing.T, size, begin, end uint64) {
		t.Logf("size=%d, begin=%d, end=%d", size, begin, end)
		if begin > end || end > size {
			return
		}
		entries := genEntries(size)
		tree := newTree(entries)
		got, err := tree.ConsistencyProof(begin, end)
		if err != nil {
			t.Errorf("ConsistencyProof: %v", err)
		}
		want := refConsistencyProof(entries[:end], end, begin, tree.hasher, true)
		if diff := cmp.Diff(got, want, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("ConsistencyProof: diff (-got +want)\n%s", diff)
		}
	})
}
