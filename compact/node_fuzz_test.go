//go:build go1.18

package compact

import (
	"testing"
)

// Test that RangeNodes returns a slice of nodes with contiguous coverage.
// https://github.com/transparency-dev/merkle/blob/main/docs/compact_ranges.md#definition
func FuzzRangeNodes(f *testing.F) {
	f.Fuzz(func(t *testing.T, begin, end uint64) {
		if begin > end {
			return
		}
		t.Logf("begin=%d, end=%d", begin, end)
		nodes := RangeNodes(begin, end, nil)
		t.Logf("nodes=%v", nodes)

		// Nodes should be contiguous covering begin to end
		previousEnd := begin
		for _, node := range nodes {
			b, e := node.Coverage()
			if b != previousEnd {
				t.Errorf("got=%d, want=%d", b, previousEnd)
			}
			previousEnd = e
		}
		if previousEnd != end {
			t.Errorf("got=%d, want=%d", previousEnd, end)
		}
	})
}
