// Copyright 2019 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package compact

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestRangeNodesAndSize(t *testing.T) {
	n := func(level uint, index uint64) NodeID {
		return NewNodeID(level, index)
	}
	for _, tc := range []struct {
		begin uint64
		end   uint64
		want  []NodeID
	}{
		// Empty ranges.
		{end: 0, want: nil},
		{begin: 10, end: 10, want: nil},
		{begin: 1024, end: 1024, want: nil},
		// One entry.
		{begin: 10, end: 11, want: []NodeID{n(0, 10)}},
		{begin: 1024, end: 1025, want: []NodeID{n(0, 1024)}},
		{begin: 1025, end: 1026, want: []NodeID{n(0, 1025)}},
		// Two entries.
		{begin: 10, end: 12, want: []NodeID{n(1, 5)}},
		{begin: 1024, end: 1026, want: []NodeID{n(1, 512)}},
		{begin: 1025, end: 1027, want: []NodeID{n(0, 1025), n(0, 1026)}},
		// Only right border.
		{end: 1, want: []NodeID{n(0, 0)}},
		{end: 2, want: []NodeID{n(1, 0)}},
		{end: 3, want: []NodeID{n(1, 0), n(0, 2)}},
		{end: 4, want: []NodeID{n(2, 0)}},
		{end: 5, want: []NodeID{n(2, 0), n(0, 4)}},
		{end: 15, want: []NodeID{n(3, 0), n(2, 2), n(1, 6), n(0, 14)}},
		{end: 100, want: []NodeID{n(6, 0), n(5, 2), n(2, 24)}},
		{end: 513, want: []NodeID{n(9, 0), n(0, 512)}},
		{end: uint64(1) << 63, want: []NodeID{n(63, 0)}},
		{end: (uint64(1) << 63) + (uint64(1) << 57), want: []NodeID{n(63, 0), n(57, 64)}},
		// Only left border.
		{begin: 0, end: 16, want: []NodeID{n(4, 0)}},
		{begin: 1, end: 16, want: []NodeID{n(0, 1), n(1, 1), n(2, 1), n(3, 1)}},
		{begin: 2, end: 16, want: []NodeID{n(1, 1), n(2, 1), n(3, 1)}},
		{begin: 3, end: 16, want: []NodeID{n(0, 3), n(2, 1), n(3, 1)}},
		{begin: 4, end: 16, want: []NodeID{n(2, 1), n(3, 1)}},
		{begin: 6, end: 16, want: []NodeID{n(1, 3), n(3, 1)}},
		{begin: 8, end: 16, want: []NodeID{n(3, 1)}},
		{begin: 11, end: 16, want: []NodeID{n(0, 11), n(2, 3)}},
		// Two-sided.
		{begin: 1, end: 31, want: []NodeID{n(0, 1), n(1, 1), n(2, 1), n(3, 1), n(3, 2), n(2, 6), n(1, 14), n(0, 30)}},
		{begin: 1, end: 17, want: []NodeID{n(0, 1), n(1, 1), n(2, 1), n(3, 1), n(0, 16)}},
	} {
		t.Run(fmt.Sprintf("range:%d:%d", tc.begin, tc.end), func(t *testing.T) {
			got := RangeNodes(tc.begin, tc.end, nil)
			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Fatalf("RangeNodes: diff(-want +got):\n%s", diff)
			}
			if got, want := RangeSize(tc.begin, tc.end), len(tc.want); got != want {
				t.Errorf("RangeSize: got %d, want %d", got, want)
			}
		})
	}
}

func TestRangeNodesAppend(t *testing.T) {
	prefix := []NodeID{NewNodeID(0, 0), NewNodeID(10, 0), NewNodeID(11, 5)}
	nodes := RangeNodes(123, 456, prefix)

	if got, min := len(nodes), len(prefix); got < min {
		t.Fatalf("RangeNodes returned %d IDs, want >= %d", got, min)
	}
	got := nodes[:len(prefix)]
	if diff := cmp.Diff(got, prefix); diff != "" {
		t.Fatalf("RangeNodes: diff(-prefix +got):\n%s", diff)
	}
}

func TestGenRangeNodes(t *testing.T) {
	const size = uint64(512)
	for begin := uint64(0); begin <= size; begin++ {
		for end := begin; end <= size; end++ {
			got := RangeNodes(begin, end, nil)
			want := refRangeNodes(NewNodeID(63, 0), begin, end)
			if diff := cmp.Diff(got, want); diff != "" {
				t.Fatalf("RangeNodes(%d, %d): diff(-want +got):\n%s", begin, end, diff)
			}
		}
	}
}

// refRangeNodes returns node IDs that comprise the [begin, end) compact range.
// This is a reference implementation for cross-checking.
func refRangeNodes(root NodeID, begin, end uint64) []NodeID {
	b, e := root.Coverage()
	if end <= b || begin >= e {
		return nil
	}
	if b >= begin && e <= end {
		return []NodeID{root}
	}
	return append(
		refRangeNodes(NewNodeID(root.Level-1, root.Index*2), begin, end),
		refRangeNodes(NewNodeID(root.Level-1, root.Index*2+1), begin, end)...)
}

// Test that RangeNodes returns a slice of nodes with contiguous coverage.
// https://github.com/transparency-dev/merkle/blob/main/docs/compact_ranges.md#definition
func FuzzRangeNodes(f *testing.F) {
	f.Fuzz(func(t *testing.T, begin, end uint64) {
		if begin > end {
			return
		}
		t.Logf("begin=%d, end=%d", begin, end)
		ids := make([]NodeID, 0)
		nodes := RangeNodes(begin, end, ids)
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
