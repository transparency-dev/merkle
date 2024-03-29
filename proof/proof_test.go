// Copyright 2022 Google LLC. All Rights Reserved.
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

package proof

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/rfc6962"
)

// TestInclusion contains inclusion proof tests. For reference, consider the
// following example of a tree from RFC 6962:
//
//	           hash              <== Level 3
//	          /    \
//	         /      \
//	        /        \
//	       /          \
//	      /            \
//	     k              l        <== Level 2
//	    / \            / \
//	   /   \          /   \
//	  /     \        /     \
//	 g       h      i      [ ]   <== Level 1
//	/ \     / \    / \    /
//	a b     c d    e f    j      <== Level 0
//	| |     | |    | |    |
//	d0 d1   d2 d3  d4 d5  d6
//
// Our storage node layers are always populated from the bottom up, hence the
// gap at level 1, index 3 in the above picture.
func TestInclusion(t *testing.T) {
	id := compact.NewNodeID
	nodes := func(ids ...compact.NodeID) Nodes {
		return Nodes{IDs: ids}
	}
	rehash := func(begin, end int, ids ...compact.NodeID) Nodes {
		return Nodes{IDs: ids, begin: begin, end: end}
	}
	for _, tc := range []struct {
		size    uint64 // The requested past tree size.
		index   uint64 // Leaf index in the requested tree.
		want    Nodes
		wantErr bool
	}{
		// Errors.
		{size: 0, index: 0, wantErr: true},
		{size: 0, index: 1, wantErr: true},
		{size: 1, index: 2, wantErr: true},
		{size: 0, index: 3, wantErr: true},
		{size: 7, index: 8, wantErr: true},

		// Small trees.
		{size: 1, index: 0, want: Nodes{IDs: []compact.NodeID{}}},
		{size: 2, index: 0, want: nodes(id(0, 1))},                  // b
		{size: 2, index: 1, want: nodes(id(0, 0))},                  // a
		{size: 3, index: 1, want: rehash(1, 2, id(0, 0), id(0, 2))}, // a c

		// Tree of size 7.
		{size: 7, index: 0, want: rehash(2, 4, // l=hash(i,j)
			id(0, 1), id(1, 1), id(0, 6), id(1, 2))}, // b h j i
		{size: 7, index: 1, want: rehash(2, 4, // l=hash(i,j)
			id(0, 0), id(1, 1), id(0, 6), id(1, 2))}, // a h j i
		{size: 7, index: 2, want: rehash(2, 4, // l=hash(i,j)
			id(0, 3), id(1, 0), id(0, 6), id(1, 2))}, // d g j i
		{size: 7, index: 3, want: rehash(2, 4, // l=hash(i,j)
			id(0, 2), id(1, 0), id(0, 6), id(1, 2))}, // c g j i
		{size: 7, index: 4, want: rehash(1, 2, id(0, 5), id(0, 6), id(2, 0))}, // f j k
		{size: 7, index: 5, want: rehash(1, 2, id(0, 4), id(0, 6), id(2, 0))}, // e j k
		{size: 7, index: 6, want: nodes(id(1, 2), id(2, 0))},                  // i k

		// Smaller trees within a bigger stored tree.
		{size: 4, index: 2, want: nodes(id(0, 3), id(1, 0))},                  // d g
		{size: 5, index: 3, want: rehash(2, 3, id(0, 2), id(1, 0), id(0, 4))}, // c g e
		{size: 6, index: 3, want: rehash(2, 3, id(0, 2), id(1, 0), id(1, 2))}, // c g i
		{size: 6, index: 4, want: nodes(id(0, 5), id(2, 0))},                  // f k
		{size: 7, index: 1, want: rehash(2, 4, // l=hash(i,j)
			id(0, 0), id(1, 1), id(0, 6), id(1, 2))}, // a h j i
		{size: 7, index: 3, want: rehash(2, 4, // l=hash(i,j)
			id(0, 2), id(1, 0), id(0, 6), id(1, 2))}, // c g j i

		// Some rehashes in the middle of the returned list.
		{size: 15, index: 10, want: rehash(2, 4,
			id(0, 11), id(1, 4),
			id(0, 14), id(1, 6),
			id(3, 0),
		)},
		{size: 31, index: 24, want: rehash(2, 4,
			id(0, 25), id(1, 13),
			id(0, 30), id(1, 14),
			id(3, 2), id(4, 0),
		)},
		{size: 95, index: 81, want: rehash(3, 6,
			id(0, 80), id(1, 41), id(2, 21),
			id(0, 94), id(1, 46), id(2, 22),
			id(4, 4), id(6, 0),
		)},
	} {
		t.Run(fmt.Sprintf("%d:%d", tc.size, tc.index), func(t *testing.T) {
			proof, err := Inclusion(tc.index, tc.size)
			if tc.wantErr {
				if err == nil {
					t.Fatal("accepted bad params")
				}
				return
			} else if err != nil {
				t.Fatalf("Inclusion: %v", err)
			}
			// Ignore the ephemeral node, it is tested separately.
			proof.ephem = compact.NodeID{}
			if diff := cmp.Diff(tc.want, proof, cmp.AllowUnexported(Nodes{})); diff != "" {
				t.Errorf("paths mismatch:\n%v", diff)
			}
		})
	}
}

// TestConsistency contains consistency proof tests. For reference, consider
// the following example:
//
//	           hash5                         hash7
//	          /    \                        /    \
//	         /      \                      /      \
//	        /        \                    /        \
//	       /          \                  /          \
//	      /            \                /            \
//	     k             [ ]    -->      k              l
//	    / \            /              / \            / \
//	   /   \          /              /   \          /   \
//	  /     \        /              /     \        /     \
//	 g       h     [ ]             g       h      i      [ ]
//	/ \     / \    /              / \     / \    / \    /
//	a b     c d    e              a b     c d    e f    j
//	| |     | |    |              | |     | |    | |    |
//	d0 d1   d2 d3  d4             d0 d1   d2 d3  d4 d5  d6
//
// The consistency proof between tree size 5 and 7 consists of nodes e, f, j,
// and k. The node j is taken instead of its missing parent.
func TestConsistency(t *testing.T) {
	id := compact.NewNodeID
	nodes := func(ids ...compact.NodeID) Nodes {
		return Nodes{IDs: ids}
	}
	rehash := func(begin, end int, ids ...compact.NodeID) Nodes {
		return Nodes{IDs: ids, begin: begin, end: end}
	}
	for _, tc := range []struct {
		size1   uint64 // The smaller of the two tree sizes.
		size2   uint64 // The bigger of the two tree sizes.
		want    Nodes
		wantErr bool
	}{
		// Errors.
		{size1: 5, size2: 0, wantErr: true},
		{size1: 9, size2: 8, wantErr: true},

		{size1: 1, size2: 2, want: nodes(id(0, 1))},                            // b
		{size1: 1, size2: 4, want: nodes(id(0, 1), id(1, 1))},                  // b h
		{size1: 1, size2: 6, want: rehash(2, 3, id(0, 1), id(1, 1), id(1, 2))}, // b h i
		{size1: 2, size2: 3, want: rehash(0, 1, id(0, 2))},                     // c
		{size1: 2, size2: 8, want: nodes(id(1, 1), id(2, 1))},                  // h l
		{size1: 3, size2: 7, want: rehash(3, 5, // l=hash(i,j)
			id(0, 2), id(0, 3), id(1, 0), id(0, 6), id(1, 2))}, // c d g j i
		{size1: 4, size2: 7, want: rehash(0, 2, // l=hash(i,j)
			id(0, 6), id(1, 2))}, // j i
		{size1: 5, size2: 7, want: rehash(2, 3,
			id(0, 4), id(0, 5), id(0, 6), id(2, 0))}, // e f j k
		{size1: 6, size2: 7, want: rehash(1, 2,
			id(1, 2), id(0, 6), id(2, 0))}, // i j k
		{size1: 7, size2: 8, want: nodes(
			id(0, 6), id(0, 7), id(1, 2), id(2, 0))}, // j leaf#7 i k

		// Same tree size.
		{size1: 1, size2: 1, want: Nodes{IDs: []compact.NodeID{}}},
		{size1: 2, size2: 2, want: Nodes{IDs: []compact.NodeID{}}},
		{size1: 3, size2: 3, want: Nodes{IDs: []compact.NodeID{}}},
		{size1: 4, size2: 4, want: Nodes{IDs: []compact.NodeID{}}},
		{size1: 5, size2: 5, want: Nodes{IDs: []compact.NodeID{}}},
		{size1: 7, size2: 7, want: Nodes{IDs: []compact.NodeID{}}},
		{size1: 8, size2: 8, want: Nodes{IDs: []compact.NodeID{}}},

		// Smaller trees within a bigger stored tree.
		{size1: 2, size2: 4, want: nodes(id(1, 1))}, // h
		{size1: 3, size2: 5, want: rehash(3, 4,
			id(0, 2), id(0, 3), id(1, 0), id(0, 4))}, // c d g e
		{size1: 3, size2: 6, want: rehash(3, 4,
			id(0, 2), id(0, 3), id(1, 0), id(1, 2))}, // c d g i
		{size1: 4, size2: 6, want: rehash(0, 1, id(1, 2))}, // i
		{size1: 1, size2: 7, want: rehash(2, 4, // l=hash(i,j)
			id(0, 1), id(1, 1), id(0, 6), id(1, 2))}, // b h j i

		// Some rehashes in the middle of the returned list.
		{size1: 10, size2: 15, want: rehash(2, 4,
			id(1, 4), id(1, 5), id(0, 14), id(1, 6), id(3, 0))},
		{size1: 24, size2: 31, want: rehash(1, 4,
			id(3, 2),
			id(0, 30), id(1, 14), id(2, 6),
			id(4, 0),
		)},
		{size1: 81, size2: 95, want: rehash(4, 7,
			id(0, 80), id(0, 81), id(1, 41), id(2, 21),
			id(0, 94), id(1, 46), id(2, 22),
			id(4, 4), id(6, 0),
		)},
	} {
		t.Run(fmt.Sprintf("%d:%d", tc.size1, tc.size2), func(t *testing.T) {
			proof, err := Consistency(tc.size1, tc.size2)
			if tc.wantErr {
				if err == nil {
					t.Fatal("accepted bad params")
				}
				return
			} else if err != nil {
				t.Fatalf("Consistency: %v", err)
			}
			// Ignore the ephemeral node, it is tested separately.
			proof.ephem = compact.NodeID{}
			if diff := cmp.Diff(tc.want, proof, cmp.AllowUnexported(Nodes{})); diff != "" {
				t.Errorf("paths mismatch:\n%v", diff)
			}
		})
	}
}

func TestInclusionSucceedsUpToTreeSize(t *testing.T) {
	const maxSize = uint64(555)
	for ts := uint64(1); ts <= maxSize; ts++ {
		for i := ts; i < ts; i++ {
			if _, err := Inclusion(i, ts); err != nil {
				t.Errorf("Inclusion(ts:%d, i:%d) = %v", ts, i, err)
			}
		}
	}
}

func TestConsistencySucceedsUpToTreeSize(t *testing.T) {
	const maxSize = uint64(100)
	for s1 := uint64(1); s1 < maxSize; s1++ {
		for s2 := s1 + 1; s2 <= maxSize; s2++ {
			if _, err := Consistency(s1, s2); err != nil {
				t.Errorf("Consistency(%d, %d) = %v", s1, s2, err)
			}
		}
	}
}

func TestEphem(t *testing.T) {
	id := compact.NewNodeID
	for _, tc := range []struct {
		index uint64
		size  uint64
		want  compact.NodeID
	}{
		// Edge case: For perfect trees the ephemeral node is the sibling of the
		// root. However, it will not be used in the proof, as the corresponding
		// subtree is empty.
		{index: 3, size: 32, want: id(5, 1)},

		{index: 0, size: 9, want: id(3, 1)},
		{index: 0, size: 13, want: id(3, 1)},
		{index: 7, size: 13, want: id(3, 1)},
		{index: 8, size: 13, want: id(2, 3)},
		{index: 11, size: 13, want: id(2, 3)},
		// More edge cases when the computed ephemeral node is not used in the
		// proof, because it is fully outside the tree border.
		{index: 12, size: 13, want: id(0, 13)},
		{index: 13, size: 14, want: id(1, 7)},

		// There is only one node (level 0, index 1024) in the right subtree, but
		// the ephemeral node is at level 10 rather than level 0. This is because
		// for the purposes of the proof this node is *effectively* at level 10.
		{index: 123, size: 1025, want: id(10, 1)},

		{index: 0, size: 0xFFFF, want: id(15, 1)},
		{index: 0xF000, size: 0xFFFF, want: id(11, 0x1F)},
		{index: 0xFF00, size: 0xFFFF, want: id(7, 0x1FF)},
		{index: 0xFFF0, size: 0xFFFF, want: id(3, 0x1FFF)},
		{index: 0xFFFF - 1, size: 0xFFFF, want: id(0, 0xFFFF)},
	} {
		t.Run(fmt.Sprintf("%d:%d", tc.index, tc.size), func(t *testing.T) {
			nodes, err := Inclusion(tc.index, tc.size)
			if err != nil {
				t.Fatalf("Inclusion: %v", err)
			}
			got, _, _ := nodes.Ephem()
			if want := tc.want; got != want {
				t.Errorf("Ephem: got %+v, want %+v", got, want)
			}
		})
	}
}

func TestRehash(t *testing.T) {
	th := rfc6962.DefaultHasher
	h := [][]byte{
		th.HashLeaf([]byte("Hash 1")),
		th.HashLeaf([]byte("Hash 2")),
		th.HashLeaf([]byte("Hash 3")),
		th.HashLeaf([]byte("Hash 4")),
		th.HashLeaf([]byte("Hash 5")),
	}

	for _, tc := range []struct {
		desc   string
		hashes [][]byte
		nodes  Nodes
		want   [][]byte
	}{
		{
			desc:   "no-rehash",
			hashes: h[:3],
			nodes:  inclusion(t, 3, 8),
			want:   h[:3],
		},
		{
			desc:   "rehash",
			hashes: h[:5],
			nodes:  inclusion(t, 9, 15),
			want:   [][]byte{h[0], h[1], th.HashChildren(h[3], h[2]), h[4]},
		},
		{
			desc:   "rehash-at-the-end",
			hashes: h[:4],
			nodes:  inclusion(t, 2, 7),
			want:   [][]byte{h[0], h[1], th.HashChildren(h[3], h[2])},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			h := append([][]byte{}, tc.hashes...)
			got, err := tc.nodes.Rehash(h, th.HashChildren)
			if err != nil {
				t.Fatalf("Rehash: %v", err)
			}
			if want := tc.want; !cmp.Equal(got, want) {
				t.Errorf("proofs mismatch:\ngot: %x\nwant: %x", got, want)
			}
		})
	}
}

func inclusion(t *testing.T, index, size uint64) Nodes {
	t.Helper()
	n, err := Inclusion(index, size)
	if err != nil {
		t.Fatalf("Inclusion: %v", err)
	}
	return n
}
