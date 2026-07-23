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

// TestSubtreeInclusion contains subtree inclusion proof tests. For reference, consider the
// following example of a tree from RFC 6962:
//
//	                        aaaaa                                   <== Level 4
//	                         / \
//	               ...                   ...
//	               /                       \
//	              /                         \
//	             /                           \
//	           aaaa                         bbbb                    <== Level 3
//	          /    \                       /    \
//	         /      \                     /      \
//	        /        \                   /        \
//	       /          \                 /          \
//	      /            \               /            \
//	    aaa            bbb           ccc            ddd             <== Level 2
//	    / \            / \           / \            / \
//	   /   \          /   \         /   \          /   \
//	  /     \        /     \       /     \        /     \
//	 aa      bb     cc     dd     ee      ff     gg    hh      ii   <== Level 1
//	/ \     / \    / \    / \    / \     / \    / \    / \    / \
//	a b     c d    e f    g h    i j     k l    m n    o p    q r   <== Level 0
//	| |     | |    | |    | |    | |     | |    | |    | |    | |
//	d0 d1   d2 d3  d4 d5  d6 d7  d8 d9   d10    d12    d14    d16
//	                                       |      |      |      |
//	                                       d11    d13    d15    d17
//
// Our storage node layers are always populated from the bottom up, hence the
// gaps above ii.
func TestSubtreeInclusion(t *testing.T) {
	id := compact.NewNodeID
	nodes := func(ids ...compact.NodeID) Nodes {
		return Nodes{IDs: ids}
	}
	rehash := func(begin, end int, ids ...compact.NodeID) Nodes {
		return Nodes{IDs: ids, begin: begin, end: end}
	}
	for _, tc := range []struct {
		index   uint64 // Leaf index in the requested tree.
		start   uint64 // The smallest index of the subtree.
		end     uint64 // The largest index of the subtree + 1.
		want    Nodes
		wantErr bool
	}{
		// Errors.
		{start: 0, end: 0, index: 0, wantErr: true},         // everything at 0
		{start: 1, end: 1, index: 0, wantErr: true},         // start = end
		{start: 2, end: 1, index: 0, wantErr: true},         // start > end
		{start: 1, end: 2, index: 0, wantErr: true},         // index out of bounds left
		{start: 0, end: 2, index: 3, wantErr: true},         // index out of bounds right
		{start: 0, end: 3, index: 3, wantErr: true},         // index out of bounds right
		{start: 3, end: 5, index: 3, wantErr: true},         // start not multiple of bit_ceil(len)
		{start: 1, end: 1<<63 + 2, index: 1, wantErr: true}, // start not multiple of bit_ceil(len) with big tree

		// Small trees.
		{start: 0, end: 1, index: 0, want: Nodes{IDs: []compact.NodeID{}}},
		{start: 0, end: 2, index: 0, want: nodes(id(0, 1))},                  // b
		{start: 0, end: 2, index: 1, want: nodes(id(0, 0))},                  // a
		{start: 0, end: 3, index: 1, want: rehash(1, 2, id(0, 0), id(0, 2))}, // a c

		// Small subtrees.
		// Small tree shifted by bit_ceil(len).
		{start: 1, end: 2, index: 1, want: Nodes{IDs: []compact.NodeID{}}},
		{start: 2, end: 3, index: 2, want: Nodes{IDs: []compact.NodeID{}}},
		{start: 7, end: 8, index: 7, want: Nodes{IDs: []compact.NodeID{}}},
		{start: 2, end: 4, index: 2, want: nodes(id(0, 3))}, // d
		{start: 2, end: 4, index: 3, want: nodes(id(0, 2))}, // c
		{start: 4, end: 7, index: 4, want: rehash(1, 2,
			id(0, 5), id(0, 6))}, // f, j
		{start: 4, end: 7, index: 6, want: nodes(id(1, 2))}, // i

		// Tree of size 7.
		{start: 0, end: 7, index: 0, want: rehash(2, 4, // bbb=hash(cc,g)
			id(0, 1), id(1, 1), id(0, 6), id(1, 2))}, // b bb g cc
		{start: 0, end: 7, index: 1, want: rehash(2, 4, // bbb=hash(cc,g)
			id(0, 0), id(1, 1), id(0, 6), id(1, 2))}, // a bb g cc
		{start: 0, end: 7, index: 2, want: rehash(2, 4, // bbb=hash(cc,g)
			id(0, 3), id(1, 0), id(0, 6), id(1, 2))}, // d aa g cc
		{start: 0, end: 7, index: 3, want: rehash(2, 4, // bbb=hash(cc,g)
			id(0, 2), id(1, 0), id(0, 6), id(1, 2))}, // c aa g cc
		{start: 0, end: 7, index: 4, want: rehash(1, 2,
			id(0, 5), id(0, 6), id(2, 0))}, // f g aaa
		{start: 0, end: 7, index: 5, want: rehash(1, 2,
			id(0, 4), id(0, 6), id(2, 0))}, // e g aaa
		{start: 0, end: 7, index: 6, want: nodes(id(1, 2), id(2, 0))}, // i k

		// Subtree of size 7.
		// Tree of size 7 shifted by bit_ceil(len).
		{start: 8, end: 15, index: 8, want: rehash(2, 4, // ddd=hash(gg,o)
			id(0, 9), id(1, 5), id(0, 14), id(1, 6))}, // j ff o gg
		{start: 8, end: 15, index: 9, want: rehash(2, 4, // ddd=hash(gg,o)
			id(0, 8), id(1, 5), id(0, 14), id(1, 6))}, // j ff o gg
		{start: 8, end: 15, index: 10, want: rehash(2, 4, // ddd=hash(gg,o)
			id(0, 11), id(1, 4), id(0, 14), id(1, 6))}, // l ee o gg
		{start: 8, end: 15, index: 11, want: rehash(2, 4, // ddd=hash(gg, o)
			id(0, 10), id(1, 4), id(0, 14), id(1, 6))}, // k ee o gg
		{start: 8, end: 15, index: 12, want: rehash(1, 2,
			id(0, 13), id(0, 14), id(2, 2))}, // n o ccc
		{start: 8, end: 15, index: 13, want: rehash(1, 2,
			id(0, 12), id(0, 14), id(2, 2))}, // m o ccc
		{start: 8, end: 15, index: 14, want: nodes(id(1, 6), id(2, 2))}, // gg ccc

		// Smaller trees within a bigger stored tree.
		// start = 0
		{start: 0, end: 4, index: 2, want: nodes(id(0, 3), id(1, 0))},                  // d aa
		{start: 0, end: 5, index: 3, want: rehash(2, 3, id(0, 2), id(1, 0), id(0, 4))}, // c aa e
		{start: 0, end: 6, index: 3, want: rehash(2, 3, id(0, 2), id(1, 0), id(1, 2))}, // c aa i
		{start: 0, end: 6, index: 4, want: nodes(id(0, 5), id(2, 0))},                  // f aaa
		{start: 0, end: 7, index: 1, want: rehash(2, 4, // bbb=hash(cc,g)
			id(0, 0), id(1, 1), id(0, 6), id(1, 2))}, // a bb g cc
		{start: 0, end: 7, index: 3, want: rehash(2, 4, // bbb=hash(cc,g)
			id(0, 2), id(1, 0), id(0, 6), id(1, 2))}, // c aa g cc
		// Shifted by bit_ceil(len).
		{start: 4, end: 8, index: 6, want: nodes(id(0, 7), id(1, 2))},                      // h cc
		{start: 8, end: 13, index: 11, want: rehash(2, 3, id(0, 10), id(1, 4), id(0, 12))}, // k ee m
		{start: 8, end: 14, index: 11, want: rehash(2, 3, id(0, 10), id(1, 4), id(1, 6))},  // k, ee, gg
		{start: 8, end: 14, index: 12, want: nodes(id(0, 13), id(2, 2))},                   // n ccc
		{start: 8, end: 15, index: 9, want: rehash(2, 4, // ddd=hash(gg,o)
			id(0, 8), id(1, 5), id(0, 14), id(1, 6))}, // i ff o gg
		{start: 8, end: 15, index: 11, want: rehash(2, 4, // bbb=hash(cc,g)
			id(0, 10), id(1, 4), id(0, 14), id(1, 6))}, // k ff q gg

		// Some rehashes in the middle of the returned list.
		{start: 0, end: 15, index: 10, want: rehash(2, 4,
			id(0, 11), id(1, 4),
			id(0, 14), id(1, 6),
			id(3, 0),
		)},
		{start: 16, end: 31, index: 26, want: rehash(2, 4,
			id(0, 27), id(1, 12),
			id(0, 30), id(1, 14),
			id(3, 2),
		)},
		{start: 0, end: 31, index: 24, want: rehash(2, 4,
			id(0, 25), id(1, 13),
			id(0, 30), id(1, 14),
			id(3, 2), id(4, 0),
		)},
		{start: 32, end: 63, index: 56, want: rehash(2, 4,
			id(0, 57), id(1, 29),
			id(0, 62), id(1, 30),
			id(3, 6), id(4, 2),
		)},
		{start: 0, end: 95, index: 81, want: rehash(3, 6,
			id(0, 80), id(1, 41), id(2, 21),
			id(0, 94), id(1, 46), id(2, 22),
			id(4, 4), id(6, 0),
		)},
		{start: 128, end: 223, index: 209, want: rehash(3, 6,
			id(0, 208), id(1, 105), id(2, 53),
			id(0, 222), id(1, 110), id(2, 54),
			id(4, 12), id(6, 2),
		)},
	} {
		t.Run(fmt.Sprintf("%d:%d:%d", tc.start, tc.end, tc.index), func(t *testing.T) {
			proof, err := SubtreeInclusion(tc.index, tc.start, tc.end)
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
		{size1: 0, size2: 5, wantErr: true},
		{size1: 0, size2: 0, wantErr: true},

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

// TestSubtreeConsistency contains consistency proof tests. For reference, consider
// the following example:
//
//	                        aaaaa                                   <== Level 4
//	                         / \
//	               ...                   ...
//	               /                       \
//	              /                         \
//	             /                           \
//	           aaaa                         bbbb                    <== Level 3
//	          /    \                       /    \
//	         /      \                     /      \
//	        /        \                   /        \
//	       /          \                 /          \
//	      /            \               /            \
//	    aaa            bbb           ccc            ddd             <== Level 2
//	    / \            / \           / \            / \
//	   /   \          /   \         /   \          /   \
//	  /     \        /     \       /     \        /     \
//	 aa      bb     cc     dd     ee      ff     gg    hh      ii   <== Level 1
//	/ \     / \    / \    / \    / \     / \    / \    / \    / \
//	a b     c d    e f    g h    i j     k l    m n    o p    q r   <== Level 0
//	| |     | |    | |    | |    | |     | |    | |    | |    | |
//	d0 d1   d2 d3  d4 d5  d6 d7  d8 d9   d10    d12    d14    d16
//	                                       |      |      |      |
//	                                       d11    d13    d15    d17
//
// The consistency proof between tree size 5 and 7 consists of nodes e, f, g,
// and aaa. The node g is taken instead of its missing parent.
func TestSubtreeConsistency(t *testing.T) {
	id := compact.NewNodeID
	nodes := func(ids ...compact.NodeID) Nodes {
		return Nodes{IDs: ids}
	}
	rehash := func(begin, end int, ids ...compact.NodeID) Nodes {
		return Nodes{IDs: ids, begin: begin, end: end}
	}
	for _, tc := range []struct {
		start   uint64
		end     uint64
		size    uint64
		want    Nodes
		wantErr bool
	}{
		// Errors.
		{start: 2, end: 1, size: 0, wantErr: true},                 // start > end
		{start: 0, end: 5, size: 0, wantErr: true},                 // end > size
		{start: 0, end: 9, size: 8, wantErr: true},                 // end > size
		{start: 3, end: 5, size: 3, wantErr: true},                 // start not multiple of bit_ceil(end-start)
		{start: 1, end: 1<<63 + 2, size: 1<<63 + 2, wantErr: true}, // start not multiple of bit_ceil(len) with big tree

		// Small trees.
		// start = 0
		{start: 0, end: 0, size: 0, want: Nodes{IDs: []compact.NodeID{}}},             // start = end = 0
		{start: 0, end: 1, size: 2, want: nodes(id(0, 1))},                            // b
		{start: 0, end: 1, size: 4, want: nodes(id(0, 1), id(1, 1))},                  // b bb
		{start: 0, end: 1, size: 6, want: rehash(2, 3, id(0, 1), id(1, 1), id(1, 2))}, // b bb cc
		{start: 0, end: 2, size: 3, want: rehash(0, 1, id(0, 2))},                     // c
		{start: 0, end: 2, size: 8, want: nodes(id(1, 1), id(2, 1))},                  // bb bbb
		{start: 0, end: 3, size: 7, want: rehash(3, 5, // bbb=hash(cc,g)
			id(0, 2), id(0, 3), id(1, 0), id(0, 6), id(1, 2))}, // c d aa g cc
		{start: 0, end: 4, size: 7, want: rehash(0, 2, // bbb=hash(cc,g)
			id(0, 6), id(1, 2))}, // g cc
		{start: 0, end: 5, size: 7, want: rehash(2, 3,
			id(0, 4), id(0, 5), id(0, 6), id(2, 0))}, // e f g aaa
		{start: 0, end: 6, size: 7, want: rehash(1, 2,
			id(1, 2), id(0, 6), id(2, 0))}, // cc g aaa
		{start: 0, end: 6, size: 8, want: nodes(
			id(1, 2), id(1, 3), id(2, 0))}, // cc h aaa
		{start: 0, end: 7, size: 8, want: nodes(
			id(0, 6), id(0, 7), id(1, 2), id(2, 0))}, // g h cc aaa
		// start > 0
		{start: 1, end: 1, size: 1, want: Nodes{IDs: []compact.NodeID{}}},                       // start = end
		{start: 1, end: 2, size: 3, want: rehash(1, 2, id(0, 0), id(0, 2))},                     // a c
		{start: 1, end: 2, size: 5, want: rehash(2, 3, id(0, 0), id(1, 1), id(0, 4))},           // a bb e
		{start: 2, end: 4, size: 5, want: rehash(1, 2, id(1, 0), id(0, 4))},                     // aa e
		{start: 1, end: 2, size: 7, want: rehash(2, 4, id(0, 0), id(1, 1), id(0, 6), id(1, 2))}, // a bb g cc
		{start: 2, end: 4, size: 10, want: rehash(2, 3, id(1, 0), id(2, 1), id(1, 4))},          // aa bbb ee
		{start: 4, end: 6, size: 10, want: rehash(2, 3, id(1, 3), id(2, 0), id(1, 4))},          // dd aaa ee
		{start: 4, end: 4, size: 10, want: Nodes{IDs: []compact.NodeID{}}},                      // start = end
		{start: 4, end: 7, size: 11, want: rehash(4, 6, // ccc=hash(ee,k)
			id(0, 6), id(0, 7), id(1, 2), id(2, 0), id(0, 10), id(1, 4))}, // g h cc aaa k ee
		{start: 4, end: 8, size: 11, want: rehash(1, 3, // ccc=hash(ee,k)
			id(2, 0), id(0, 10), id(1, 4))}, // aaa k ee
		{start: 8, end: 13, size: 15, want: rehash(2, 3,
			id(0, 12), id(0, 13), id(0, 14), id(2, 2), id(3, 0))}, // m n  o ccc aaaa
		{start: 8, end: 14, size: 15, want: rehash(1, 2, // hh=hash(o)
			id(1, 6), id(0, 14), id(2, 2), id(3, 0))}, // gg, o, ccc, aaaa
		{start: 8, end: 14, size: 16, want: nodes(
			id(1, 6), id(1, 7), id(2, 2), id(3, 0))}, // gg hh ccc aaaa
		{start: 8, end: 15, size: 16, want: nodes(
			id(0, 14), id(0, 15), id(1, 6), id(2, 2), id(3, 0))}, // o p gg ccc aaaa
		// end = size
		{start: 1, end: 2, size: 2, want: nodes(id(0, 0))},                     // a
		{start: 3, end: 4, size: 4, want: nodes(id(0, 2), id(1, 0))},           // c aa
		{start: 5, end: 6, size: 6, want: nodes(id(0, 4), id(2, 0))},           // e aaa
		{start: 2, end: 3, size: 3, want: nodes(id(1, 0))},                     // aa
		{start: 6, end: 8, size: 8, want: nodes(id(1, 2), id(2, 0))},           // cc aaa
		{start: 4, end: 7, size: 7, want: nodes(id(2, 0))},                     // aaa
		{start: 6, end: 7, size: 7, want: nodes(id(1, 2), id(2, 0))},           // cc aaa
		{start: 4, end: 8, size: 8, want: nodes(id(2, 0))},                     // aaa
		{start: 7, end: 8, size: 8, want: nodes(id(0, 6), id(1, 2), id(2, 0))}, // g h cc aaa

		// Same tree size.
		{start: 0, end: 1, size: 1, want: Nodes{IDs: []compact.NodeID{}}},
		{start: 0, end: 2, size: 2, want: Nodes{IDs: []compact.NodeID{}}},
		{start: 0, end: 3, size: 3, want: Nodes{IDs: []compact.NodeID{}}},
		{start: 0, end: 4, size: 4, want: Nodes{IDs: []compact.NodeID{}}},
		{start: 0, end: 5, size: 5, want: Nodes{IDs: []compact.NodeID{}}},
		{start: 0, end: 7, size: 7, want: Nodes{IDs: []compact.NodeID{}}},
		{start: 0, end: 8, size: 8, want: Nodes{IDs: []compact.NodeID{}}},

		// Smaller trees within a bigger stored tree.
		// start = 0
		{start: 0, end: 2, size: 4, want: nodes(id(1, 1))}, // bb
		{start: 0, end: 3, size: 5, want: rehash(3, 4,
			id(0, 2), id(0, 3), id(1, 0), id(0, 4))}, // c d aa e
		{start: 0, end: 3, size: 6, want: rehash(3, 4,
			id(0, 2), id(0, 3), id(1, 0), id(1, 2))}, // c d aa cc
		{start: 0, end: 4, size: 6, want: rehash(0, 1, id(1, 2))}, // cc
		{start: 0, end: 1, size: 7, want: rehash(2, 4, // bbb=hash(cc,g)
			id(0, 1), id(1, 1), id(0, 6), id(1, 2))}, // b bb g cc
		// start > 0
		{start: 2, end: 4, size: 6, want: rehash(1, 2, // bbb=hash(cc)
			id(1, 0), id(1, 2))}, // aa, cc
		{start: 4, end: 7, size: 9, want: rehash(4, 5, // bbbb=hash(i)
			id(0, 6), id(0, 7), id(1, 2), id(2, 0), id(0, 8))}, // g h cc aaa i
		{start: 4, end: 7, size: 10, want: rehash(4, 5, // bbbb=hash(ee)
			id(0, 6), id(0, 7), id(1, 2), id(2, 0), id(1, 4))}, // g h cc aaa ee
		{start: 4, end: 8, size: 10, want: rehash(1, 2, //ccc=hash(ee)
			id(2, 0), id(1, 4))}, // aa ee
		{start: 2, end: 3, size: 9, want: rehash(3, 4, // bbbb=hash(i)
			id(0, 3), id(1, 0), id(2, 1), id(0, 8))}, // d aa bbb i
		// end = size
		{start: 4, end: 6, size: 6, want: nodes(id(2, 0))},   // aaa
		{start: 8, end: 9, size: 9, want: nodes(id(3, 0))},   // aaaa
		{start: 8, end: 10, size: 10, want: nodes(id(3, 0))}, // aaaa
		{start: 8, end: 12, size: 12, want: nodes(id(3, 0))}, // aaaa

		// Some rehashes in the middle of the returned list.
		{start: 0, end: 10, size: 15, want: rehash(2, 4,
			id(1, 4), id(1, 5), id(0, 14), id(1, 6), id(3, 0))},
		{start: 16, end: 26, size: 31, want: rehash(2, 4,
			id(1, 12), id(1, 13), id(0, 30), id(1, 14), id(3, 2), id(4, 0))},
		{start: 0, end: 24, size: 31, want: rehash(1, 4,
			id(3, 2),
			id(0, 30), id(1, 14), id(2, 6),
			id(4, 0),
		)},
		{start: 32, end: 56, size: 63, want: rehash(1, 4,
			id(3, 6),
			id(0, 62), id(1, 30), id(2, 14),
			id(4, 2),
			id(5, 0),
		)},
		{start: 0, end: 81, size: 95, want: rehash(4, 7,
			id(0, 80), id(0, 81), id(1, 41), id(2, 21),
			id(0, 94), id(1, 46), id(2, 22),
			id(4, 4), id(6, 0),
		)},
		{start: 128, end: 209, size: 223, want: rehash(4, 7,
			id(0, 208), id(0, 209), id(1, 105), id(2, 53),
			id(0, 222), id(1, 110), id(2, 54),
			id(4, 12), id(6, 2),
			id(7, 0),
		)},
	} {
		t.Run(fmt.Sprintf("%d:%d:%d", tc.start, tc.end, tc.size), func(t *testing.T) {
			proof, err := SubtreeConsistency(tc.start, tc.end, tc.size)
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

func TestInclusionSubtreeSucceedsUpToTreeSize(t *testing.T) {
	const maxSize = uint64(555)
	for sbe := uint64(1); sbe <= maxSize; sbe++ {
		for sbs := range sbe {
			if err := isSubtreeValid(sbs, sbe); err != nil {
				continue
			}
			for i := sbs; i < sbe; i++ {
				if _, err := SubtreeInclusion(i, sbs, sbe); err != nil {
					t.Errorf("SubtreeInclusion(i:%d, sbs:%d, sbe: %d) = %v", i, sbs, sbe, err)
				}
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

func TestSubtreeConsistencySucceedsUpToTreeSize(t *testing.T) {
	const maxSize = uint64(100)
	for s := range maxSize + 1 {
		for sbe := range s + 1 {
			for sbs := range sbe + 1 {
				if err := isSubtreeValid(sbs, sbe); err != nil {
					continue
				}
				if _, err := SubtreeConsistency(sbs, sbe, s); err != nil {
					t.Errorf("SubtreeConsistency(sbs:%d, sbe:%d, s:%d) = %v", sbs, sbe, s, err)
				}
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

func TestEphemSubtree(t *testing.T) {
	id := compact.NewNodeID
	for _, tc := range []struct {
		index uint64
		start uint64
		end   uint64
		want  compact.NodeID
	}{
		// Edge case: For perfect trees (resp. subtree) the ephemeral node is the
		// sibling of the root (resp subtree root). However, it will not be used in
		// the proof, as the corresponding subtree is empty.
		{index: 3, start: 0, end: 32, want: id(5, 1)},
		{index: 35, start: 32, end: 64, want: id(5, 2)},

		// start = 0
		{index: 0, start: 0, end: 9, want: id(3, 1)},
		{index: 0, start: 0, end: 13, want: id(3, 1)},
		{index: 7, start: 0, end: 13, want: id(3, 1)},
		{index: 8, start: 0, end: 13, want: id(2, 3)},
		{index: 11, start: 0, end: 13, want: id(2, 3)},
		// More edge cases when the computed ephemeral node is not used in the
		// proof, because it is fully outside the tree border.
		{index: 12, start: 0, end: 13, want: id(0, 13)},
		{index: 13, start: 0, end: 14, want: id(1, 7)},
		// Shifted by bit_ceil(len).
		{index: 16, start: 16, end: 25, want: id(3, 3)},
		{index: 16, start: 16, end: 29, want: id(3, 3)},
		{index: 23, start: 16, end: 29, want: id(3, 3)},
		{index: 24, start: 16, end: 29, want: id(2, 7)},
		{index: 27, start: 16, end: 29, want: id(2, 7)},
		// More edge cases when the computed ephemeral node is not used in the
		// proof, because it is fully outside the tree border.
		{index: 28, start: 16, end: 29, want: id(0, 29)},
		{index: 29, start: 16, end: 30, want: id(1, 15)},

		// There is only one node (level 0, index 1024) in the right subtree, but
		// the ephemeral node is at level 10 rather than level 0. This is because
		// for the purposes of the proof this node is *effectively* at level 10.
		{index: 123, start: 0, end: 1025, want: id(10, 1)},
		// Shifted by bit_ceil(len).
		{index: 2171, start: 2048, end: 3073, want: id(10, 3)},

		{index: 0, start: 0, end: 0xFFFF, want: id(15, 1)},
		{index: 0xF000, start: 0, end: 0xFFFF, want: id(11, 0x1F)},
		{index: 0xFF00, start: 0, end: 0xFFFF, want: id(7, 0x1FF)},
		{index: 0xFFF0, start: 0, end: 0xFFFF, want: id(3, 0x1FFF)},
		{index: 0xFFFF - 1, start: 0, end: 0xFFFF, want: id(0, 0xFFFF)},
		// Shifted by bit_ceil(len).
		{index: 0x10000, start: 0x10000, end: 0x1FFFF, want: id(15, 3)},
		{index: 0x1F000, start: 0x10000, end: 0x1FFFF, want: id(11, 0x3F)},
		{index: 0x1FF00, start: 0x10000, end: 0x1FFFF, want: id(7, 0x3FF)},
		{index: 0x1FFF0, start: 0x10000, end: 0x1FFFF, want: id(3, 0x3FFF)},
		{index: 0x1FFFF - 1, start: 0x10000, end: 0x1FFFF, want: id(0, 0x1FFFF)},
	} {
		t.Run(fmt.Sprintf("%d:%d:%d", tc.index, tc.start, tc.end), func(t *testing.T) {
			nodes, err := SubtreeInclusion(tc.index, tc.start, tc.end)
			if err != nil {
				t.Fatalf("SubtreeInclusion: %v", err)
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

func TestFindSubtrees(t *testing.T) {
	for _, tc := range []struct {
		start, end                      uint64
		wantStart, wantMid, wantEnd     uint64
		wantErr                         bool
	}{
		// Single entry subtrees:
		{start: 0, end: 1, wantStart: 0, wantMid: 1, wantEnd: 1},
		{start: 3, end: 4, wantStart: 3, wantMid: 4, wantEnd: 4},
		// Perfectly aligned subtrees:
		{start: 4, end: 6, wantStart: 4, wantMid: 5, wantEnd: 6},
		{start: 16, end: 32, wantStart: 16, wantMid: 24, wantEnd: 32},
		// Non-perfect trees are split into two:
		{start: 5, end: 13, wantStart: 4, wantMid: 8, wantEnd: 13},
		{start: 7, end: 9, wantStart: 7, wantMid: 8, wantEnd: 9},
		// Empty subtrees.
		{start: 5, end: 5, wantStart: 5, wantMid: 5, wantEnd: 5},
		// Invalid inputs:
		{start: 6, end: 5, wantErr: true},
	} {
		t.Run(fmt.Sprintf("%d:%d", tc.start, tc.end), func(t *testing.T) {
			gotStart, gotMid, gotEnd, err := FindSubtrees(tc.start, tc.end)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("FindSubtrees: %v", err)
			}
			if gotStart != tc.wantStart || gotMid != tc.wantMid || gotEnd != tc.wantEnd {
				t.Errorf("FindSubtrees(%d, %d) = (%d, %d, %d), want (%d, %d, %d)", tc.start, tc.end, gotStart, gotMid, gotEnd, tc.wantStart, tc.wantMid, tc.wantEnd)
			}
		})
	}
}
