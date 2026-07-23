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

// Package proof contains helpers for constructing log Merkle tree proofs.
package proof

import (
	"fmt"
	"math/bits"

	"github.com/transparency-dev/merkle/compact"
)

// Nodes contains information on how to construct a log Merkle tree proof. It
// supports any proof that has at most one ephemeral node, such as inclusion
// and consistency proofs defined in RFC 6962.
type Nodes struct {
	// IDs contains the IDs of non-ephemeral nodes sufficient to build the proof.
	// If an ephemeral node is needed for a proof, it can be recomputed based on
	// a subset of nodes in this list.
	IDs []compact.NodeID
	// begin is the beginning index (inclusive) into the IDs[begin:end] subslice
	// of the nodes which will be used to re-create the ephemeral node.
	begin int
	// end is the ending (exclusive) index into the IDs[begin:end] subslice of
	// the nodes which will be used to re-create the ephemeral node.
	end int
	// ephem is the ID of the ephemeral node in the proof. This node is a common
	// ancestor of all nodes in IDs[begin:end]. It is the node that otherwise
	// would have been used in the proof if the tree was perfect.
	ephem compact.NodeID
}

// Inclusion returns the information on how to fetch and construct an inclusion
// proof for the given leaf index in a log Merkle tree of the given size. It
// requires 0 <= index < size.
func Inclusion(index, size uint64) (Nodes, error) {
	if index >= size {
		return Nodes{}, fmt.Errorf("index %d out of bounds for tree size %d", index, size)
	}
	return nodes(index, 0, size).skipFirst(), nil
}

// SubtreeInclusion returns the information on how to fetch and construct an inclusion
// proof for the given leaf index in a log Merkle subtree covering [start, end).
// It requires:
//   - 0 <= start <= index < end
//   - start to be a multiple of the smallest power of two greater than or equal to
//     (end - start)
func SubtreeInclusion(index, start, end uint64) (Nodes, error) {
	if err := isSubtreeValid(start, end); err != nil {
		return Nodes{}, fmt.Errorf("subtree invalid: %v", err)
	}
	if index < start || index >= end {
		return Nodes{}, fmt.Errorf("index %d out of bounds for subtree [%d, %d)", index, start, end)
	}

	// Shift the subtree to the left, such that it starts at 0.
	p := nodes(index-start, 0, end-start).skipFirst()

	// Shift nodes back to the right, in line with the original subtree position.
	for n := range p.IDs {
		p.IDs[n].Index += start >> p.IDs[n].Level
	}
	// p.ephem might not be used by the resulting proof, but shift it
	// unconditionally for uniformity.
	p.ephem.Index += start >> p.ephem.Level

	return p, nil
}

// Consistency returns the information on how to fetch and construct a
// consistency proof between the two given tree sizes of a log Merkle tree. It
// requires 0 < size1 <= size2.
func Consistency(size1, size2 uint64) (Nodes, error) {
	if size1 > size2 {
		return Nodes{}, fmt.Errorf("tree size %d > %d", size1, size2)
	}
	if size1 == 0 {
		return Nodes{}, fmt.Errorf("consistency proof from empty tree is meaningless")
	}
	return subtreeConsistency(0, size1, size2)
}

// SubtreeConsistency returns the information on how to fetch and construct a
// consistency proof between a Merkle subtree covering [start, end) and the
// larger parent Merkle tree of a given size. It requires:
//   - 0 <= start < end <= size
//   - start to be a multiple of the smallest power of two greater than or equal to
//     (end - start)
func SubtreeConsistency(start, end, size uint64) (Nodes, error) {
	if err := isSubtreeValid(start, end); err != nil {
		return Nodes{}, fmt.Errorf("subtree invalid: %v", err)
	}
	if end > size {
		return Nodes{}, fmt.Errorf("subtree end %d strictly greater than tree size %d", end, size)
	}
	return subtreeConsistency(start, end, size)
}

func subtreeConsistency(start, end, size uint64) (Nodes, error) {
	if start == 0 && end == size {
		return Nodes{IDs: []compact.NodeID{}}, nil
	}
	if start == end {
		return Nodes{IDs: []compact.NodeID{}}, nil
	}

	// If end == size, prove inclusion of [start, end) into the tree.
	if end == size {
		// Find the subtree's root, the lowest common ancestor of entries |start| and
		// |end-1|.
		// xor trims the common prefix between the first and last entry. The bit len
		// of the result is the height of the subtree.
		level := uint(bits.Len64((end - 1) ^ start))
		// Then, shift the tree down by |level| to make this node a leaf.
		index := (end - 1) >> level

		p := nodes(index, 0, index+1)
		// The first node of the proof is the subtree's root. It is already known
		// by the client and should be skipped.
		p = p.skipFirst()

		// Shift the nodes back up.
		for n := range p.IDs {
			p.IDs[n].Level += level
		}
		// p.ephem might not be used by the resulting proof, but shift it
		// unconditionally for uniformity.
		p.ephem.Level += level
		return p, nil
	}

	// Find the root of the biggest perfect subtree of [start, end) ending at end.
	level := uint(bits.TrailingZeros64(end - start))
	index := (end - 1) >> level

	// The consistency proof consists of this node (except if the subtree is full,
	// in which case adding this node would be redundant because the client is
	// assumed to know it from a checkpoint), and nodes of the inclusion proof
	// of this node in the tree of the given size.
	p := nodes(index, level, size)
	// Handle the case when the subtree size is a power of 2.
	if (end-start)&(end-start-1) == 0 {
		return p.skipFirst(), nil
	}
	return p, nil
}

// nodes returns the node IDs necessary to prove that the (level, index) node
// is included in the Merkle tree of the given size.
func nodes(index uint64, level uint, size uint64) Nodes {
	// Compute the `fork` node, where the path from root to (level, index) node
	// diverges from the path to (0, size).
	//
	// The sibling of this node is the ephemeral node which represents a subtree
	// that is not complete in the tree of the given size. To compute the hash
	// of the ephemeral node, we need all the non-ephemeral nodes that cover the
	// same range of leaves.
	//
	// The `inner` variable is how many layers up from (level, index) the `fork`
	// and the ephemeral nodes are.
	inner := bits.Len64(index^(size>>level)) - 1
	fork := compact.NewNodeID(level+uint(inner), index>>inner)

	begin, end := fork.Coverage()
	left := compact.RangeSize(0, begin)
	right := compact.RangeSize(end, size)

	node := compact.NewNodeID(level, index)
	// Pre-allocate the exact number of nodes for the proof, in order:
	// - The seed node for which we are building the proof.
	// - The `inner` nodes at each level up to the fork node.
	// - The `right` nodes, comprising the ephemeral node.
	// - The `left` nodes, completing the coverage of the whole [0, size) range.
	nodes := append(make([]compact.NodeID, 0, 1+inner+right+left), node)

	// The first portion of the proof consists of the siblings for nodes of the
	// path going up to the level at which the ephemeral node appears.
	for ; node.Level < fork.Level; node = node.Parent() {
		nodes = append(nodes, node.Sibling())
	}
	// This portion of the proof covers the range [begin, end) under it. The
	// ranges to the left and to the right from it remain to be covered.

	// Add all the nodes (potentially none) that cover the right range, and
	// represent the ephemeral node. Reverse them so that the Rehash method can
	// process hashes in the convenient order, from lower to upper levels.
	len1 := len(nodes)
	nodes = compact.RangeNodes(end, size, nodes)
	reverse(nodes[len(nodes)-right:])
	len2 := len(nodes)
	// Add the nodes that cover the left range, ordered increasingly by level.
	nodes = compact.RangeNodes(0, begin, nodes)
	reverse(nodes[len(nodes)-left:])

	// nodes[len1:len2] contains the nodes representing the ephemeral node. If
	// it's empty, make it zero. Note that it can also contain a single node.
	// Depending on the preference of the layer above, it may or may not be
	// considered ephemeral.
	if len1 >= len2 {
		len1, len2 = 0, 0
	}

	// Edge case: For perfect trees the ephemeral node is the sibling of the root
	// However, it will not be used in any proof.
	return Nodes{IDs: nodes, begin: len1, end: len2, ephem: fork.Sibling()}
}

// Ephem returns the ephemeral node, and indices begin and end, such that
// IDs[begin:end] slice contains the child nodes of the ephemeral node.
//
// The list is empty iff there are no ephemeral nodes in the proof. Some
// examples of when this can happen: a proof in a perfect tree; an inclusion
// proof for a leaf in a perfect subtree at the right edge of the tree.
func (n Nodes) Ephem() (compact.NodeID, int, int) {
	return n.ephem, n.begin, n.end
}

// Rehash computes the proof based on the slice of node hashes corresponding to
// their IDs in the n.IDs field. The slices must be of the same length. The hc
// parameter computes a node's hash based on hashes of its children.
//
// Warning: The passed-in slice of hashes can be modified in-place.
func (n Nodes) Rehash(h [][]byte, hc func(left, right []byte) []byte) ([][]byte, error) {
	if got, want := len(h), len(n.IDs); got != want {
		return nil, fmt.Errorf("got %d hashes but expected %d", got, want)
	}
	cursor := 0
	// Scan the list of node hashes, and store the rehashed list in-place.
	// Invariant: cursor <= i, and h[:cursor] contains all the hashes of the
	// rehashed list after scanning h up to index i-1.
	for i, ln := 0, len(h); i < ln; i, cursor = i+1, cursor+1 {
		hash := h[i]
		if i >= n.begin && i < n.end {
			// Scan the block of node hashes that need rehashing.
			for i++; i < n.end; i++ {
				hash = hc(h[i], hash)
			}
			i--
		}
		h[cursor] = hash
	}
	return h[:cursor], nil
}

func (n Nodes) skipFirst() Nodes {
	n.IDs = n.IDs[1:]
	// Fixup the indices into the IDs slice.
	if n.begin < n.end {
		n.begin--
		n.end--
	}
	return n
}

func reverse(ids []compact.NodeID) {
	for i, j := 0, len(ids)-1; i < j; i, j = i+1, j-1 {
		ids[i], ids[j] = ids[j], ids[i]
	}
}

// FindSubtrees returns three indices (start, mid, end) defining two adjacent
// subtrees [start, mid) and [mid, end) that efficiently cover the input range.
//
// This function applies the "Selecting Two Subtrees" procedure from
// Section 4.5.1 of draft-ietf-plants-merkle-tree-certs.
//
// Note that:
//   - If the input range has a size <= 1, then this function returns [start, end) and an empty subtree [end, end).
//   - If the provided [start, end) range is already a valid subtree, then it is still split into two smaller subtrees.
//   - The [mid, end) range, if not empty, is adjacent to the first, and may not be a perfect subtree.
//   - The returned subtrees ranges fully cover the input range.
//   - There are no "extra" entries covered past end, but there may be covered entries prior to start (i.e. returned start <= input start).
//   - The number of entries covered before the input start is always less than half the size of the first returned subtree.
func FindSubtrees(start, end uint64) (uint64, uint64, uint64, error) {
	if start > end {
		return 0, 0, 0, fmt.Errorf("start %d must be less than or equal to end %d", start, end)
	}
	if end-start <= 1 {
		return start, end, end, nil
	}
	last := end - 1
	// Find where start and last's tree paths diverge.
	split := bits.Len64(start^last) - 1
	mask := (uint64(1) << split) - 1
	mid := last & ^mask

	// Maximize the left endpoint.
	leftSplit := bits.Len64(^start & mask)
	leftStart := start & ^((uint64(1) << leftSplit) - 1)
	return leftStart, mid, end, nil
}

// isSubtreeValid returns whether a subtree covers a valid range.
// A subtree is valid if there exist a parent tree node to:
// - all the subtree nodes
// - no extra node to the left of the subtree
// - potentially extra nodes to the right of the subtree
func isSubtreeValid(start, end uint64) error {
	if start > end {
		return fmt.Errorf("start %d must be less than or equal to end %d", start, end)
	}
	if start == 0 {
		return nil
	}
	if start == end {
		return nil
	}

	l := end - start

	// special-case large subtree to avoid panic
	if l > uint64(1)<<63 {
		return fmt.Errorf("start %d must be 0 when subtree length %d > 1<<63", start, l)
	}
	if bc := bitCeil(l); start&(bc-1) != 0 {
		return fmt.Errorf("start %d not a multiple of bit_ceil(end - start) = %d", start, bc)
	}

	return nil
}

// bitCeil returns the smallest power of 2 larger than or equal to n.
// MUST NOT be used with n larger than uint64(1)<<63.
func bitCeil(n uint64) uint64 {
	if n <= 1 {
		return 1
	}
	return uint64(1) << bits.Len64(n-1)
}
