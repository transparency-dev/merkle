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
	return nodes(index, 0, size), nil
}

// Consistency returns the information on how to fetch and construct a
// consistency proof between the two given tree sizes of a log Merkle tree. It
// requires 0 <= size1 <= size2.
func Consistency(size1, size2 uint64) (Nodes, error) {
	if size1 > size2 {
		return Nodes{}, fmt.Errorf("tree size %d > %d", size1, size2)
	}
	if size1 == size2 || size1 == 0 {
		return Nodes{IDs: []compact.NodeID{}}, nil
	}

	// Find the root of the biggest perfect subtree that ends at size1.
	level := uint(bits.TrailingZeros64(size1))
	index := (size1 - 1) >> level
	// The consistency proof consists of this node (except if size1 is a power of
	// two, in which case adding this node would be redundant because the client
	// is assumed to know it from a checkpoint), and nodes of the inclusion proof
	// into this node in the tree of size2.
	p := nodes(index, level, size2)

	// Handle the case when size1 is not a power of 2.
	if index != 0 {
		// Prepend the earlier computed node to the proof.
		// TODO(pavelkalinnikov): This code path is invoked almost always. Avoid
		// the extra allocation that append does.
		p.IDs = append(p.IDs, compact.NodeID{})
		copy(p.IDs[1:], p.IDs)
		p.IDs[0] = compact.NewNodeID(level, index)

		// Fixup the indices into the IDs slice.
		if p.begin < p.end {
			p.begin++
			p.end++
		}
	}

	return p, nil
}

// nodes returns the node IDs necessary to prove that the (level, index) node
// is included in the Merkle tree of the given size.
func nodes(index uint64, level uint, size uint64) Nodes {
	node := compact.NewNodeID(level, index)
	begin, _ := node.Coverage()

	// Compute the level at which the path to leaf `begin` diverges from the path
	// to `size`. This is where the ephemeral node is located. The ephemeral node
	// represents a subtree that is not complete in the tree of the given size,
	// so we instead provide the minimal list of non-ephemeral nodes which cover
	// the same range of leaves.
	ephemLevel := uint(bits.Len64(begin^size) - 1)

	// The first portion of the proof consists of the siblings for nodes of the
	// path going up to the level at which the ephemeral node appears.
	// TODO(pavelkalinnikov): Pre-allocate the full capacity.
	nodes := make([]compact.NodeID, 0, ephemLevel-level)
	for ; node.Level < ephemLevel; node = node.Parent() {
		nodes = append(nodes, node.Sibling())
	}
	// This portion of the proof covers the range under the reached node. The
	// ranges to the left and to the right from it remain to be covered.
	begin, end := node.Coverage()

	// Add all the nodes (potentially none) that cover the right range, and
	// represent the ephemeral node. Reverse them so that the Rehash method can
	// process hashes in the convenient order, from lower to upper levels.
	len1 := len(nodes)
	nodes = append(nodes, reverse(compact.RangeNodes(end, size))...)
	len2 := len(nodes)
	// Add the nodes that cover the left range, ordered increasingly by level.
	nodes = append(nodes, reverse(compact.RangeNodes(0, begin))...)

	// nodes[len1:len2] contains the nodes representing the ephemeral node. If
	// it's empty or only has one node, make it zero.
	//
	// TODO(pavelkalinnikov): Don't empty the single node case. It is still a
	// valuable info to expose.
	if len1+1 >= len2 {
		len1, len2 = 0, 0
	}

	return Nodes{IDs: nodes, begin: len1, end: len2, ephem: node.Sibling()}
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

func reverse(ids []compact.NodeID) []compact.NodeID {
	for i, j := 0, len(ids)-1; i < j; i, j = i+1, j-1 {
		ids[i], ids[j] = ids[j], ids[i]
	}
	return ids
}
