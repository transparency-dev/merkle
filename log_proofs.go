// Copyright 2016 Google LLC. All Rights Reserved.
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

package merkle

import (
	"errors"
	"fmt"

	"github.com/transparency-dev/merkle/proof"
)

// NodeFetch bundles a node ID with additional information on how to use the
// node to construct a proof.
type NodeFetch = proof.NodeFetch

// CalcInclusionProofNodeAddresses returns the tree node IDs needed to build an
// inclusion proof for a specified tree size and leaf index. All the returned
// nodes represent complete subtrees in the tree of this size or above.
//
// Use Rehash function to compose the proof after the node hashes are fetched.
func CalcInclusionProofNodeAddresses(size, index uint64) ([]NodeFetch, error) {
	if size < 1 {
		return nil, fmt.Errorf("invalid parameter for inclusion proof: size %d < 1", size)
	}
	if index >= size {
		return nil, fmt.Errorf("invalid parameter for inclusion proof: index %d is >= size %d", index, size)
	}
	return proof.Nodes(index, 0, size, true), nil
}

// CalcConsistencyProofNodeAddresses returns the tree node IDs needed to build
// a consistency proof between two specified tree sizes. All the returned nodes
// represent complete subtrees in the tree of size2 or above.
//
// Use Rehash function to compose the proof after the node hashes are fetched.
func CalcConsistencyProofNodeAddresses(size1, size2 uint64) ([]NodeFetch, error) {
	if size1 < 1 {
		return nil, fmt.Errorf("invalid parameter for consistency proof: size1 %d < 1", size1)
	}
	if size2 < 1 {
		return nil, fmt.Errorf("invalid parameter for consistency proof: size2 %d < 1", size2)
	}
	if size1 > size2 {
		return nil, fmt.Errorf("invalid parameter for consistency proof: size1 %d > size2 %d", size1, size2)
	}

	return proof.Consistency(size1, size2), nil
}

// Rehash computes the proof based on the slice of NodeFetch structs, and the
// corresponding hashes of these nodes. The slices must be of the same length.
// The hc parameter computes node's hash based on hashes of its children.
//
// Warning: The passed-in slice of hashes can be modified in-place.
func Rehash(h [][]byte, nf []NodeFetch, hc func(left, right []byte) []byte) ([][]byte, error) {
	if len(h) != len(nf) {
		return nil, errors.New("slice lengths mismatch")
	}
	cursor := 0
	// Scan the list of node hashes, and store the rehashed list in-place.
	// Invariant: cursor <= i, and h[:cursor] contains all the hashes of the
	// rehashed list after scanning h up to index i-1.
	for i, ln := 0, len(h); i < ln; i, cursor = i+1, cursor+1 {
		hash := h[i]
		if nf[i].Rehash {
			// Scan the block of node hashes that need rehashing.
			for i++; i < len(nf) && nf[i].Rehash; i++ {
				hash = hc(h[i], hash)
			}
			i--
		}
		h[cursor] = hash
	}
	return h[:cursor], nil
}
