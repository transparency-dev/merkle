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
	"bytes"
	"fmt"
	"math/bits"

	"github.com/transparency-dev/merkle/compact"
)

// RootMismatchError is an error occuring when a proof verification fails.
type RootMismatchError struct {
	Size     uint64 // The size at which the root hash mismatch happened.
	Computed []byte // The computed root hash at this size.
	Expected []byte // The expected root hash at this size.
}

// Error returns the error string for RootMismatchError.
func (e RootMismatchError) Error() string {
	return fmt.Sprintf("root hash at size %d mismatched: computed %x, expected %x", e.Size, e.Computed, e.Expected)
}

func verifyMatch(size uint64, computed, expected []byte) error {
	if !bytes.Equal(computed, expected) {
		return RootMismatchError{Size: size, Computed: computed, Expected: expected}
	}
	return nil
}

// NodeHasher allows computing hashes of internal nodes of the Merkle tree.
type NodeHasher interface {
	// HashChildren returns hash of a tree node based on hashes of its children.
	HashChildren(left, right []byte) []byte
}

// VerifyInclusion verifies the correctness of the inclusion proof for the leaf
// with the specified hash and index, relatively to the tree of the given size
// and root hash. Requires 0 <= index < size. Returns RootMismatchError if the
// computed root hash does not match the provided one.
func VerifyInclusion(nh NodeHasher, index, size uint64, hash []byte, proof [][]byte, root []byte) error {
	if index >= size {
		return fmt.Errorf("index %d out of range for size %d", index, size)
	}
	return verify(nh, index, 0, size, hash, proof, root)
}

// VerifyConsistency verifies that the consistency proof is valid between the
// two given tree sizes, with the corresponding root hashes.
// Requires 0 <= size1 <= size2. Returns RootMismatchError if any of the
// computed root hashes at size1 or size2 does not match the provided one.
func VerifyConsistency(nh NodeHasher, size1, size2 uint64, proof [][]byte, root1, root2 []byte) error {
	if size1 > size2 {
		return fmt.Errorf("tree size %d > %d", size1, size2)
	}
	if (size1 == size2 || size1 == 0) && len(proof) != 0 {
		return fmt.Errorf("incorrect proof size: got %d, want 0", len(proof))
	}
	if size1 == size2 {
		return verifyMatch(size1, root1, root2)
	}
	if size1 == 0 {
		return nil
	}

	// Find the root of the biggest perfect subtree that ends at size1.
	level := uint(bits.TrailingZeros64(size1))
	index := (size1 - 1) >> level
	// The consistency proof consists of this node (except if size1 is a power of
	// two, in which case adding this node would be redundant because the client
	// is assumed to know it from a checkpoint), and nodes of the inclusion proof
	// into this node in the tree of size2.

	// Handle the case when size1 is a power of 2.
	if index == 0 {
		return verify(nh, index, level, size2, root1, proof, root2)
	}

	// Otherwise, the consistency proof is equivalent to an inclusion proof of
	// its first hash. Verify it below.
	if got, want := len(proof), 1+bits.Len64(size2-1)-int(level); got != want {
		return fmt.Errorf("incorrect proof size: %d, want %d", got, want)
	}
	if err := verify(nh, index, level, size2, proof[0], proof[1:], root2); err != nil {
		return err
	}

	inner := bits.Len64(index^(size2>>level)) - 1
	hash := proof[0]
	for i, h := range proof[1 : 1+inner] {
		if (index>>uint(i))&1 == 1 {
			hash = nh.HashChildren(h, hash)
		}
	}
	for _, h := range proof[1+inner:] {
		hash = nh.HashChildren(h, hash)
	}
	return verifyMatch(size1, hash, root1)
}

func verify(nh NodeHasher, index uint64, level uint, size uint64, hash []byte, proof [][]byte, root []byte) error {
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
	right := 1
	if end == size { // No ephemeral nodes.
		right = 0
	}

	if got, want := len(proof), inner+right+left; got != want {
		return fmt.Errorf("incorrect proof size: %d, want %d", got, want)
	}

	node := compact.NewNodeID(level, index)
	for _, h := range proof[:inner] {
		if node.Index&1 == 0 {
			hash = nh.HashChildren(hash, h)
		} else {
			hash = nh.HashChildren(h, hash)
		}
		node = node.Parent()
	}
	if right == 1 {
		hash = nh.HashChildren(hash, proof[inner])
	}
	for _, h := range proof[inner+right:] {
		hash = nh.HashChildren(h, hash)
	}
	return verifyMatch(size, hash, root)
}
