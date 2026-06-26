// Copyright 2017 Google LLC. All Rights Reserved.
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
	"errors"
	"fmt"
	"math/bits"

	"github.com/transparency-dev/merkle"
)

// RootMismatchError occurs when an inclusion proof fails.
type RootMismatchError struct {
	ExpectedRoot   []byte
	CalculatedRoot []byte
}

func (e RootMismatchError) Error() string {
	return fmt.Sprintf("calculated root:\n%v\n does not match expected root:\n%v", e.CalculatedRoot, e.ExpectedRoot)
}

func verifyMatch(calculated, expected []byte) error {
	if !bytes.Equal(calculated, expected) {
		return RootMismatchError{ExpectedRoot: expected, CalculatedRoot: calculated}
	}
	return nil
}

// VerifyInclusion verifies the correctness of the inclusion proof for the leaf
// with the specified hash and index, relatively to the tree of the given size
// and root hash. Requires 0 <= index < size.
func VerifyInclusion(hasher merkle.LogHasher, index, size uint64, leafHash []byte, proof [][]byte, root []byte) error {
	calcRoot, err := RootFromInclusionProof(hasher, index, size, leafHash, proof)
	if err != nil {
		return err
	}
	return verifyMatch(calcRoot, root)
}

// VerifySubtreeInclusion verifies the correctness of the subtree inclusion
// proof for the leaf with the specified hash and index, relative to the
// provided subtree [start, end) subtree and subtree root hash.
// It requires:
//   - 0 <= start <= index < end
//   - start to be a multiple of the smallest power of two greater than or equal to
//     (end - start)
func VerifySubtreeInclusion(hasher merkle.LogHasher, index, start, end uint64, leafHash []byte, proof [][]byte, root []byte) error {
	if err := isSubtreeValid(start, end); err != nil {
		return fmt.Errorf("subtree invalid: %v", err)
	}
	if index < start || index >= end {
		return fmt.Errorf("index %d out of bounds for subtree [%d, %d)", index, start, end)
	}
	calcRoot, err := RootFromInclusionProof(hasher, index-start, end-start, leafHash, proof)
	if err != nil {
		return err
	}
	return verifyMatch(calcRoot, root)
}

// RootFromInclusionProof calculates the expected root hash for a tree of the
// given size, provided a leaf index and hash with the corresponding inclusion
// proof. Requires 0 <= index < size.
func RootFromInclusionProof(hasher merkle.LogHasher, index, size uint64, leafHash []byte, proof [][]byte) ([]byte, error) {
	if index >= size {
		return nil, fmt.Errorf("index is beyond size: %d >= %d", index, size)
	}
	if got, want := len(leafHash), hasher.Size(); got != want {
		return nil, fmt.Errorf("leafHash has unexpected size %d, want %d", got, want)
	}

	inner, border := decompInclProof(index, size)
	if got, want := len(proof), inner+border; got != want {
		return nil, fmt.Errorf("wrong proof size %d, want %d", got, want)
	}

	res := chainInner(hasher, leafHash, proof[:inner], index)
	res = chainBorderRight(hasher, res, proof[inner:])
	return res, nil
}

// VerifyConsistency checks that the passed-in consistency proof is valid
// between the passed in tree sizes, with respect to the corresponding root
// hashes. Requires 0 < size1 <= size2.
func VerifyConsistency(hasher merkle.LogHasher, size1, size2 uint64, proof [][]byte, root1, root2 []byte) error {
	hash2, err := RootFromConsistencyProof(hasher, size1, size2, proof, root1)
	if err != nil {
		return err
	}
	return verifyMatch(hash2, root2)
}

// VerifySubtreeConsistency checks that the passed-in subtree consistency proof
// is valid between the passed in subtree indices and parent tree size, with
// respect to the corresponding subtree root node hash. It Requires:
//   - 0 <= start < end <= size.
//   - start to be a multiple of the smallest power of two greater than or equal to
//     (end - start)
func VerifySubtreeConsistency(hasher merkle.LogHasher, start, end, size uint64, proof [][]byte, subRoot, parentRoot []byte) error {
	hash2, err := RootFromSubtreeConsistencyProof(hasher, start, end, size, proof, subRoot)
	if err != nil {
		return err
	}
	return verifyMatch(hash2, parentRoot)
}

// RootFromConsistencyProof calculates the expected root hash for a tree of the
// given size2, provided a tree of size1 with root1, and a consistency proof.
// Requires 0 < size1 <= size2.
// Note that consistency proofs from a size1==0 cannot be computed.
func RootFromConsistencyProof(hasher merkle.LogHasher, size1, size2 uint64, proof [][]byte, root1 []byte) ([]byte, error) {
	switch {
	case size2 < size1:
		return nil, fmt.Errorf("size2 (%d) < size1 (%d)", size1, size2)
	case size1 == 0:
		return nil, errors.New("consistency proof from empty tree is meaningless")
	case size1 == size2:
		if len(proof) > 0 {
			return nil, errors.New("size1=size2, but proof is not empty")
		}
		return root1, nil
	case len(proof) == 0:
		return nil, errors.New("empty proof")
	}
	return rootFromSubtreeConsistencyProof(hasher, 0, size1, size2, proof, root1)
}

// RootFromSubtreeConsistencyProof calculates the expected root hash for a
// parent tree of the given size, from a subtree [start, end) with its root and
// a consistency proof.
//
// It requires:
//   - 0 <= start < end <= size.
//   - start to be a multiple of the smallest power of two greater than or equal to
//     (end - start)
//
// Returns an error if the proof does not hash to the provided subtree root.
func RootFromSubtreeConsistencyProof(hasher merkle.LogHasher, start, end, size uint64, proof [][]byte, subRoot []byte) ([]byte, error) {
	err := isSubtreeValid(start, end)
	switch {
	case err != nil:
		return nil, fmt.Errorf("subtree invalid: %v", err)
	case size < end:
		return nil, fmt.Errorf("size (%d) < end (%d)", size, end)
	case start == 0 && size == end:
		if len(proof) > 0 {
			return nil, errors.New("start=0 and end=size, but proof is not empty")
		}
		return subRoot, nil
	case len(proof) == 0:
		return nil, errors.New("empty proof")
	}
	return rootFromSubtreeConsistencyProof(hasher, start, end, size, proof, subRoot)
}

func rootFromSubtreeConsistencyProof(hasher merkle.LogHasher, start, end, size uint64, proof [][]byte, subRoot []byte) ([]byte, error) {
	// If the right end of the subtree is also the right end of the parent tree,
	// the proof allows reconstructing the tree root directly from the argument
	// subtree root |subRoot|.
	if end == size {
		// Find the root of the subtree.
		// xor trims the common prefix between the first and last entry. The bit len
		// of the result is the height of the subtree.
		level := bits.Len64((end - 1) ^ start) // Height of the subtree.
		index := start >> level
		// To reconstruct the root from the subtree root, we need one left sibling
		// node for each level where the subtree's ancestor is a right child.
		want := bits.OnesCount64(index)
		if got := len(proof); got != want {
			return nil, fmt.Errorf("wrong proof size %d, want %d", got, want)
		}
		return chainBorderRight(hasher, subRoot, proof), nil
	}

	// Otherwise, we need to:
	//   - Verify that nodes in the proof that belong to the subtree are consistent
	//     with the argument subtree root |subRoot|.
	//   - Reconstruct the parent tree root from the argument subtree root
	//     grown into a subtree of the parent tree of size |size|.
	//
	// Split the proof in two, where paths to leaves |end-1| and |size-1| diverge.
	forkLevel, border := decompInclProof(end-1, size)
	// Height of the rightmost perfect subtree within the argument subtree.
	// The proof starts at this level.
	shift := bits.TrailingZeros64(end - start)
	// Number of levels between the root of that subtree and the end of the first
	// part of the proof.
	inner := forkLevel - shift // Note: shift < inner if end < size.

	// The first node of the proof is the root of the rightmost subtree within
	// the argument subtree.
	seed, pStart := proof[0], 1
	// Unless the argument subtree is perfect, in which case that rightmost
	// subtree is the argument subtree itself. Its root is not included in the
	// proof since a client verifying a subtree inclusion proof is expected to
	// already know what the root of that subtree is.
	if (end - start) == 1<<uint(shift) {
		seed, pStart = subRoot, 0
	}
	if got, want := len(proof), pStart+inner+border; got != want {
		return nil, fmt.Errorf("wrong proof size %d, want %d", got, want)
	}
	proof = proof[pStart:]
	// Now len(proof) == inner+border, and proof is effectively a suffix of
	// the inclusion proof for entry |end-1| in a tree of size |size|.

	mask := (end - 1) >> uint(shift) // Start chaining from level |shift|.

	// If the argument subtree is not perfect, the proof includes some nodes that
	// belong to the subtree. We must verify that these nodes chain correctly to
	// the argument subtree root.
	if pStart == 1 {
		subInner, subBorder := decompSubtreeProof(start, end, size, border, proof)
		hash1 := chainInnerRight(hasher, seed, subInner, mask)
		hash1 = chainBorderRight(hasher, hash1, subBorder)
		if err := verifyMatch(hash1, subRoot); err != nil {
			return nil, err
		}
	}

	// Verify the second root.
	hash2 := chainInner(hasher, seed, proof[:inner], mask)
	hash2 = chainBorderRight(hasher, hash2, proof[inner:])
	return hash2, nil
}

// decompInclProof breaks down inclusion proof for a leaf at the specified
// |index| in a tree of the specified |size| into 2 components. The splitting
// point between them is where paths to leaves |index| and |size-1| diverge.
// Returns lengths of the inner and border proof parts correspondingly. The sum
// of the two determines the correct length of the inclusion proof.
//
// Inner nodes are left or right siblings depending on the level they are used
// in the proof. There can be multiple nodes per level.
// Border nodes are left siblings only. There's only one node per level.
func decompInclProof(index, size uint64) (int, int) {
	inner := innerProofSize(index, size)
	border := bits.OnesCount64(index >> uint(inner))
	return inner, border
}

// decompSubtreeProof computes the exact proof slice indices needed to
// reconstruct the [start, end) subtree root.
//   - proof[0:subInner]: inner proof hashes under the subtree root node
//     in a tree of size |end| or |size|. These nodes can be inside or outside
//     of the subtree, and left or right siblings depending on the level at
//     which they are used in the proof. Only left siblings (except possibly
//     the first node) are required to reconstruct the subtree root hash, and
//     right siblings can be ignored.
//   - proof[inner:inner+subBorder]: border proof hashes, inside the subtree.
//     These nodes are left siblings only, and there's one hash per level.
func decompSubtreeProof(start, end, size uint64, border int, proof [][]byte) (subInnerProof [][]byte, subBorderProof [][]byte) {
	// xor trims the common prefix between the first and last entry. The bit len
	// of the result is the height of the subtree.
	h := bits.Len64((end - 1) ^ start)
	// Using a similar technique, we compute where paths to leaves |end-1| and
	// |size-1| diverge.
	forkLevel := bits.Len64((end - 1) ^ (size - 1))
	// Height of the rightmost perfect subtree within the argument subtree.
	// The proof starts at this level.
	shift := bits.TrailingZeros64(end - start)

	// Number of inner proof nodes from level |shift| up to subtree height |h|
	// (clamped at |forkLevel|) that belong inside the [start, end) subtree.
	// We take the minimum between h and forkLevel to make sure that subInner
	// isn't higher than the subtree root. Subtract shift since the proof
	// starts at this level.
	subInner := min(h, forkLevel) - shift
	// Total number of inner proof nodes between level |shift| and |forkLevel|.
	// It delimits the end of the inner proof nodes, and the beginning of the
	// border nodes.
	inner := forkLevel - shift
	// Number of border proof nodes above |forkLevel| and below subtree height |h|
	// that belong inside the [start, end) subtree. Use max as the border proof
	// might not include any nodes that belong to the subtree.
	subBorder := max(0, border-bits.OnesCount64((end-1)>>uint(h)))
	// The proof slice indices needed to reconstruct hash1 are [0:subInner] for
	// inner-right chaining and [inner:inner+subBorder] for border chaining.
	return proof[0:subInner], proof[inner : inner+subBorder]
}

func innerProofSize(index, size uint64) int {
	// Height of the first node where the paths of leaves at |index| and |size-1|
	// diverge.
	return bits.Len64(index ^ (size - 1))
}

// chainInner computes a subtree hash for a node on or below the tree's right
// border. Assumes |proof| hashes are ordered from lower levels to upper, and
// |seed| is the initial subtree/leaf hash on the path located at the specified
// |index| on its level.
func chainInner(hasher merkle.LogHasher, seed []byte, proof [][]byte, index uint64) []byte {
	for i, h := range proof {
		if (index>>uint(i))&1 == 0 {
			seed = hasher.HashChildren(seed, h)
		} else {
			seed = hasher.HashChildren(h, seed)
		}
	}
	return seed
}

// chainInnerRight computes a subtree hash like chainInner, but only takes
// hashes to the left from the path into consideration, which effectively means
// the result is a hash of the corresponding earlier version of this subtree.
func chainInnerRight(hasher merkle.LogHasher, seed []byte, proof [][]byte, index uint64) []byte {
	for i, h := range proof {
		if (index>>uint(i))&1 == 1 {
			seed = hasher.HashChildren(h, seed)
		}
	}
	return seed
}

// chainBorderRight chains proof hashes along tree borders. This differs from
// inner chaining because |proof| contains only left-side subtree hashes.
func chainBorderRight(hasher merkle.LogHasher, seed []byte, proof [][]byte) []byte {
	for _, h := range proof {
		seed = hasher.HashChildren(h, seed)
	}
	return seed
}
