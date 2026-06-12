// Copyright 2026 Google LLC. All Rights Reserved.
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

package testonly

import (
	"crypto/sha256"
	"fmt"
	"io"
	"math/bits"
	"testing"
)

// These tests reproduce the accumulated test vectors from the "Subtree Test
// Vectors" appendix of draft-ietf-plants-merkle-tree-certs. For trees of sizes
// up to 130, they fold the output of each subtree algorithm over every valid
// input into a single rolling SHA-256, which is compared against the value
// published in the draft.

const subtreeVectorMax = 130

// subtreeVectorTree builds the tree D used by the test vectors, with leaf values
// d[0] = 0x00, d[1] = 0x01, and so on.
func subtreeVectorTree() *Tree {
	entries := make([][]byte, subtreeVectorMax)
	for i := range entries {
		entries[i] = []byte{byte(i)}
	}
	return newTree(entries)
}

func isValidSubtree(start, end int) bool {
	if 0 > start || start >= end {
		return false
	}
	ceil := uint(1) << (bits.UintSize - bits.LeadingZeros(uint(end-start-1)))
	return uint(start)&(ceil-1) == 0
}

// writeProofLine writes prefix followed by, for each hash in the concatenated
// proof, a space and the hash's hexadecimal encoding, then a newline. An empty
// proof contributes no hashes and so leaves no trailing space.
func writeProofLine(w io.Writer, prefix string, proof [][]byte) {
	io.WriteString(w, prefix)
	for _, h := range proof {
		fmt.Fprintf(w, " %x", h)
	}
	io.WriteString(w, "\n")
}

func TestSubtreeHashVectors(t *testing.T) {
	tree := subtreeVectorTree()
	h := sha256.New()
	for end := 1; end <= subtreeVectorMax; end++ {
		for start := 0; start < end; start++ {
			if !isValidSubtree(start, end) {
				continue
			}
			subtreeHash := tree.SubtreeHashAt(uint64(start), uint64(end))
			fmt.Fprintf(h, "[%d, %d) %x\n", start, end, subtreeHash)
		}
	}

	const want = "94a95384a8c69acea9b50d035a58285b3a777cb7a724005faa5e1f1e1190007f"
	if got := fmt.Sprintf("%x", h.Sum(nil)); got != want {
		t.Errorf("subtree hash vector = %s, want %s", got, want)
	}
}

func TestSubtreeInclusionProofVectors(t *testing.T) {
	tree := subtreeVectorTree()
	h := sha256.New()
	for end := 1; end <= subtreeVectorMax; end++ {
		for start := 0; start < end; start++ {
			if !isValidSubtree(start, end) {
				continue
			}
			for index := start; index < end; index++ {
				proof, err := tree.SubtreeInclusionProof(uint64(index), uint64(start), uint64(end))
				if err != nil {
					t.Fatalf("SubtreeInclusionProof(%d, %d, %d): %v", index, start, end, err)
				}
				writeProofLine(h, fmt.Sprintf("%d [%d, %d)", index, start, end), proof)
			}
		}
	}
	const want = "ac2a8f989e44d99e399db448050ff5f19757df53cfb716aa81015d3955d8163f"
	if got := fmt.Sprintf("%x", h.Sum(nil)); got != want {
		t.Errorf("subtree inclusion proof vector = %s, want %s", got, want)
	}
}

func TestSubtreeConsistencyProofVectors(t *testing.T) {
	tree := subtreeVectorTree()
	h := sha256.New()
	for n := 0; n <= subtreeVectorMax; n++ {
		for end := 1; end <= n; end++ {
			for start := 0; start < end; start++ {
				if !isValidSubtree(start, end) {
					continue
				}
				proof, err := tree.SubtreeConsistencyProof(uint64(start), uint64(end), uint64(n))
				if err != nil {
					t.Fatalf("SubtreeConsistencyProof(%d, %d, %d): %v", start, end, n, err)
				}
				writeProofLine(h, fmt.Sprintf("[%d, %d) %d", start, end, n), proof)
			}
		}
	}
	const want = "c586ebbb73a5621baf2140095d87dde934e3b6503a562a1a5215b8209edd083d"
	if got := fmt.Sprintf("%x", h.Sum(nil)); got != want {
		t.Errorf("subtree consistency proof vector = %s, want %s", got, want)
	}
}
