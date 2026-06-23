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
	"testing"
)

// These tests reproduce the accumulated test vectors from the "Subtree Test
// Vectors" appendix of draft-ietf-plants-merkle-tree-certs. For trees of sizes
// up to 130, they fold the output of each subtree algorithm over every valid
// input into a single rolling SHA-256, which is compared against the value
// published in the draft.

const subtreeVectorMax = uint64(130)

// subtreeVectorTree builds the tree D used by the test vectors, with leaf values
// d[0] = 0x00, d[1] = 0x01, and so on.
func subtreeVectorTree() *Tree {
	entries := make([][]byte, subtreeVectorMax)
	for i := range entries {
		entries[i] = []byte{byte(i)}
	}
	return newTree(entries)
}

// writeProofLine writes prefix followed by, for each hash in the concatenated
// proof, a space and the hash's hexadecimal encoding, then a newline. An empty
// proof contributes no hashes and so leaves no trailing space.
func writeProofLine(t *testing.T, w io.Writer, prefix string, proof [][]byte) {
	t.Helper()
	if _, err := io.WriteString(w, prefix); err != nil {
		t.Fatalf("io.WriteString: %v", err)
	}
	for _, h := range proof {
		if _, err := fmt.Fprintf(w, " %x", h); err != nil {
			t.Fatalf("fmt.Fprintf: %v", err)
		}
	}
	if _, err := io.WriteString(w, "\n"); err != nil {
		t.Fatalf("io.WriteString: %v", err)
	}
}

func TestSubtreeHashVectors(t *testing.T) {
	tree := subtreeVectorTree()
	h := sha256.New()
	for end := uint64(1); end <= subtreeVectorMax; end++ {
		for start := range end {
			if err := isSubtreeValid(start, end); err != nil {
				continue
			}
			subtreeHash := tree.SubtreeHashAt(start, end)
			if _, err := fmt.Fprintf(h, "[%d, %d) %x\n", start, end, subtreeHash); err != nil {
				t.Fatalf("fmt.Fprintf: %v", err)
			}
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
	for end := uint64(1); end <= subtreeVectorMax; end++ {
		for start := range end {
			if err := isSubtreeValid(start, end); err != nil {
				continue
			}
			for index := start; index < end; index++ {
				proof, err := tree.SubtreeInclusionProof(index, start, end)
				if err != nil {
					t.Fatalf("SubtreeInclusionProof(%d, %d, %d): %v", index, start, end, err)
				}
				writeProofLine(t, h, fmt.Sprintf("%d [%d, %d)", index, start, end), proof)
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
	for n := range subtreeVectorMax + 1 {
		for end := uint64(1); end <= n; end++ {
			for start := range end {
				if err := isSubtreeValid(start, end); err != nil {
					continue
				}
				proof, err := tree.SubtreeConsistencyProof(start, end, n)
				if err != nil {
					t.Fatalf("SubtreeConsistencyProof(%d, %d, %d): %v", start, end, n, err)
				}
				writeProofLine(t, h, fmt.Sprintf("[%d, %d) %d", start, end, n), proof)
			}
		}
	}
	const want = "c586ebbb73a5621baf2140095d87dde934e3b6503a562a1a5215b8209edd083d"
	if got := fmt.Sprintf("%x", h.Sum(nil)); got != want {
		t.Errorf("subtree consistency proof vector = %s, want %s", got, want)
	}
}
