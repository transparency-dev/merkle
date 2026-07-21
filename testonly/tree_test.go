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

package testonly

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/transparency-dev/merkle/rfc6962"
)

func validateTree(t *testing.T, mt *Tree, size uint64) {
	t.Helper()
	if got, want := mt.Size(), size; got != want {
		t.Errorf("Size: %d, want %d", got, want)
	}
	roots := RootHashes()
	if got, want := mt.Hash(), roots[size]; !bytes.Equal(got, want) {
		t.Errorf("Hash(%d): %x, want %x", size, got, want)
	}
	for s := range size + 1 {
		if got, want := mt.HashAt(s), roots[s]; !bytes.Equal(got, want) {
			t.Errorf("HashAt(%d/%d): %x, want %x", s, size, got, want)
		}
	}
}

func TestBuildTreeBuildOneAtATime(t *testing.T) {
	mt := newTree(nil)
	validateTree(t, mt, 0)
	for i, entry := range LeafInputs() {
		mt.AppendData(entry)
		validateTree(t, mt, uint64(i+1))
	}
}

func TestBuildTreeBuildTwoChunks(t *testing.T) {
	entries := LeafInputs()
	mt := newTree(nil)
	mt.AppendData(entries[:3]...)
	validateTree(t, mt, 3)
	mt.AppendData(entries[3:8]...)
	validateTree(t, mt, 8)
}

func TestBuildTreeBuildAllAtOnce(t *testing.T) {
	mt := newTree(nil)
	mt.AppendData(LeafInputs()...)
	validateTree(t, mt, 8)
}

func TestTreeHashAt(t *testing.T) {
	test := func(desc string, entries [][]byte) {
		t.Run(desc, func(t *testing.T) {
			mt := newTree(entries)
			for size := range len(entries) + 1 {
				got := mt.HashAt(uint64(size))
				want := refRootHash(entries[:size], mt.hasher)
				if !bytes.Equal(got, want) {
					t.Errorf("HashAt(%d): %x, want %x", size, got, want)
				}
			}
		})
	}

	entries := LeafInputs()
	for size := range len(entries) + 1 {
		test(fmt.Sprintf("size:%d", size), entries[:size])
	}
	test("generated:256", genEntries(256))
}

func TestTreeInclusionProof(t *testing.T) {
	test := func(desc string, entries [][]byte) {
		t.Run(desc, func(t *testing.T) {
			mt := newTree(entries)
			size := uint64(len(entries))
			for index := range size {
				got, err := mt.InclusionProof(index, size)
				if err != nil {
					t.Fatalf("InclusionProof(%d, %d): %v", index, size, err)
				}
				want := refInclusionProof(entries[:size], index, mt.hasher)
				if diff := cmp.Diff(got, want, cmpopts.EquateEmpty()); diff != "" {
					t.Fatalf("InclusionProof(%d, %d): diff (-got +want)\n%s", index, size, diff)
				}
			}
		})
	}

	test("generated:256", genEntries(256))
	entries := LeafInputs()
	for size := range len(entries) {
		test(fmt.Sprintf("golden:%d", size), entries[:size])
	}
}

func TestSubtreeInclusionProof(t *testing.T) {
	test := func(desc string, entries [][]byte) {
		for end := uint64(1); end < uint64(len(entries)); end++ {
			for start := range end {
				if err := isSubtreeValid(start, end); err != nil {
					continue
				}
				mt := newTree(entries)
				t.Run(fmt.Sprintf("%s:%d:%d", desc, start, end), func(t *testing.T) {
					t.Parallel()
					subtreeEntries := entries[start:end]
					for index := start; index < end; index++ {
						got, err := mt.SubtreeInclusionProof(index, start, end)
						if err != nil {
							t.Fatalf("SubtreeInclusionProof(%d, %d, %d): %v", index, start, end, err)
						}
						want := refInclusionProof(subtreeEntries, index-start, mt.hasher)
						if diff := cmp.Diff(got, want, cmpopts.EquateEmpty()); diff != "" {
							t.Fatalf("SubtreeInclusionProof(%d, %d, %d): diff (-got +want)\n%s", index, start, end, diff)
						}
					}
				})
			}
		}
	}

	// Use smaller trees with subtrees to reduce test duration.
	test("generated:128", genEntries(128))
	entries := LeafInputs()
	for size := 1; size <= len(entries); size++ {
		test(fmt.Sprintf("golden:%d", size), entries[:size])
	}
}

func TestTreeConsistencyProof(t *testing.T) {
	entries := LeafInputs()
	mt := newTree(entries)
	validateTree(t, mt, 8)

	if _, err := mt.ConsistencyProof(6, 3); err == nil {
		t.Error("ConsistencyProof(6, 3) succeeded unexpectedly")
	}
	if _, err := mt.ConsistencyProof(0, 3); err == nil {
		t.Error("ConsistencyProof(0, 3) succeeded unexpectedly")
	}

	for size1 := uint64(1); size1 <= 8; size1++ {
		for size2 := size1; size2 <= 8; size2++ {
			t.Run(fmt.Sprintf("%d:%d", size1, size2), func(t *testing.T) {
				got, err := mt.ConsistencyProof(size1, size2)
				if err != nil {
					t.Fatalf("ConsistencyProof: %v", err)
				}
				want := refConsistencyProof(entries[:size2], size2, size1, mt.hasher, true)
				if diff := cmp.Diff(got, want, cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("ConsistencyProof: diff (-got +want)\n%s", diff)
				}
			})
		}
	}
}

// Make random proof queries and check against the reference implementation.
func TestTreeConsistencyProofFuzz(t *testing.T) {
	entries := genEntries(256)

	for treeSize := uint64(1); treeSize <= 256; treeSize++ {
		mt := newTree(entries[:treeSize])
		for range 8 {
			size2 := rand.Uint64N(treeSize) + 1
			size1 := rand.Uint64N(size2) + 1

			got, err := mt.ConsistencyProof(size1, size2)
			if err != nil {
				t.Fatalf("ConsistencyProof: %v", err)
			}
			want := refConsistencyProof(entries[:size2], size2, size1, mt.hasher, true)
			if diff := cmp.Diff(got, want, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("ConsistencyProof: diff (-got +want)\n%s", diff)
			}
		}
	}
}

func TestSubtreeTreeConsistencyProof(t *testing.T) {
	entries := LeafInputs()
	mt := newTree(entries)
	validateTree(t, mt, 8)

	if _, err := mt.SubtreeConsistencyProof(0, 6, 3); err == nil {
		t.Error("SubtreeConsistencyProof(0, 6, 3) succeeded unexpectedly (size < end)")
	}
	if _, err := mt.SubtreeConsistencyProof(1, 3, 8); err == nil {
		t.Error("SubtreeConsistencyProof(1, 3, 8) succeeded unexpectedly (invalid subtree)")
	}

	maxSize := uint64(len(entries))
	for size := range maxSize + 1 {
		for end := range size + 1 {
			for start := range end + 1 {
				if err := isSubtreeValid(start, end); err != nil {
					continue
				}
				t.Run(fmt.Sprintf("%d:%d:%d", start, end, size), func(t *testing.T) {
					got, err := mt.SubtreeConsistencyProof(start, end, size)
					if err != nil {
						t.Fatalf("SubtreeConsistencyProof: %v", err)
					}
					want := refSubtreeConsistencyProof(start, end, entries[:size], true, mt.hasher)
					if diff := cmp.Diff(got, want, cmpopts.EquateEmpty()); diff != "" {
						t.Errorf("SubtreeConsistencyProof: diff (-got +want)\n%s", diff)
					}
				})
			}
		}
	}
}

func TestTreeAppend(t *testing.T) {
	entries := genEntries(256)
	mt1 := newTree(entries)

	mt2 := newTree(nil)
	for _, entry := range entries {
		mt2.Append(rfc6962.DefaultHasher.HashLeaf(entry))
	}

	if diff := cmp.Diff(mt1, mt2, cmp.AllowUnexported(Tree{})); diff != "" {
		t.Errorf("Trees built with AppendData and Append mismatch: diff (-mt1 +mt2)\n%s", diff)
	}
}

func TestTreeAppendAssociativity(t *testing.T) {
	entries := genEntries(256)
	mt1 := newTree(nil)
	mt1.AppendData(entries...)

	mt2 := newTree(nil)
	for _, entry := range entries {
		mt2.AppendData(entry)
	}

	if diff := cmp.Diff(mt1, mt2, cmp.AllowUnexported(Tree{})); diff != "" {
		t.Errorf("AppendData is not associative: diff (-mt1 +mt2)\n%s", diff)
	}
}

func newTree(entries [][]byte) *Tree {
	tree := New(rfc6962.DefaultHasher)
	tree.AppendData(entries...)
	return tree
}

// genEntries a slice of entries of the given size.
func genEntries(size uint64) [][]byte {
	entries := make([][]byte, size)
	for i := range entries {
		entries[i] = []byte(strconv.Itoa(i))
	}
	return entries
}
