//go:build go1.18

package testonly

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/transparency-dev/merkle/proof"
)

// Compute and verify consistency proofs
func FuzzConsistencyProof(f *testing.F) {
	for size := 0; size <= 8; size++ {
		for size2 := 0; size2 <= size; size2++ {
			for size1 := 0; size1 <= size2; size1++ {
				f.Add(uint64(size), uint64(size1), uint64(size2))
			}
		}
	}
	f.Fuzz(func(t *testing.T, size, size1, size2 uint64) {
		t.Logf("size=%d, size1=%d, size2=%d", size, size1, size2)
		if size1 > size2 || size2 > size {
			return
		}
		tree := newTree(genEntries(size))
		p, err := tree.ConsistencyProof(size1, size2)
		t.Logf("proof=%v", p)
		if err != nil {
			t.Error(err)
		}
		err = proof.VerifyConsistency(tree.hasher, size1, size2, p, tree.HashAt(size1), tree.HashAt(size2))
		if err != nil {
			t.Error(err)
		}
	})
}

// Compute and verify inclusion proofs
func FuzzInclusionProof(f *testing.F) {
	for size := 0; size <= 8; size++ {
		for index := 0; index <= size; index++ {
			f.Add(uint64(index), uint64(size))
		}
	}
	f.Fuzz(func(t *testing.T, index, size uint64) {
		t.Logf("index=%d, size=%d", index, size)
		if index >= size {
			return
		}
		tree := newTree(genEntries(size))
		p, err := tree.InclusionProof(index, size)
		t.Logf("proof=%v", p)
		if err != nil {
			t.Error(err)
		}
		err = proof.VerifyInclusion(tree.hasher, index, size, tree.LeafHash(index), p, tree.Hash())
		if err != nil {
			t.Error(err)
		}
	})
}

func FuzzHashAtAgainstReferenceImplementation(f *testing.F) {
	for size := 0; size <= 8; size++ {
		for index := 0; index <= size; index++ {
			f.Add(uint64(index), uint64(size))
		}
	}
	f.Fuzz(func(t *testing.T, index, size uint64) {
		t.Logf("index=%d, size=%d", index, size)
		if index >= size {
			return
		}
		entries := genEntries(size)
		mt := newTree(entries)
		got := mt.HashAt(uint64(size))
		want := refRootHash(entries[:size], mt.hasher)
		if !bytes.Equal(got, want) {
			t.Errorf("HashAt(%d): %x, want %x", size, got, want)
		}
	})
}

func FuzzInclusionProofAgainstReferenceImplementation(f *testing.F) {
	for size := 0; size <= 8; size++ {
		for index := 0; index <= size; index++ {
			f.Add(uint64(index), uint64(size))
		}
	}
	f.Fuzz(func(t *testing.T, index, size uint64) {
		t.Logf("index=%d, size=%d", index, size)
		if index >= size {
			return
		}
		entries := genEntries(size)
		tree := newTree(entries)
		got, err := tree.InclusionProof(index, size)
		t.Logf("proof=%v", got)
		if err != nil {
			t.Error(err)
		}
		want := refInclusionProof(entries, index, tree.hasher)
		if diff := cmp.Diff(got, want, cmpopts.EquateEmpty()); diff != "" {
			t.Fatalf("InclusionProof(%d, %d): diff (-got +want)\n%s", index, size, diff)
		}
	})
}
