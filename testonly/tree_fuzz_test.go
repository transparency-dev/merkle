//go:build go1.18

package testonly

import (
	"bytes"
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/transparency-dev/merkle/proof"
)

// Compute and verify consistency proofs
func FuzzConsistencyProofAndVerify(f *testing.F) {
	for size := 0; size <= 8; size++ {
		for end := 0; end <= size; end++ {
			for begin := 0; begin <= end; begin++ {
				f.Add(uint64(size), uint64(begin), uint64(end))
			}
		}
	}
	f.Fuzz(func(t *testing.T, size, begin, end uint64) {
		// necessary to restrict size for compile_native_go_fuzzer
		if size >= math.MaxUint16 {
			return
		}
		t.Logf("size=%d, begin=%d, end=%d", size, begin, end)
		if begin > end || end > size {
			return
		}
		tree := newTree(genEntries(size))
		p, err := tree.ConsistencyProof(begin, end)
		t.Logf("proof=%v", p)
		if err != nil {
			t.Error(err)
		}
		err = proof.VerifyConsistency(tree.hasher, begin, end, p, tree.HashAt(begin), tree.HashAt(end))
		if err != nil {
			t.Error(err)
		}
	})
}

// Compute and verify inclusion proofs
func FuzzInclusionProofAndVerify(f *testing.F) {
	for size := 0; size <= 8; size++ {
		for index := 0; index <= size; index++ {
			f.Add(uint64(index), uint64(size))
		}
	}
	f.Fuzz(func(t *testing.T, index, size uint64) {
		if size >= math.MaxUint16 {
			return
		}
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
		if size >= math.MaxUint16 {
			return
		}
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
		if size >= math.MaxUint16 {
			return
		}
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
			t.Errorf("InclusionProof(%d, %d): diff (-got +want)\n%s", index, size, diff)
		}
	})
}

func FuzzConsistencyProofAgainstReferenceImplementation(f *testing.F) {
	for size := 0; size <= 8; size++ {
		for end := 0; end <= size; end++ {
			for begin := 0; begin <= end; begin++ {
				f.Add(uint64(size), uint64(begin), uint64(end))
			}
		}
	}
	f.Fuzz(func(t *testing.T, size, begin, end uint64) {
		if size >= math.MaxUint16 {
			return
		}
		t.Logf("size=%d, begin=%d, end=%d", size, begin, end)
		if begin > end || end > size {
			return
		}
		entries := genEntries(size)
		tree := newTree(entries)
		got, err := tree.ConsistencyProof(begin, end)
		if err != nil {
			t.Errorf("ConsistencyProof: %v", err)
		}
		want := refConsistencyProof(entries[:end], end, begin, tree.hasher, true)
		if diff := cmp.Diff(got, want, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("ConsistencyProof: diff (-got +want)\n%s", diff)
		}
	})
}
