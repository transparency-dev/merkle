// Copyright 2025 Google LLC. All Rights Reserved.
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

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/transparency-dev/merkle/rfc6962"
)

type inclusionProofTestVector struct {
	leafIdx uint64
	size    uint64
	proof   [][]byte
}

type consistencyTestVector struct {
	size1 uint64
	size2 uint64
	proof [][]byte
}

var (
	sha256SomeHash      = dh("abacaba000000000000000000000000000000000000000000060061e00123456", 32)
	sha256EmptyTreeHash = dh("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 32)

	inclusionProofs = []inclusionProofTestVector{
		{1, 1, nil},
		{1, 8, [][]byte{
			dh("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7", 32),
			dh("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", 32),
			dh("6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4", 32),
		}},
		{6, 8, [][]byte{
			dh("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b", 32),
			dh("ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0", 32),
			dh("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7", 32),
		}},
		{3, 3, [][]byte{
			dh("fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125", 32),
		}},
		{2, 5, [][]byte{
			dh("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", 32),
			dh("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", 32),
			dh("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b", 32),
		}},
	}

	consistencyProofs = []consistencyTestVector{
		{1, 1, nil},
		{1, 8, [][]byte{
			dh("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7", 32),
			dh("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", 32),
			dh("6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4", 32),
		}},
		{6, 8, [][]byte{
			dh("0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a", 32),
			dh("ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0", 32),
			dh("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7", 32),
		}},
		{2, 5, [][]byte{
			dh("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", 32),
			dh("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b", 32),
		}},
		{6, 7, [][]byte{
			dh("0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a", 32),
			dh("b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f", 32),
			dh("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7", 32),
		}},
	}

	roots = [][]byte{
		dh("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", 32),
		dh("fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125", 32),
		dh("aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77", 32),
		dh("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7", 32),
		dh("4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4", 32),
		dh("76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef", 32),
		dh("ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c", 32),
		dh("5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328", 32),
	}

	leaves = [][]byte{
		dh("", 0),
		dh("00", 1),
		dh("10", 1),
		dh("", 0),
		dh("", 0),
		dh("40414243", 4),
	}
)

// inclusionProbe is a parameter set for inclusion proof verification.
type inclusionProbe struct {
	LeafIdx  uint64   `json:"leafIdx"`
	TreeSize uint64   `json:"treeSize"`
	Root     []byte   `json:"root"`
	LeafHash []byte   `json:"leafHash"`
	Proof    [][]byte `json:"proof"`

	Desc      string `json:"desc"`
	WantError bool   `json:"wantErr"`
}

func inclusionProbes(rootDir string) error {
	for i, p := range inclusionProofs {
		dir := filepath.Join(rootDir, strconv.Itoa(i))
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}

		leafHash := rfc6962.DefaultHasher.HashLeaf(leaves[p.leafIdx-1])
		if err := corruptedInclusionProbes(dir, p.leafIdx-1, p.size, p.proof, roots[p.size-1], leafHash); err != nil {
			return err
		}
	}

	staticDir := filepath.Join(rootDir, "additional")
	if err := os.MkdirAll(staticDir, 0755); err != nil {
		return err
	}

	if err := staticInclusionProbes(staticDir); err != nil {
		return err
	}

	singleEntryDir := filepath.Join(rootDir, "single-entry")
	if err := os.MkdirAll(singleEntryDir, 0755); err != nil {
		return err
	}

	if err := singleEntryInclusionProbes(singleEntryDir); err != nil {
		return err
	}

	return nil
}

func invalidInclusionProof(leafIdx, treeSize uint64, proof [][]byte, root, leafHash []byte) []inclusionProbe {
	ret := []inclusionProbe{
		// Wrong leaf index.
		{leafIdx - 1, treeSize, root, leafHash, proof, "leafIdx sub @1", true},
		{leafIdx + 1, treeSize, root, leafHash, proof, "leafIdx plus @1", true},
		{leafIdx ^ 2, treeSize, root, leafHash, proof, "leafIdx XOR @2", true},
		// Wrong tree height.
		{leafIdx, treeSize * 2, root, leafHash, proof, "treeSize mul @2", true},
		{leafIdx, treeSize / 2, root, leafHash, proof, "treeSize div @2", true},
		// Wrong leaf or root.
		{leafIdx, treeSize, root, []byte("WrongLeaf"), proof, "wrong leaf", true},
		{leafIdx, treeSize, sha256EmptyTreeHash, leafHash, proof, "empty root", true},
		{leafIdx, treeSize, sha256SomeHash, leafHash, proof, "random root", true},
		// Add garbage at the end.
		{leafIdx, treeSize, root, leafHash, extend(proof, []byte{}), "trailing garbage", true},
		{leafIdx, treeSize, root, leafHash, extend(proof, root), "trailing root", true},
		// Add garbage at the front.
		{leafIdx, treeSize, root, leafHash, prepend(proof, []byte{}), "preceding garbage", true},
		{leafIdx, treeSize, root, leafHash, prepend(proof, root), "preceding root", true},
	}
	ln := len(proof)

	// Modify single bit in an element of the proof.
	for i := 0; i < ln; i++ {
		wrongProof := prepend(proof)                          // Copy the proof slice.
		wrongProof[i] = append([]byte(nil), wrongProof[i]...) // But also the modified data.
		wrongProof[i][0] ^= 8                                 // Flip the bit.
		desc := fmt.Sprintf("modified proof[%d] bit @3", i)
		ret = append(ret, inclusionProbe{leafIdx, treeSize, root, leafHash, wrongProof, desc, true})
	}

	if ln > 0 {
		ret = append(ret, inclusionProbe{leafIdx, treeSize, root, leafHash, proof[:ln-1], "removed component", true})
	}
	if ln > 1 {
		wrongProof := prepend(proof[1:], proof[0], sha256SomeHash)
		ret = append(ret, inclusionProbe{leafIdx, treeSize, root, leafHash, wrongProof, "inserted component", true})
	}

	return ret
}

func corruptedInclusionProbes(dir string, leafIdx, treeSize uint64, proof [][]byte, root, leafHash []byte) error {
	happyPath := inclusionProbe{leafIdx, treeSize, root, leafHash, proof, "happy path", false}
	if err := writeInclusionProbe(dir, happyPath); err != nil {
		return nil
	}

	probes := invalidInclusionProof(leafIdx, treeSize, proof, root, leafHash)
	for _, p := range probes {
		if err := writeInclusionProbe(dir, p); err != nil {
			return err
		}
	}

	return nil
}

func singleEntryInclusionProbes(dir string) error {
	data := []byte("data")
	// Root and leaf hash for 1-entry tree are the same.
	hash := rfc6962.DefaultHasher.HashLeaf(data)
	// The corresponding inclusion proof is empty.
	proof := [][]byte{}
	emptyHash := []byte{}

	for _, p := range []struct {
		root    []byte
		leaf    []byte
		desc    string
		wantErr bool
	}{
		{hash, hash, "matching root and leaf", false},
		{hash, emptyHash, "empty leaf", true},
		{emptyHash, hash, "empty root", true},
		{emptyHash, emptyHash, "empty root and leaf", true}, // Wrong hash size.
	} {
		probe := inclusionProbe{0, 1, p.root, p.leaf, proof, p.desc, p.wantErr}

		if err := writeInclusionProbe(dir, probe); err != nil {
			return err
		}
	}

	return nil
}

func staticInclusionProbes(rootDir string) error {
	proof := [][]byte{}

	probes := []struct {
		index, size uint64
	}{{0, 0}, {0, 1}, {1, 0}, {2, 1}}
	for i, p := range probes {
		dir := filepath.Join(rootDir, strconv.Itoa(i))
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			return err
		}

		randomLeaf := inclusionProbe{p.index, p.size, []byte{}, sha256SomeHash, proof, "random leaf", true}
		if err := writeInclusionProbe(dir, randomLeaf); err != nil {
			return err
		}

		emptyRoot := inclusionProbe{p.index, p.size, sha256EmptyTreeHash, []byte{}, proof, "empty root", true}
		if err := writeInclusionProbe(dir, emptyRoot); err != nil {
			return err
		}

		emptyRootRandomLeaf := inclusionProbe{p.index, p.size, sha256EmptyTreeHash, sha256SomeHash, proof, "empty root and random leaf", true}
		if err := writeInclusionProbe(dir, emptyRootRandomLeaf); err != nil {
			return err
		}
	}

	return nil
}

func writeInclusionProbe(dir string, probe inclusionProbe) error {
	fileName := strings.Replace(probe.Desc, " ", "-", -1) + ".json"

	probeJson, err := json.MarshalIndent(probe, "", "  ")
	if err != nil {
		return fmt.Errorf("Error marshaling probe: %s", err)
	}

	fileLocation := filepath.Join(dir, fileName)
	if err := os.WriteFile(fileLocation, probeJson, 0644); err != nil {
		return fmt.Errorf("Error writing probe: %s: %s", fileName, err)
	}

	return nil
}

// consistencyProbe is a parameter set for consistency proof verification.
type consistencyProbe struct {
	Size1 uint64   `json:"size1"`
	Size2 uint64   `json:"size2"`
	Root1 []byte   `json:"root1"`
	Root2 []byte   `json:"root2"`
	Proof [][]byte `json:"proof"`

	Desc      string `json:"desc"`
	WantError bool   `json:"wantErr"`
}

func consistencyProbes(rootDir string) error {
	for i, p := range consistencyProofs {
		dir := filepath.Join(rootDir, strconv.Itoa(i))
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}

		if err := corruptedConsistencyProbes(dir, p.size1, p.size2, p.proof,
			roots[p.size1-1], roots[p.size2-1]); err != nil {
			fmt.Errorf("Failed to write consistency test data: %s", err)
		}
	}

	staticDir := filepath.Join(rootDir, "additional")
	if err := os.MkdirAll(staticDir, 0755); err != nil {
		return err
	}

	if err := staticConsistencyProbes(staticDir); err != nil {
		return err
	}

	return nil
}

func invalidConsistencyProof(size1, size2 uint64, root1, root2 []byte, proof [][]byte) []consistencyProbe {
	ln := len(proof)
	ret := []consistencyProbe{
		// Wrong size1.
		{size1 - 1, size2, root1, root2, proof, "size1 sub @1", true},
		{size1 + 1, size2, root1, root2, proof, "size1 plus @1", true},
		{size1 ^ 2, size2, root1, root2, proof, "size1 XOR @2", true},
		// Wrong tree height.
		{size1, size2 * 2, root1, root2, proof, "size2 mul @2", true},
		{size1, size2 / 2, root1, root2, proof, "size2 div @2", true},
		// Wrong root.
		{size1, size2, []byte("WrongRoot"), root2, proof, "wrong root1", true},
		{size1, size2, root1, []byte("WrongRoot"), proof, "wrong root2", true},
		{size1, size2, root2, root1, proof, "swapped roots", true},
		// Empty proof.
		{size1, size2, root1, root2, [][]byte{}, "empty proof", true},
		// Add garbage at the end.
		{size1, size2, root1, root2, extend(proof, []byte{}), "trailing garbage", true},
		{size1, size2, root1, root2, extend(proof, root1), "trailing root1", true},
		{size1, size2, root1, root2, extend(proof, root2), "trailing root2", true},
		// Add garbage at the front.
		{size1, size2, root1, root2, prepend(proof, []byte{}), "preceding garbage", true},
		{size1, size2, root1, root2, prepend(proof, root1), "preceding root1", true},
		{size1, size2, root1, root2, prepend(proof, root2), "preceding root2", true},
		{size1, size2, root1, root2, prepend(proof, proof[0]), "preceding proof @0", true},
	}

	// Remove a node from the end.
	if ln > 0 {
		ret = append(ret, consistencyProbe{size1, size2, root1, root2, proof[:ln-1], "truncated proof", true})
	}

	// Modify single bit in an element of the proof.
	for i := 0; i < ln; i++ {
		wrongProof := prepend(proof)                          // Copy the proof slice.
		wrongProof[i] = append([]byte(nil), wrongProof[i]...) // But also the modified data.
		wrongProof[i][0] ^= 16                                // Flip the bit.
		desc := fmt.Sprintf("modified proof@%d bit @4", i)
		ret = append(ret, consistencyProbe{size1, size2, root1, root2, wrongProof, desc, true})
	}

	return ret
}

func corruptedConsistencyProbes(dir string, size1, size2 uint64, proof [][]byte, root1, root2 []byte) error {
	happyPath := consistencyProbe{size1, size2, root1, root2, proof, "happy path", false}
	if err := writeConsistencyProbe(dir, happyPath); err != nil {
		return err
	}

	// For simplicity test only non-trivial proofs that have root1 != root2,
	// size1 != 0 and size1 != size2.
	if len(proof) == 0 {
		return nil
	}

	probes := invalidConsistencyProof(size1, size2, root1, root2, proof)
	for _, p := range probes {
		writeConsistencyProbe(dir, p)
	}

	return nil
}

func staticConsistencyProbes(dir string) error {
	root1 := []byte("don't care 1")
	root2 := []byte("don't care 2")
	proof1 := [][]byte{}
	proof2 := [][]byte{sha256EmptyTreeHash}

	tests := []consistencyProbe{
		{0, 0, root1, root2, proof1, "sizes are equal (zero) but roots are not", true},
		{1, 1, root1, root2, proof1, "sizes are equal (one) but roots are not", true},
		// Sizes that are always consistent.
		{0, 0, root1, root1, proof1, "sizes are equal and proof is not empty where both sizes are zero", false},
		{0, 1, root1, root2, proof1, "size1 is zero and does not equal size2", true},
		{1, 1, root2, root2, proof1, "sizes are equal and proof is not empty where both sizes are one", false},
		// Time travel to the past.
		{1, 0, root1, root2, proof1, "size1 is greater than size2", true},
		{2, 1, root1, root2, proof1, "size1 is greater than size2 again", true},
		// Empty proof.
		{1, 2, root1, root2, proof1, "sizes do not watch and proof is empty", true},
		// Roots don't match.
		{0, 0, sha256EmptyTreeHash, root2, proof1, "roots do not match and sizes are zero", true},
		{1, 1, sha256EmptyTreeHash, root2, proof1, "roots do not not match and sizes are one", true},
		// Sizes match but the proof is not empty.
		{0, 0, sha256EmptyTreeHash, sha256EmptyTreeHash, proof2, "sizes match but proof is not empty and sizes are zero", true},
		{1, 1, sha256EmptyTreeHash, sha256EmptyTreeHash, proof2, "sizes match but proof is not empty and sizes are one", true},
		// Fail to validate empty tree
		{0, 1, sha256EmptyTreeHash, sha256EmptyTreeHash, proof2, "consistency check on empty tree (size1 is zero) is useless", true},
	}

	for _, p := range tests {
		if err := writeConsistencyProbe(dir, p); err != nil {
			return err
		}
	}

	return nil
}

func writeConsistencyProbe(dir string, probe consistencyProbe) error {
	fileName := strings.Replace(probe.Desc, " ", "-", -1) + ".json"

	probeJson, err := json.MarshalIndent(probe, "", "  ")
	if err != nil {
		return fmt.Errorf("Error marshaling probe: %s", err)
	}

	fileLocation := filepath.Join(dir, fileName)
	if err := os.WriteFile(fileLocation, probeJson, 0644); err != nil {
		return fmt.Errorf("Error writing probe: %s: %s", fileName, err)
	}

	return nil
}

// extend explicitly copies |proof| slice and appends |hashes| to it.
func extend(proof [][]byte, hashes ...[]byte) [][]byte {
	return append(append([][]byte{}, proof...), hashes...)
}

// prepend adds |proof| to the tail of |hashes|.
func prepend(proof [][]byte, hashes ...[]byte) [][]byte {
	return append(hashes, proof...)
}

func dh(h string, expLen int) []byte {
	r, err := hex.DecodeString(h)
	if err != nil {
		log.Fatalf("Error decoding input: %s", err)
	}
	if got := len(r); got != expLen {
		log.Fatalf(fmt.Sprintf("decode %q: len=%d, want %d", h, got, expLen))
	}
	return r
}

func main() {
	inclusionDir := "testdata/inclusion"
	if err := inclusionProbes(inclusionDir); err != nil {
		log.Fatalf("Error writing inclusion test data: %s", err)
	}

	consistencyDir := "testdata/consistency"
	if err := consistencyProbes(consistencyDir); err != nil {
		log.Fatalf("Error writing consistency test data: %s", err)
	}
}
