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
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/transparency-dev/merkle/rfc6962"
)

var (
	hasher = rfc6962.DefaultHasher
)

// inclusionProbe is a parameter set for inclusion proof verification.
type inclusionProbe struct {
	LeafIndex uint64   `json:"leafIndex"`
	TreeSize  uint64   `json:"treeSize"`
	Root      []byte   `json:"root"`
	LeafHash  []byte   `json:"leafHash"`
	Proof     [][]byte `json:"proof"`

	Desc      string `json:"desc"`
	WantError bool   `json:"wantErr"`
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

//	func verifierCheck(hasher merkle.LogHasher, proof proofgen.inclusionProof) error {
//		// Verify original inclusion proof.
//		got, err := RootFromInclusionProof(hasher, leafIndex, treeSize, leafHash, proof)
//		if err != nil {
//			return err
//		}
//		if !bytes.Equal(got, root) {
//			return fmt.Errorf("got root:\n%x\nexpected:\n%x", got, root)
//		}
//		if err := VerifyInclusion(hasher, leafIndex, treeSize, leafHash, proof, root); err != nil {
//			return err
//		}
//
//		probes := corruptInclusionProof(leafIndex, treeSize, proof, root, leafHash)
//		var wrong []string
//		for _, p := range probes {
//			if err := VerifyInclusion(hasher, p.leafIndex, p.treeSize, p.leafHash, p.proof, p.root); err == nil {
//				wrong = append(wrong, p.desc)
//			}
//		}
//		if len(wrong) > 0 {
//			return fmt.Errorf("incorrectly verified against: %s", strings.Join(wrong, ", "))
//		}
//		return nil
//	}
//
//	func verifierConsistencyCheck(hasher merkle.LogHasher, size1, size2 uint64, proof [][]byte, root1, root2 []byte) error {
//		// Verify original consistency proof.
//		if err := VerifyConsistency(hasher, size1, size2, proof, root1, root2); err != nil {
//			return err
//		}
//		// For simplicity test only non-trivial proofs that have root1 != root2,
//		// size1 != 0 and size1 != size2.
//		if len(proof) == 0 {
//			return nil
//		}
//
//		probes := corruptConsistencyProof(size1, size2, root1, root2, proof)
//		var wrong []string
//		for _, p := range probes {
//			if err := VerifyConsistency(hasher, p.size1, p.size2, p.proof, p.root1, p.root2); err == nil {
//				wrong = append(wrong, p.desc)
//			}
//		}
//		if len(wrong) > 0 {
//			return fmt.Errorf("incorrectly verified against: %s", strings.Join(wrong, ", "))
//		}
//		return nil
//	}
func TestVerifyInclusionProbes(t *testing.T) {
	var probes []inclusionProbe
	root := "testdata/inclusion"

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Errorf("failed to run test")
	}

	directory := filepath.Join(file, "..", "..", root)

	err := filepath.WalkDir(directory, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if filepath.Ext(d.Name()) != ".json" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var probe inclusionProbe
		if err := json.Unmarshal(data, &probe); err != nil {
			return fmt.Errorf("error parsing inclusion probe json: %s", err)
		}

		probes = append(probes, probe)

		return nil
	})

	if err != nil {
		t.Errorf("failed to read inclusion probes: %s", err)
	}

	var wrong []string
	for _, p := range probes {
		err = VerifyInclusion(hasher, p.LeafIndex, p.TreeSize, p.LeafHash, p.Proof, p.Root)
		if p.WantError && err == nil {
			wrong = append(wrong, fmt.Sprintf("expected error but didn't get one: %s", p.Desc))
			continue
		}

		if !p.WantError && err != nil {
			wrong = append(wrong, fmt.Sprintf("unexpected error: %s, %s", p.Desc, err))
			continue
		}
	}

	if len(wrong) > 0 {
		t.Errorf("errors verifying inclusion probes: \n%d out of %d failures \nError messages: \n%s", len(wrong), len(probes), strings.Join(wrong, "\n"))
	}
}

func TestVerifyConsistencyProbes(t *testing.T) {
	var probes []consistencyProbe
	root := "testdata/consistency"

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Errorf("failed to run test")
	}

	directory := filepath.Join(file, "..", "..", root)

	err := filepath.WalkDir(directory, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if filepath.Ext(d.Name()) != ".json" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var probe consistencyProbe
		if err := json.Unmarshal(data, &probe); err != nil {
			return fmt.Errorf("error parsing consistency probe json: %s", err)
		}

		probes = append(probes, probe)

		return nil
	})

	if err != nil {
		t.Errorf("failed to read consistency probes: %s", err)
	}

	var wrong []string
	for _, p := range probes {
		err = VerifyConsistency(hasher, p.Size1, p.Size2, p.Proof, p.Root1, p.Root2)
		if p.WantError && err == nil {
			wrong = append(wrong, fmt.Sprintf("expected error but didn't get one: %s", p.Desc))
			continue
		}

		if !p.WantError && err != nil {
			wrong = append(wrong, fmt.Sprintf("unexpected error: %s, %s", p.Desc, err))
			continue
		}
	}

	if len(wrong) > 0 {
		t.Errorf("errors verifying consistency probes: \n%d out of %d failures \nError messages: \n%s", len(wrong), len(probes), strings.Join(wrong, "\n"))
	}
}
