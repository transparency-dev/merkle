// Copyright 2025 The Tessera authors. All Rights Reserved.
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
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/witness"
	"golang.org/x/mod/sumdb/note"
)

// NewTLogProof creates a transparency log proof for a given index, inclusion proof
// and signed checkpoint.
// The format of the returned proof is described at https://c2sp.org/tlog-proof
func NewTLogProof(index uint64, hashes [][sha256.Size]byte, checkpoint []byte) []byte {
	return buildTLogProof(index, hashes, checkpoint, nil)
}

// NewTLogProofWithExtra creates a transparency log proof for a given index, inclusion proof
// and signed checkpoint, along with opaque extra data.
// The format of the returned proof is described at https://c2sp.org/tlog-proof
func NewTLogProofWithExtra(index uint64, hashes [][sha256.Size]byte, checkpoint []byte, extraData []byte) []byte {
	return buildTLogProof(index, hashes, checkpoint, extraData)
}

func buildTLogProof(index uint64, hashes [][sha256.Size]byte, checkpoint []byte, extraData []byte) []byte {
	var proof bytes.Buffer
	proof.WriteString("c2sp.org/tlog-proof@v1\n")
	if extraData != nil {
		proof.WriteString("extra ")
		fmt.Fprintf(&proof, "%s\n", base64.StdEncoding.EncodeToString(extraData))
	}
	fmt.Fprintf(&proof, "index %d\n", index)
	for _, h := range hashes {
		fmt.Fprintf(&proof, "%s\n", base64.StdEncoding.EncodeToString(h[:]))
	}
	proof.WriteRune('\n')
	proof.Write(checkpoint)
	return proof.Bytes()
}

// VerifyTLogProof verifies a c2sp.org/tlog-proof formatted proof for a given leaf hash. The proof must contain
// a valid inclusion proof for a given leaf hash and a signed checkpoint for a given origin, verified by
// the given log verifier and optionally a witness policy.
func VerifyTLogProof(proof, leafHash []byte, logOrigin string, logVerifier note.Verifier, witnessPolicy []byte) (uint64, []byte, error) {
	var err error
	b := bufio.NewScanner(bytes.NewReader(proof))

	if b.Scan(); b.Text() != "c2sp.org/tlog-proof@v1" {
		return 0, nil, fmt.Errorf("tlog proof missing expected header")
	}

	// Handle optional extra line
	var extra []byte
	if b.Scan(); strings.HasPrefix(b.Text(), "extra ") {
		e, _ := strings.CutPrefix(b.Text(), "extra ")
		extra, err = base64.StdEncoding.DecodeString(e)
		if err != nil {
			return 0, nil, fmt.Errorf("tlog proof extra data not base64 encoded: %w", err)
		}
		b.Scan()
	}

	var idx uint64
	idxStr, ok := strings.CutPrefix(b.Text(), "index ")
	if !ok {
		return 0, nil, fmt.Errorf("tlog proof missing required index")
	}
	idx, err = strconv.ParseUint(idxStr, 10, 64)
	if err != nil {
		return 0, nil, fmt.Errorf("tlog proof index not a valid uint64: %w", err)
	}

	var hashes [][]byte
	for b.Scan() {
		if b.Text() == "" {
			break
		}
		hash, err := base64.StdEncoding.DecodeString(b.Text())
		if err != nil {
			return 0, nil, fmt.Errorf("tlog proof hash not base64 encoded: %w", err)
		}
		if len(hash) != sha256.Size {
			return 0, nil, fmt.Errorf("tlog proof hash length was %d, expected %d", len(hash), sha256.Size)
		}
		hashes = append(hashes, hash)
	}

	var checkpoint []byte
	for b.Scan() {
		checkpoint = append(checkpoint, b.Bytes()...)
		checkpoint = append(checkpoint, '\n')
	}

	// Verify checkpoint
	verifiedCkpt, _, _, err := log.ParseCheckpoint(checkpoint, logOrigin, logVerifier)
	if err != nil {
		return 0, nil, fmt.Errorf("tlog proof checkpoint could not be verified: %w", err)
	}

	// Verify witness signatures
	if witnessPolicy != nil {
		wg, err := witness.NewWitnessGroupFromPolicy(witnessPolicy)
		if err != nil {
			return 0, nil, fmt.Errorf("invalid witness policy: %w", err)
		}
		if !wg.Satisfied(checkpoint) {
			return 0, nil, fmt.Errorf("tlog proof checkpoint could not be verified by witness policy")
		}
	}

	// Verify inclusion proof
	if err := VerifyInclusion(rfc6962.DefaultHasher, idx, verifiedCkpt.Size, leafHash, hashes, verifiedCkpt.Hash); err != nil {
		return 0, nil, fmt.Errorf("tlog proof inclusion proof not verifiable: %w", err)
	}

	return idx, extra, nil
}
