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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/transparency-dev/formats/log"
	"golang.org/x/mod/sumdb/note"
)

func TestNewTLogProof(t *testing.T) {
	tests := []struct {
		name           string
		index          uint64
		hashes         [][sha256.Size]byte
		checkpoint     []byte
		extraData      []byte
		wantExtra      bool
		wantIndexStr   string
		wantCheckpoint string
	}{
		{
			name:           "proof without extra data",
			index:          5,
			hashes:         [][sha256.Size]byte{sha256.Sum256([]byte("hash1")), sha256.Sum256([]byte("hash2"))},
			checkpoint:     []byte("test checkpoint\n"),
			extraData:      nil,
			wantExtra:      false,
			wantIndexStr:   "index 5\n",
			wantCheckpoint: "test checkpoint",
		},
		{
			name:           "proof with extra data",
			index:          10,
			hashes:         [][sha256.Size]byte{sha256.Sum256([]byte("hash1"))},
			checkpoint:     []byte("checkpoint data\n"),
			extraData:      []byte("extra information"),
			wantExtra:      true,
			wantIndexStr:   "index 10\n",
			wantCheckpoint: "checkpoint data",
		},
		{
			name:           "proof with empty hashes",
			index:          0,
			hashes:         [][sha256.Size]byte{},
			checkpoint:     []byte("checkpoint\n"),
			extraData:      nil,
			wantExtra:      false,
			wantIndexStr:   "index 0\n",
			wantCheckpoint: "checkpoint",
		},
		{
			name:  "proof with multiple hashes",
			index: 15,
			hashes: [][sha256.Size]byte{
				sha256.Sum256([]byte("hash1")),
				sha256.Sum256([]byte("hash2")),
				sha256.Sum256([]byte("hash3")),
			},
			checkpoint:     []byte("multi-hash checkpoint\n"),
			extraData:      nil,
			wantExtra:      false,
			wantIndexStr:   "index 15\n",
			wantCheckpoint: "multi-hash checkpoint",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var proof []byte
			if tt.extraData != nil {
				proof = NewTLogProofWithExtra(tt.index, tt.hashes, tt.checkpoint, tt.extraData)
			} else {
				proof = NewTLogProof(tt.index, tt.hashes, tt.checkpoint)
			}

			proofStr := string(proof)

			if !strings.HasPrefix(proofStr, "c2sp.org/tlog-proof@v1\n") {
				t.Error("proof missing expected header")
			}

			if tt.wantExtra && !strings.Contains(proofStr, "extra ") {
				t.Error("proof missing extra data line")
			}

			if !tt.wantExtra && strings.Contains(proofStr, "extra ") {
				t.Error("proof should not contain extra data line")
			}

			if !strings.Contains(proofStr, tt.wantIndexStr) {
				t.Errorf("proof missing correct index string: want %q", tt.wantIndexStr)
			}

			if !strings.Contains(proofStr, tt.wantCheckpoint) {
				t.Errorf("proof missing checkpoint: want %q", tt.wantCheckpoint)
			}

			// Verify all hashes are encoded
			for i, h := range tt.hashes {
				encoded := base64.StdEncoding.EncodeToString(h[:])
				if !strings.Contains(proofStr, encoded) {
					t.Errorf("proof missing hash %d: %s", i, encoded)
				}
			}

			// Verify extra data encoding if present
			if tt.extraData != nil {
				expectedExtra := base64.StdEncoding.EncodeToString(tt.extraData)
				if !strings.Contains(proofStr, expectedExtra) {
					t.Error("proof missing encoded extra data")
				}
			}
		})
	}
}

func TestVerifyTLogProofErrors(t *testing.T) {
	tests := []struct {
		name          string
		proof         []byte
		wantErrSubstr string
	}{
		{
			name:          "missing header",
			proof:         []byte("wrong-header\nindex 0\n\ncheckpoint\n"),
			wantErrSubstr: "missing expected header",
		},
		{
			name:          "invalid extra data encoding",
			proof:         []byte("c2sp.org/tlog-proof@v1\nextra !!notbase64!!\nindex 0\n\ncheckpoint\n"),
			wantErrSubstr: "extra data not base64 encoded",
		},
		{
			name:          "missing index",
			proof:         []byte("c2sp.org/tlog-proof@v1\n\n\ncheckpoint\n"),
			wantErrSubstr: "missing required index",
		},
		{
			name:          "invalid index - not a number",
			proof:         []byte("c2sp.org/tlog-proof@v1\nindex notanumber\n\ncheckpoint\n"),
			wantErrSubstr: "not a valid uint64",
		},
		{
			name:          "invalid index - negative",
			proof:         []byte("c2sp.org/tlog-proof@v1\nindex -5\n\ncheckpoint\n"),
			wantErrSubstr: "not a valid uint64",
		},
		{
			name:          "invalid hash base64",
			proof:         []byte("c2sp.org/tlog-proof@v1\nindex 0\n!!notbase64!!\n\ncheckpoint\n"),
			wantErrSubstr: "hash not base64 encoded",
		},
		{
			name: "hash too long",
			proof: []byte("c2sp.org/tlog-proof@v1\nindex 0\n" +
				base64.StdEncoding.EncodeToString(make([]byte, 64)) + "\n\ncheckpoint\n"),
			wantErrSubstr: "hash length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := VerifyTLogProof(tt.proof, nil, "", nil, nil)

			if err == nil {
				t.Fatal("expected error but got none")
			}

			if !strings.Contains(err.Error(), tt.wantErrSubstr) {
				t.Errorf("error message doesn't contain %q, got: %v", tt.wantErrSubstr, err)
			}
		})
	}
}

func TestVerifyTLogProof(t *testing.T) {
	origin := "test"
	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		t.Fatalf("unexpected error creating key: %v", err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("unexpected error creating signer: %v", err)
	}
	verifier, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatalf("unexpected error creating verifier: %v", err)
	}

	witnessPolicy := []byte("")

	checkpoint := createSignedCheckpoint(t, signer, 10, []byte("roothash"))

	extraData := []byte("test extra data")
	hash := sha256.Sum256([]byte("leaf"))

	proof := NewTLogProofWithExtra(0, [][sha256.Size]byte{}, checkpoint, extraData)

	// This will fail at checkpoint verification stage
	// TODO: Provide valid proof
	_, _, err = VerifyTLogProof(proof, hash[:], origin, verifier, witnessPolicy)
	if err == nil {
		t.Errorf("expected verification to fail, but it passed")
	}
}

// Helper function to create a signed checkpoint
func createSignedCheckpoint(t *testing.T, signer note.Signer, size uint64, hash []byte) []byte {
	t.Helper()

	checkpoint := log.Checkpoint{
		Origin: "test",
		Size:   size,
		Hash:   hash,
	}

	checkpointBytes := checkpoint.Marshal()
	signed, err := note.Sign(&note.Note{Text: string(checkpointBytes)}, signer)
	if err != nil {
		t.Fatalf("failed to sign checkpoint: %v", err)
	}

	return signed
}
