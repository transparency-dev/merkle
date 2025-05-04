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

package merkle_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/transparency-dev/merkle"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
)

func TestGetCompactRange(t *testing.T) {
	rf := compact.RangeFactory{Hash: func(left, right []byte) []byte {
		return append(append(make([]byte, 0, len(left)+len(right)), left...), right...)
	}}
	tr := newTree(t, 256, &rf)

	test := func(begin, end, size uint64) {
		t.Run(fmt.Sprintf("%d:%d_%d", size, begin, end), func(t *testing.T) {
			got, err := merkle.GetCompactRange(&rf, begin, end, size, tr)
			if err != nil {
				t.Fatalf("GetCompactRange: %v", err)
			}
			want, err := tr.getCompactRange(begin, end)
			if err != nil {
				t.Fatalf("GetCompactRange: %v", err)
			}
			if diff := cmp.Diff(got, want); diff != "" {
				t.Fatalf("Diff: %s", diff)
			}
		})
	}

	for begin := uint64(0); begin <= tr.size; begin++ {
		for end := begin; end <= tr.size; end++ {
			for size := end; size < end+5 && size < tr.size; size++ {
				test(begin, end, size)
			}
			test(begin, end, tr.size)
		}
	}
}

type tree struct {
	rf    *compact.RangeFactory
	size  uint64
	nodes map[compact.NodeID][]byte
}

func newTree(t *testing.T, size uint64, rf *compact.RangeFactory) *tree {
	hash := func(leaf uint64) []byte {
		if leaf >= 256 {
			t.Fatalf("leaf %d not supported in this test", leaf)
		}
		return []byte{byte(leaf)}
	}

	nodes := make(map[compact.NodeID][]byte, size*2-1)
	r := rf.NewEmptyRange(0)
	for i := uint64(0); i < size; i++ {
		nodes[compact.NewNodeID(0, i)] = hash(i)
		if err := r.Append(hash(i), func(id compact.NodeID, hash []byte) {
			nodes[id] = hash
		}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	return &tree{rf: rf, size: size, nodes: nodes}
}

func (t *tree) GetConsistencyProof(first, second uint64) ([][]byte, error) {
	if first > t.size || second > t.size {
		return nil, fmt.Errorf("%d or %d is beyond %d", first, second, t.size)
	}
	nodes, err := proof.Consistency(first, second)
	if err != nil {
		return nil, err
	}
	hashes, err := t.getNodes(nodes.IDs)
	if err != nil {
		return nil, err
	}
	return nodes.Rehash(hashes, t.rf.Hash)
}

func (t *tree) GetLeafHashes(begin, end uint64) ([][]byte, error) {
	if begin >= end {
		return nil, nil
	}
	ids := make([]compact.NodeID, 0, end-begin)
	for i := begin; i < end; i++ {
		ids = append(ids, compact.NewNodeID(0, i))
	}
	return t.getNodes(ids)
}

func (t *tree) getCompactRange(begin, end uint64) (*compact.Range, error) {
	hashes, err := t.getNodes(compact.RangeNodes(begin, end))
	if err != nil {
		return nil, err
	}
	return t.rf.NewRange(begin, end, hashes)
}

func (t *tree) getNodes(ids []compact.NodeID) ([][]byte, error) {
	hashes := make([][]byte, len(ids))
	for i, id := range ids {
		if hash, ok := t.nodes[id]; ok {
			hashes[i] = hash
		} else {
			return nil, fmt.Errorf("node %+v not found", id)
		}
	}
	return hashes, nil
}
