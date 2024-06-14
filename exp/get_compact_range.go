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

package merkle

import (
	"fmt"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
)

type HashGetter interface {
	GetConsistencyProof(first, second uint64) ([][]byte, error)
	GetLeafHashes(begin, end uint64) ([][]byte, error)
}

func GetCompactRange(rf *compact.RangeFactory, begin, end, size uint64, hg HashGetter) (*compact.Range, error) {
	if begin > size || end > size {
		return nil, fmt.Errorf("[%d, %d) out of range in %d", begin, end, size)
	}
	if begin >= end {
		return rf.NewEmptyRange(begin), nil
	}

	if size <= 3 || end == 1 {
		hashes, err := hg.GetLeafHashes(begin, end)
		if err != nil {
			return nil, fmt.Errorf("GetLeafHashes(%d, %d): %v", begin, end, err)
		}
		if got, want := uint64(len(hashes)), end-begin; got != want {
			return nil, fmt.Errorf("GetLeafHashes(%d, %d): %d hashes, want %d", begin, end, got, want)
		}
		r := rf.NewEmptyRange(begin)
		for _, h := range hashes {
			if err := r.Append(h, nil); err != nil {
				return nil, fmt.Errorf("Append: %v", err)
			}
		}
		return r, nil
	}
	// size >= 4 && end >= 2

	known := make(map[compact.NodeID][]byte)

	store := func(nodes proof.Nodes, hashes [][]byte) error {
		_, b, e := nodes.Ephem()
		wantSize := len(nodes.IDs) - (e - b)
		if b != e {
			wantSize++
		}
		if got := len(hashes); got != wantSize {
			return fmt.Errorf("proof size mismatch: got %d, want %d", got, wantSize)
		}

		idx := 0
		for _, hash := range hashes {
			if idx == b && b+1 < e {
				idx = e - 1
				continue
			}
			known[nodes.IDs[idx]] = hash
			idx++
		}
		return nil
	}

	newRange := func(begin, end uint64) (*compact.Range, error) {
		size := compact.RangeSize(begin, end)
		ids := compact.RangeNodes(begin, end, make([]compact.NodeID, 0, size))
		hashes := make([][]byte, 0, len(ids))
		for _, id := range ids {
			if hash, ok := known[id]; ok {
				hashes = append(hashes, hash)
			} else {
				return nil, fmt.Errorf("hash not known: %+v", id)
			}
		}
		return rf.NewRange(begin, end, hashes)
	}

	fetch := func(first, second uint64) error {
		nodes, err := proof.Consistency(first, second)
		if err != nil {
			return fmt.Errorf("proof.Consistency: %v", err)
		}
		hashes, err := hg.GetConsistencyProof(first, second)
		if err != nil {
			return fmt.Errorf("GetConsistencyProof(%d, %d): %v", first, second, err)
		}
		store(nodes, hashes)
		return nil
	}

	mid, _ := compact.Decompose(begin, end)
	mid += begin
	if err := fetch(begin, mid); err != nil {
		return nil, err
	}

	if begin == 0 && end == 2 || end == 3 {
		if err := fetch(3, 4); err != nil {
			return nil, err
		}
	}
	if end <= 3 {
		return newRange(begin, end)
	}
	// end >= 4

	if (end-1)&(end-2) != 0 { // end-1 is not a power of 2.
		if err := fetch(end-1, end); err != nil {
			return nil, err
		}
		r, err := newRange(begin, end-1)
		if err != nil {
			return nil, err
		}
		if err := r.Append(known[compact.NewNodeID(0, end-1)], nil); err != nil {
			return nil, fmt.Errorf("Append: %v", err)
		}
		return r, nil
	}

	// At this point: end >= 4, end-1 is a power of 2; thus, end-2 is not a power of 2.
	if err := fetch(end-2, end); err != nil {
		return nil, err
	}
	r := rf.NewEmptyRange(begin)
	if end-2 > begin {
		var err error
		if r, err = newRange(begin, end-2); err != nil {
			return nil, err
		}
	}
	for index := r.End(); index < end; index++ {
		if err := r.Append(known[compact.NewNodeID(0, index)], nil); err != nil {
			return nil, fmt.Errorf("Append: %v", err)
		}
	}
	return r, nil
}
