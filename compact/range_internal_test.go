// Copyright 2019 Google LLC. All Rights Reserved.
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

package compact

import (
	"fmt"
	"strings"
	"testing"
)

var (
	hashChildren = func(_, _ []byte) []byte { return []byte("fake-hash") }
	factory      = &RangeFactory{Hash: hashChildren}
)

func TestAppendRangeErrors(t *testing.T) {
	anotherFactory := &RangeFactory{Hash: hashChildren}

	nonEmpty1, _ := factory.NewRange(7, 8, [][]byte{[]byte("hash")})
	nonEmpty2, _ := factory.NewRange(0, 6, [][]byte{[]byte("hash0"), []byte("hash1")})
	nonEmpty3, _ := factory.NewRange(6, 7, [][]byte{[]byte("hash")})
	corrupt := func(rng *Range, dBegin, dEnd int64) *Range {
		rng.begin = uint64(int64(rng.begin) + dBegin)
		rng.end = uint64(int64(rng.end) + dEnd)
		return rng
	}
	for _, tc := range []struct {
		desc    string
		l, r    *Range
		wantErr string
	}{
		{
			desc: "ok",
			l:    factory.NewEmptyRange(0),
			r:    factory.NewEmptyRange(0),
		},
		{
			desc:    "incompatible",
			l:       factory.NewEmptyRange(0),
			r:       anotherFactory.NewEmptyRange(0),
			wantErr: "incompatible ranges",
		},
		{
			desc:    "disjoint",
			l:       factory.NewEmptyRange(0),
			r:       factory.NewEmptyRange(1),
			wantErr: "ranges are disjoint",
		},
		{
			desc:    "left_corrupted",
			l:       corrupt(factory.NewEmptyRange(7), -7, 0),
			r:       nonEmpty1,
			wantErr: "corrupted lhs range",
		},
		{
			desc:    "right_corrupted",
			l:       nonEmpty2,
			r:       corrupt(nonEmpty3, 0, 20),
			wantErr: "corrupted rhs range",
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			err := tc.l.AppendRange(tc.r, nil)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("AppendRange: %v; want nil", err)
				}
			} else if err == nil || !strings.HasPrefix(err.Error(), tc.wantErr) {
				t.Fatalf("AppendRange: %v; want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestEqual(t *testing.T) {
	for _, test := range []struct {
		desc      string
		lhs       *Range
		rhs       *Range
		wantEqual bool
	}{
		{
			desc: "incompatible trees",
			lhs: &Range{
				f:      factory,
				begin:  17,
				end:    23,
				hashes: [][]byte{[]byte("hash 1"), []byte("hash 2")},
			},
			rhs: &Range{
				f:      &RangeFactory{Hash: hashChildren},
				begin:  17,
				end:    23,
				hashes: [][]byte{[]byte("hash 1"), []byte("hash 2")},
			},
		},

		{
			desc: "unequal begin",
			lhs: &Range{
				f:      factory,
				begin:  17,
				end:    23,
				hashes: [][]byte{[]byte("hash 1"), []byte("hash 2")},
			},
			rhs: &Range{
				f:      factory,
				begin:  18,
				end:    23,
				hashes: [][]byte{[]byte("hash 1"), []byte("hash 2")},
			},
		},

		{
			desc: "unequal end",
			lhs: &Range{
				f:      factory,
				begin:  17,
				end:    23,
				hashes: [][]byte{[]byte("hash 1"), []byte("hash 2")},
			},
			rhs: &Range{
				f:      factory,
				begin:  17,
				end:    24,
				hashes: [][]byte{[]byte("hash 1"), []byte("hash 2")},
			},
		},

		{
			desc: "unequal number of hashes",
			lhs: &Range{
				f:      factory,
				begin:  17,
				end:    23,
				hashes: [][]byte{[]byte("hash 1"), []byte("hash 2")},
			},
			rhs: &Range{
				f:      factory,
				begin:  17,
				end:    23,
				hashes: [][]byte{[]byte("hash 1")},
			},
		},

		{
			desc: "mismatched hash",
			lhs: &Range{
				f:      factory,
				begin:  17,
				end:    23,
				hashes: [][]byte{[]byte("hash 1"), []byte("hash 2")},
			},
			rhs: &Range{
				f:      factory,
				begin:  17,
				end:    23,
				hashes: [][]byte{[]byte("hash 1"), []byte("not hash 2")},
			},
		},

		{
			desc: "equal ranges",
			lhs: &Range{
				f:      factory,
				begin:  17,
				end:    23,
				hashes: [][]byte{[]byte("hash 1"), []byte("hash 2")},
			},
			rhs: &Range{
				f:      factory,
				begin:  17,
				end:    23,
				hashes: [][]byte{[]byte("hash 1"), []byte("hash 2")},
			},
			wantEqual: true,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			if got, want := test.lhs.Equal(test.rhs), test.wantEqual; got != want {
				t.Errorf("%+v.Equal(%+v) = %v, want %v", test.lhs, test.rhs, got, want)
			}
		})
	}
}

func TestGetMergePath(t *testing.T) {
	for _, tc := range []struct {
		begin, mid, end uint64
		wantLow         uint
		wantHigh        uint
		wantEmpty       bool
	}{
		{begin: 0, mid: 0, end: 0, wantEmpty: true},
		{begin: 0, mid: 0, end: 1, wantEmpty: true},
		{begin: 0, mid: 0, end: uint64(1) << 63, wantEmpty: true},
		{begin: 0, mid: 1, end: 1, wantEmpty: true},
		{begin: 0, mid: 1, end: 2, wantLow: 0, wantHigh: 1},
		{begin: 0, mid: 16, end: 32, wantLow: 4, wantHigh: 5},
		{begin: 0, mid: uint64(1) << 63, end: ^uint64(0), wantEmpty: true},
		{begin: 0, mid: uint64(1) << 63, end: uint64(1)<<63 + 100500, wantEmpty: true},
		{begin: 2, mid: 9, end: 13, wantLow: 0, wantHigh: 2},
		{begin: 6, mid: 13, end: 17, wantLow: 0, wantHigh: 3},
		{begin: 4, mid: 8, end: 16, wantEmpty: true},
		{begin: 8, mid: 12, end: 16, wantLow: 2, wantHigh: 3},
		{begin: 4, mid: 6, end: 12, wantLow: 1, wantHigh: 2},
		{begin: 8, mid: 10, end: 16, wantLow: 1, wantHigh: 3},
		{begin: 11, mid: 17, end: 27, wantLow: 0, wantHigh: 3},
		{begin: 11, mid: 16, end: 27, wantEmpty: true},
	} {
		t.Run(fmt.Sprintf("%d:%d:%d", tc.begin, tc.mid, tc.end), func(t *testing.T) {
			low, high := getMergePath(tc.begin, tc.mid, tc.end)
			if tc.wantEmpty {
				if low < high {
					t.Fatalf("getMergePath(%d,%d,%d)=%d,%d; want empty", tc.begin, tc.mid, tc.end, low, high)
				}
			} else if low != tc.wantLow || high != tc.wantHigh {
				t.Fatalf("getMergePath(%d,%d,%d)=%d,%d; want %d,%d", tc.begin, tc.mid, tc.end, low, high, tc.wantLow, tc.wantHigh)
			}
		})
	}
}
