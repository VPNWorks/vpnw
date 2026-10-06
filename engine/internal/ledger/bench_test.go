// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"io"
	"sync"
	"testing"
)

var (
	millionOnce sync.Once
	million     Tree
)

// BenchmarkCheckpoint is one checkpoint at a million records: the root from
// the tree's complete subtrees, the signed text, the Ed25519 signature and
// the JSON line, written nowhere. The tree is built once.
func BenchmarkCheckpoint(b *testing.B) {
	millionOnce.Do(func() {
		leaf := LeafHash([]byte("{}"))
		for i := 0; i < 1_000_000; i++ {
			million.Add(leaf)
		}
	})
	s := newSealer(io.Discard, testKey(b, 1), "bench.jsonl", Options{})
	s.tree = million
	s.tree.full = append([]Hash(nil), million.full...)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.pending = 1
		if err := s.Checkpoint(); err != nil {
			b.Fatal(err)
		}
	}
}
