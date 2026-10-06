// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"crypto/sha256"
	"strings"
	"testing"
)

// The eight inputs of the RFC 6962 test data (certificate-transparency's
// merkle_tree_test), and the roots of their first n leaves, also computed
// apart from this code with Python's hashlib.
var (
	vecInputs = []string{"", "\x00", "\x10", "\x20\x21", "\x30\x31", "\x40\x41\x42\x43", "\x50\x51\x52\x53\x54\x55\x56\x57",
		"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"}
	vecRoots = []string{
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
		"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
		"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
		"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
		"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
		"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
		"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
		"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
	}
)

func vecLeaves() []Hash {
	var out []Hash
	for _, s := range vecInputs {
		out = append(out, LeafHash([]byte(s)))
	}
	return out
}

func hexes(hs []Hash) string {
	var s []string
	for _, h := range hs {
		s = append(s, h.String())
	}
	return strings.Join(s, " ")
}

func TestRFC6962Roots(t *testing.T) {
	leaves := vecLeaves()
	var tree Tree
	for n := 0; n <= len(leaves); n++ {
		if n > 0 {
			tree.Add(leaves[n-1])
		}
		if got := RootOf(leaves[:n]).String(); got != vecRoots[n] {
			t.Errorf("RootOf %d leaves: %s, want %s", n, got, vecRoots[n])
		}
		if got := tree.Root().String(); got != vecRoots[n] || tree.Size() != n {
			t.Errorf("Tree of %d leaves: %s, want %s", n, got, vecRoots[n])
		}
	}
}

func TestRFC6962Paths(t *testing.T) {
	leaves := vecLeaves()
	for _, c := range []struct {
		m, n int
		want string
	}{
		{0, 8, "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7 5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e 6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"},
		{5, 7, "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"},
		{0, 1, ""},
	} {
		if got := hexes(AuditPath(leaves[:c.n], c.m)); got != c.want {
			t.Errorf("path of %d in %d:\n got %s\nwant %s", c.m, c.n, got, c.want)
		}
	}
}

// Every leaf of every tree up to 70 leaves climbs to the root, and nowhere
// else: not from another place, not with another leaf, not with a path one
// hash too long or too short.
func TestPathsClimbToRoot(t *testing.T) {
	var leaves []Hash
	for i := 0; i < 70; i++ {
		leaves = append(leaves, LeafHash([]byte{byte(i), byte(i >> 8)}))
	}
	for n := 1; n <= len(leaves); n++ {
		root := RootOf(leaves[:n])
		for m := 0; m < n; m++ {
			path := AuditPath(leaves[:n], m)
			if got, err := RootFromPath(leaves[m], m, n, path); err != nil || got != root {
				t.Fatalf("leaf %d of %d: %v", m, n, err)
			}
			if n > 1 {
				other := (m + 1) % n
				if got, err := RootFromPath(leaves[m], other, n, path); err == nil && got == root {
					t.Fatalf("leaf %d of %d also proves place %d", m, n, other)
				}
				if got, _ := RootFromPath(leaves[other], m, n, path); got == root {
					t.Fatalf("leaf %d of %d proved with leaf %d", m, n, other)
				}
				if _, err := RootFromPath(leaves[m], m, n, path[:len(path)-1]); err == nil {
					t.Fatalf("leaf %d of %d: a short path passed", m, n)
				}
			}
			if _, err := RootFromPath(leaves[m], m, n, append(path, root)); err == nil {
				t.Fatalf("leaf %d of %d: a long path passed", m, n)
			}
		}
		if _, err := RootFromPath(leaves[0], n, n, nil); err == nil {
			t.Fatalf("a place outside a tree of %d passed", n)
		}
	}
	if _, err := RootFromPath(leaves[0], -1, 3, nil); err == nil {
		t.Fatal("place -1 passed")
	}
}

func TestChain(t *testing.T) {
	leaves := vecLeaves()
	var tree Tree
	for _, h := range leaves[:3] {
		tree.Add(h)
	}
	if got := tree.Chain().String(); got != "7e59456d940731d109135bf29ed67a6ad42bb199a75579cdeccdb64e036cb00a" {
		t.Errorf("chain of 3: %s", got)
	}
	var swapped Tree
	for _, h := range []Hash{leaves[1], leaves[0], leaves[2]} {
		swapped.Add(h)
	}
	if swapped.Chain() == tree.Chain() {
		t.Error("the chain doesn't depend on the order")
	}
	// The prefixes keep a leaf, a node and a link apart.
	a, b := leaves[0], leaves[1]
	if NodeHash(a, b) == ChainHash(a, b) || NodeHash(a, b) == NodeHash(b, a) {
		t.Error("node and chain hashes collide")
	}
	if LeafHash([]byte("x")) == sha256.Sum256([]byte("x")) {
		t.Error("a leaf hash without its prefix")
	}
}

func TestParseHash(t *testing.T) {
	h := LeafHash([]byte("a"))
	if g, err := ParseHash(h.String()); err != nil || g != h {
		t.Fatalf("%v %s", err, g)
	}
	for _, s := range []string{"", "00", strings.ToUpper(h.String()), h.String()[:63] + "g", h.String() + "0"} {
		if _, err := ParseHash(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}
