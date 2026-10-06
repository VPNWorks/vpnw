// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

func TestKeyFiles(t *testing.T) {
	// The seed of RFC 8032's first test vector; its public key is
	// d75a9801…511a, whose SHA-256 starts 21fe31df (computed with Python).
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	k, err := NewKey(bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	if k.ID != "k-21fe31df" || hex.EncodeToString(k.Public().Key) != "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" {
		t.Fatalf("id %s, public %x", k.ID, k.Public().Key)
	}
	priv, err := ParsePrivateKey(k.Text(), "k.key")
	if err != nil || priv.ID != k.ID || !priv.Key.Equal(k.Key) {
		t.Fatalf("private round trip: %v\n%s", err, k.Text())
	}
	pub, err := ParsePublicKey(k.Public().Text(), "k.pub")
	if err != nil || pub.ID != k.ID || !pub.Key.Equal(k.Public().Key) {
		t.Fatalf("public round trip: %v\n%s", err, k.Public().Text())
	}
	if !strings.Contains(k.Text(), "Keep it secret") || !strings.Contains(pub.Text(), `id = "k-21fe31df"`) {
		t.Errorf("key texts:\n%s\n%s", k.Text(), pub.Text())
	}
	if _, err := NewKey(bytes.NewReader(nil)); err == nil {
		t.Error("a key from no randomness")
	}
}

func TestKeyFileErrors(t *testing.T) {
	k := testKey(t, 1)
	pubText, privText := k.Public().Text(), k.Text()
	other := testKey(t, 2).Public().Text()
	otherKey := other[strings.Index(other, "public = "):]
	cases := []struct {
		src, file, want string
		private         bool
	}{
		{privText, "k.key", "k.pub:4: this is a private key: give the public key", false},
		{pubText, "k.pub", "k.key:4: this is a public key, which can't sign", true},
		{"version = 2\n", "", "k.pub:1: version must be 1", false},
		{"version = \"1\"\n", "", "k.pub:1: version must be 1", false},
		{"id = \"k-00000000\"\n", "", "k.pub:1: missing version = 1", false},
		{"version = 1\nid = \"k-00000000\"\n", "", "missing public =", false},
		{"version = 1\npublic = \"ed25519 AAAA\"\n", "", "missing id =", false},
		{"version = 1\nid = 3\n", "", "k.pub:2: id must be a string", false},
		{"version = 1\ncolor = \"blue\"\n", "", `k.pub:2: unknown key "color"`, false},
		{"version = 1\n[key]\nid = \"x\"\n", "", "k.pub:2: a key file has no tables", false},
		{"version = 1\nid = \"k-00000000\"\npublic = \"rsa AAAA\"\n", "", `k.pub:3: public: want "ed25519"`, false},
		{"version = 1\nid = \"k-00000000\"\npublic = \"ed25519 !!!\"\n", "", "k.pub:3: public: want 44 characters", false},
		{"version = 1\nid = \"k-00000000\"\npublic = \"ed25519 AAAA\"\n", "", "k.pub:3: public: want 44 characters", false},
		{strings.Replace(pubText, `id = "`+k.ID, `id = "k-00000000`, 1), "", "k.pub:3: id k-00000000 doesn't match the key, whose ID is " + k.ID, false},
		{strings.Replace(pubText, pubText[strings.Index(pubText, "public = "):], otherKey, 1), "", "doesn't match the key", false},
		{strings.Replace(privText, `id = "`+k.ID, `id = "k-00000000`, 1), "", "k.key:3: id k-00000000 doesn't match", true},
		{"version = 1\nid = \"unterminated\n", "", "k.pub:2:", false},
	}
	for _, c := range cases {
		var err error
		if c.private {
			_, err = ParsePrivateKey(c.src, "k.key")
		} else {
			_, err = ParsePublicKey(c.src, "k.pub")
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: error %v, want %q", c.src, err, c.want)
		}
	}
	if len(k.Key) != ed25519.PrivateKeySize {
		t.Error("key size")
	}
}
