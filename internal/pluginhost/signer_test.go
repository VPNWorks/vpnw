// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package pluginhost_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VPNWorks/vpnw/internal/pluginhost"
	"github.com/VPNWorks/vpnw/plugins/ledger/chain"
)

// The key file is made once, readable by its owner alone, and read back as
// the same key.
func TestSigningKeyFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "vpnw", "signing.key")
	if _, _, err := pluginhost.LoadSigner(file, false); err == nil {
		t.Fatal("a missing key was taken without create")
	}
	a, made, err := pluginhost.LoadSigner(file, true)
	if err != nil || !made {
		t.Fatalf("%v %v", made, err)
	}
	if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", fi.Mode(), err)
	}
	b, made, err := pluginhost.LoadSigner(file, true)
	if err != nil || made || b.Public != a.Public || !chain.ValidKey(a.Public) {
		t.Fatalf("again: %v %v %s %s", made, err, a.Public, b.Public)
	}
	os.WriteFile(file, []byte("vpnw-ed25519:"+strings.Repeat("A", 43)+"=\n"), 0o600)
	if _, _, err := pluginhost.LoadSigner(file, true); err == nil || !strings.Contains(err.Error(), "not a vpnw signing key") {
		t.Fatalf("a public key as the signing key: %v", err)
	}
}

// What the core signs for Ledger is what the ledger format checks: the two
// packages agree on the signed message, byte for byte.
func TestSignedMessageMatchesLedger(t *testing.T) {
	s := pluginhost.NewSigner()
	h, _ := chain.ParseHash(strings.Repeat("ab", 32))
	st := chain.CheckpointStatement(3, 300, h)
	sig := s.Sign(chain.Signer, "r-3f9a1c", st)
	if !chain.VerifySig(s.Public, "r-3f9a1c", st, sig) || !pluginhost.VerifySigned(s.Public, "ledger", "r-3f9a1c", st, sig) {
		t.Fatal("the core's signature doesn't check out in the ledger format")
	}
	// Signed in another plugin's name, or for another run, it doesn't.
	if chain.VerifySig(s.Public, "r-3f9a1c", st, s.Sign("other", "r-3f9a1c", st)) || chain.VerifySig(s.Public, "r-3f9a1c", st, s.Sign("ledger", "r-000000", st)) {
		t.Fatal("a signature for another plugin or run checks out")
	}
	if chain.SignedDomain != pluginhost.SignedDomain {
		t.Fatal("the domains differ")
	}
}
