// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

// Review 0.10.0 round 2: on a machine with a signing key, a key file that
// can't be read (damaged here; unreadable likewise) makes verify warn and
// then check as if there were no key: a ledger written again with a
// forger's key passes with exit 0. It should fail closed (CHANGED, or a
// usage error asking for --key).
func TestReview0100bDamagedMachineKeyFailsOpen(t *testing.T) {
	skipIfNoSeal(t)
	e := newEnv(t)
	led := filepath.Join(e.dir, "first.ledger")
	e.must("run", "--plugin", "ledger", "--plugin-file", "ledger="+led, "--", "true")
	e.must("run", "--", "true") // "last" is another run now
	b, _ := os.ReadFile(led)
	_, forger, _ := ed25519.GenerateKey(crand.Reader)
	forged := rechain(t, b, func(n uint64, ev []byte) []byte {
		if n == 1 {
			return bytes.Replace(ev, []byte(`"ts":"2`), []byte(`"ts":"1`), 1)
		}
		return ev
	}, forger)
	fn := filepath.Join(e.dir, "forged.ledger")
	os.WriteFile(fn, forged, 0o600)
	if got, code := e.run("verify", fn); code != 1 {
		t.Fatalf("control: forged ledger with a good machine key: exit %d\n%s", code, got)
	}
	keyOut := e.must("key")
	_ = keyOut
	// Damage the key file: one byte gone.
	kf := ""
	for _, v := range e.vars {
		if len(v) > 5 && v[:5] == "HOME=" {
			kf = filepath.Join(v[5:], ".config", "vpnw", "signing.key")
		}
		if len(v) > 16 && v[:16] == "XDG_CONFIG_HOME=" {
			kf = filepath.Join(v[16:], "vpnw", "signing.key")
		}
	}
	kb, err := os.ReadFile(kf)
	if err != nil {
		t.Fatalf("key file: %v", err)
	}
	os.WriteFile(kf, kb[:len(kb)-5], 0o600)
	if got, code := e.run("verify", fn); code == 0 {
		t.Errorf("forged ledger, damaged machine key: exit 0\n%s", got)
	}
}
