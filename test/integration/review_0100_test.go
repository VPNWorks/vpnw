// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// Review 0.10.0, promise (a): on the machine that ran it, without --key,
// vpnw verify checks against this machine's key (docs/reference.md: "the
// same" as --key). A ledger of an earlier run (not the "last" trace's),
// written again unsigned, or signed with a forger's own key, must fail.
func TestReview0100MachineDefaultCatchesRewrite(t *testing.T) {
	skipIfNoSeal(t)
	e := newEnv(t)
	led := filepath.Join(e.dir, "first.ledger")
	e.must("run", "--plugin", "ledger", "--plugin-file", "ledger="+led, "--set", "ledger.every=1", "--", "true")
	// Another run, so the saved "last" trace is not this ledger's.
	e.must("run", "--", "true")
	b, _ := os.ReadFile(led)

	var stripped []byte
	for _, l := range bytes.SplitAfter(b, []byte("\n")) {
		if !bytes.HasPrefix(l, []byte(`{"sig":`)) {
			stripped = append(stripped, l...)
		}
	}
	unsigned := regexp.MustCompile(`,"key":"[^"]+"`).ReplaceAll(stripped, nil)
	unsigned = rechain(t, unsigned, func(n uint64, ev []byte) []byte {
		if n == 2 {
			return bytes.Replace(ev, []byte(`"ts":"2`), []byte(`"ts":"1`), 1)
		}
		return ev
	}, nil)
	_, forger, _ := ed25519.GenerateKey(crand.Reader)
	other := rechain(t, b, func(n uint64, ev []byte) []byte {
		if n == 2 {
			return bytes.Replace(ev, []byte(`"ts":"2`), []byte(`"ts":"1`), 1)
		}
		return ev
	}, forger)
	for name, l := range map[string][]byte{"unsigned": unsigned, "other-key": other} {
		fn := filepath.Join(e.dir, name+".ledger")
		os.WriteFile(fn, l, 0o600)
		got, code := e.run("verify", fn)
		if code == 0 {
			t.Errorf("%s rewrite, verify on the machine that ran it without --key: exit 0\n%s", name, got)
		}
	}
}
