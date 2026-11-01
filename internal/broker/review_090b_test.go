// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Second review round of 0.9.0.

package broker

import (
	"net"
	"strings"
	"testing"

	"github.com/VPNWorks/vpnw/internal/config"
)

// With deny_private, the Guards are now asked before the lookup, so a
// connection the policy then refuses (the name points at a private
// address) has already been decided by the Guard: Budget counts it against
// requests= and vpnw makes a byte budget for it. The docs say Guards decide
// only connections the policy allows.
func TestReview090bGuardAskedAboutPolicyRefusal(t *testing.T) {
	g := &stubGuard{name: "budget", meter: budget("k", 1000, 0)}
	r := newRig(t, pol(t, config.PolicySpec{Default: "allow", DenyPrivate: true, DenyPrivateSet: true}), g)
	r.dns.m["private.test"] = []net.IP{net.ParseIP("10.0.0.5")}
	_, status := connect(t, r.addr, "private.test:443", "")
	if !strings.HasPrefix(status, "HTTP/1.1 403") {
		t.Fatalf("status %q", status)
	}
	if d := lastDeny(r); d == nil || d.Str("rule") == "plugin:budget" {
		t.Fatalf("deny %+v", d)
	}
	r.b.mu.Lock()
	meters := len(r.b.meters)
	r.b.mu.Unlock()
	// At the lookup stage the Guard may be asked, to refuse only; it must not
	// decide (or budget) a connection the policy refused.
	decided := 0
	for _, q := range g.asked {
		if q.Stage == "" {
			decided++
		}
	}
	if decided != 0 || meters != 0 {
		t.Errorf("the policy refused private.test (deny_private), but the Guard decided it %d times and %d byte budgets were made for it", decided, meters)
	}
}
