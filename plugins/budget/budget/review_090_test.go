// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Review of 0.9.0: reproductions of defects found by the independent review.

package budget

import (
	"testing"

	"github.com/VPNWorks/vpnw/plugins/sdk"
)

// The same address written two ways is two entries to the "listed twice"
// check, and the second silently replaces the first's budget.
func TestReview090SameAddressTwice(t *testing.T) {
	for _, allow := range []string{"10.0.0.1 up=1KB; ::ffff:10.0.0.1 up=1GB", "[::1] up=1KB; ::1 up=1GB", "::1 up=1KB; 0:0::1 up=1GB"} {
		r, err := Parse(map[string]string{"allow": allow})
		if err != nil {
			continue // refused: fine
		}
		d := r.Decide(&sdk.Request{IP: "10.0.0.1"})
		if allow[0] != '1' {
			d = r.Decide(&sdk.Request{IP: "::1"})
		}
		t.Errorf("%q: accepted; the address gets %+v", allow, d.Budget)
	}
}
