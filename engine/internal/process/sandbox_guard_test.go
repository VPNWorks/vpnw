// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package process

import "testing"

func TestInterfacesOK(t *testing.T) {
	ok := [][]string{{"lo"}}
	bad := [][]string{{}, {"eth0"}, {"lo", "eth0"}, {"lo", "lo"}, {"LO"}, nil, {"lo0"}}
	for _, in := range ok {
		if !InterfacesOK(in) {
			t.Errorf("%v should be OK", in)
		}
	}
	for _, in := range bad {
		if InterfacesOK(in) {
			t.Errorf("%v should be refused (only loopback may be present)", in)
		}
	}
}
