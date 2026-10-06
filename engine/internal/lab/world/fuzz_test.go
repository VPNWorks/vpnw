// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package world

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzParseResolv(f *testing.F) {
	f.Add("nameserver 192.168.1.1\n")
	f.Add("# generated\nsearch lab.test\noptions ndots:1\nnameserver 10.66.0.1\nnameserver 9.9.9.9\n")
	f.Add("nameserver fe80::1%eth0\n")
	f.Fuzz(func(t *testing.T, text string) {
		a, err := ParseResolv(text, "resolv.conf")
		if err != nil {
			return
		}
		if !a.Is4() {
			t.Fatalf("%q gave %s", text, a)
		}
		p := filepath.Join(t.TempDir(), "resolv.conf")
		if err := WriteResolv(p, a); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(p)
		if again, err := ParseResolv(string(b), p); err != nil || again != a {
			t.Fatalf("%s written and read back as %s, %v", a, again, err)
		}
	})
}
