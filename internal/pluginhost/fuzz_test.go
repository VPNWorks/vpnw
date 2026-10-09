// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package pluginhost_test

import (
	"testing"

	"github.com/VPNWorks/vpnw/internal/pluginhost"
)

// A manifest comes from whoever wrote the plugin. Parsing one must never
// panic, and what it accepts must be a name, a type and permissions vpnw
// knows.
func FuzzParseManifest(f *testing.F) {
	f.Add("name = \"trace\"\nversion = \"0.3.0\"\ntype = \"observer\"\nabi = 1\npermissions = [\"console\"]\n")
	f.Add("name = \"g\"\nversion = \"1.0.0-rc.1\"\ntype = \"guard\"\nabi = 1\n")
	f.Add("name = \"x\"\n[t]\n")
	f.Fuzz(func(t *testing.T, src string) {
		m, err := pluginhost.ParseManifest(src)
		if err != nil {
			return
		}
		if m.Name == "" || m.ABI != pluginhost.ABI {
			t.Fatalf("accepted %+v", m)
		}
		switch m.Type {
		case pluginhost.Observer, pluginhost.Advisor, pluginhost.Guard:
		default:
			t.Fatalf("accepted type %q", m.Type)
		}
		for _, p := range m.Permissions {
			if pluginhost.PermissionText(p) == "" {
				t.Fatalf("accepted permission %q", p)
			}
		}
	})
}

// Signatures come from the plugin's author too.
func FuzzVerify(f *testing.F) {
	pub, priv, _ := pluginhost.GenerateKey()
	sig, _ := pluginhost.Sign(priv, []byte("m"), []byte("w"))
	f.Add(sig, "m", "w")
	f.Add("vpnw-ed25519:AAAA\nAAAA\n", "m", "w")
	f.Fuzz(func(t *testing.T, s, man, wasm string) {
		who, err := pluginhost.Verify(s, []byte(man), []byte(wasm), []string{pub})
		if err == nil && who != pub {
			t.Fatalf("verified for %q", who)
		}
		if err == nil && (man != "m" || wasm != "w") && s == sig {
			t.Fatal("a signature verified for other files")
		}
	})
}
