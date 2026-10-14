// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package pluginhost_test

import (
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"

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
		case pluginhost.Observer, pluginhost.Advisor, pluginhost.Guard, pluginhost.Tunnel:
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

// What a tunnel plugin hands over comes from its author. ParseOffer never
// panics, and what it accepts is within the limits.
func FuzzTunnelOffer(f *testing.F) {
	f.Add([]byte(`{"name":"de-1.conf","config":"[Interface]\n","keep":600}`))
	f.Add([]byte(`{"name":"a","config":"x"}`))
	f.Add([]byte(`{"name":"a","config":"x","keep":1e3}`))
	f.Add([]byte(`{"name":"‮","config":"x"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		o, err := pluginhost.ParseOffer(b)
		if err != nil {
			return
		}
		if o.Name == "" || o.Text == "" || len(o.Text) > pluginhost.MaxOffer || o.Keep < 0 || o.Keep > pluginhost.MaxKeep ||
			utf8.RuneCountInString(o.Name) > pluginhost.MaxOfferName || !utf8.ValidString(o.Text) {
			t.Fatalf("accepted %q -> %+v", b, o)
		}
		for _, r := range o.Name {
			if r < 0x20 || r == 0x7f || r >= 0x80 && r <= 0x9f || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069 {
				t.Fatalf("accepted the name %q", o.Name)
			}
		}
	})
}

// The names a plugin reads come from the plugin. Whatever the name, a read
// returns a file directly in the folder, never the one beside it.
func FuzzFolderRead(f *testing.F) {
	base := f.TempDir()
	os.WriteFile(filepath.Join(base, "secret"), []byte("outside"), 0o600)
	dir := filepath.Join(base, "configs")
	os.Mkdir(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "a.conf"), []byte("inside a"), 0o600)
	os.WriteFile(filepath.Join(dir, "b.conf"), []byte("inside b"), 0o600)
	os.Mkdir(filepath.Join(dir, "sub"), 0o700)
	os.WriteFile(filepath.Join(dir, "sub", "c.conf"), []byte("deeper"), 0o600)
	os.Symlink("../secret", filepath.Join(dir, "up"))
	os.Symlink(filepath.Join(base, "secret"), filepath.Join(dir, "abs"))
	os.Symlink("a.conf", filepath.Join(dir, "in"))
	d, err := pluginhost.OpenFolder(dir)
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { d.Close() })
	for _, s := range []string{"a.conf", "../secret", "up", "abs", "in", "sub/c.conf", "sub", ".", "..", "/etc/passwd", "a.conf\x00", "./a.conf"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		b, err := d.Read(name)
		if err != nil {
			return
		}
		if s := string(b); s != "inside a" && s != "inside b" {
			t.Fatalf("%q read %q", name, s)
		}
	})
}
