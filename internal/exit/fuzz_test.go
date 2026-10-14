// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package exit

import (
	"net/netip"
	"testing"

	"github.com/VPNWorks/vpnw/internal/config"
)

// FuzzExitConfig reads arbitrary exit files. Whatever the input, the reader
// must not crash, and a file it accepts must hold what serve relies on:
// every client has a token hash, a policy and an address of its own, and
// no fixed address belongs to two clients or to a client and a pool.
func FuzzExitConfig(f *testing.F) {
	h := HashHex("t")
	for _, s := range []string{
		"version = 1\nlisten = \"127.0.0.1:8443\"\ncert = \"c\"\nkey = \"k\"\n[clients.a]\ntoken_sha256 = \"" + h + "\"\nsource = \"198.51.100.10\"\npolicy = \"p.toml\"\n",
		"version = 1\nname = \"x\"\nlisten = \"[::]:0\"\ncert = \"c\"\nkey = \"k\"\n[clients.ci]\ntoken_sha256 = \"" + h + "\"\npool = \"eu\"\ndefault = \"deny\"\ndeny_private = true\nallow = [\"a.test\", \"10.0.0.0/8:22\"]\n[pools.eu]\naddresses = [\"198.51.100.20\", \"2001:db8::1\"]\n",
		"version = 1\nlisten = \"h:1\"\ncert = \"c\"\nkey = \"k\"\n[clients.a]\ntoken_sha256 = \"" + h + "\"\nsource = \"10.0.0.1\"\ndefault = \"allow\"\n[clients.b]\ntoken_sha256 = \"" + HashHex("u") + "\"\nsource = \"10.0.0.1\"\ndefault = \"deny\"\n",
		"version = 1\nlisten = \"h:1\"\ncert = \"c\"\nkey = \"k\"\n[clients.a]\ntoken_sha256 = \"" + h + "\"\nsource = \"0.0.0.0\"\nallow_exit_host = true\ndefault = \"allow\"\n",
	} {
		f.Add(s)
	}
	pol, err := config.ParseFile("p.toml", "version = 1\n[policy]\ndefault = \"deny\"\nallow = [\"api.partner.test\"]\n")
	if err != nil {
		f.Fatal(err)
	}
	load := func(string) (*config.File, error) { return pol, nil }
	f.Fuzz(func(t *testing.T, src string) {
		c, err := ParseConfig(src, "f.toml", load)
		if err != nil {
			return
		}
		if len(c.Clients) == 0 || c.Listen == "" || c.Cert == "" || c.Key == "" {
			t.Fatalf("accepted an exit with nothing to serve: %+v", c)
		}
		owner := map[netip.Addr]string{}
		hashes := map[[32]byte]bool{}
		for _, cl := range c.Clients {
			if a := cl.Address(); a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() {
				t.Fatalf("client %s leaves from %s, which isn't one address of a machine", cl.Name, a)
			}
			if cl.Policy == nil || !cl.Address().IsValid() || hashes[cl.Hash] {
				t.Fatalf("client %s: policy %v, address %v, token used twice %v", cl.Name, cl.Policy, cl.Address(), hashes[cl.Hash])
			}
			hashes[cl.Hash] = true
			if cl.Pool == nil {
				if o, dup := owner[cl.Source]; dup {
					t.Fatalf("%s is %s's and %s's", cl.Source, o, cl.Name)
				}
				owner[cl.Source] = cl.Name
			}
		}
		for _, p := range c.Pools {
			for _, a := range p.Addrs {
				if o, dup := owner[a]; dup {
					t.Fatalf("pool %s's %s is also %s's", p.Name, a, o)
				}
			}
		}
	})
}
