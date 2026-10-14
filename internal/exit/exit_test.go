// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package exit

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/VPNWorks/vpnw/internal/config"
)

// demo is an exit's file with each kind of client: a fixed address and a
// policy file, a pool and a policy in its table.
func demo(t testing.TB) (string, string) {
	t.Helper()
	dir := t.TempDir()
	pol := "version = 1\nname = \"agent-1 policy\"\n[policy]\ndefault = \"deny\"\ndeny_private = true\nallow = [\"api.partner.test\", \"*.partner.test\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "agent-1.toml"), []byte(pol), 0o644); err != nil {
		t.Fatal(err)
	}
	src := `version = 1
name = "exit-de"
listen = "198.51.100.2:8443"
cert = "exit-de.crt"
key = "/etc/vpnw/exit-de.key"

[clients.agent-1]
token_sha256 = "` + HashHex("token-1") + `"
source = "198.51.100.10"
policy = "agent-1.toml"

[clients.ci]
token_sha256 = "` + HashHex("token-ci") + `"
pool = "eu"
default = "deny"
deny_private = true
allow = ["files.partner.test:8080", "51.15.0.0/24"]

[clients.ci-2]
token_sha256 = "` + HashHex("token-ci-2") + `"
pool = "eu"
deny = ["*.ads.test"]
default = "allow"
deny_private = true

[pools.eu]
addresses = ["198.51.100.20", "198.51.100.21", "198.51.100.22"]
`
	name := filepath.Join(dir, "exit-de.toml")
	if err := os.WriteFile(name, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return name, src
}

func TestConfig(t *testing.T) {
	name, _ := demo(t)
	c, err := LoadConfig(name)
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "exit-de" || c.Listen != "198.51.100.2:8443" || len(c.Clients) != 3 || len(c.Pools) != 1 || len(c.Warnings) != 0 {
		t.Fatalf("%+v", c)
	}
	if c.CertFile() != filepath.Join(filepath.Dir(name), "exit-de.crt") || c.KeyFile() != "/etc/vpnw/exit-de.key" {
		t.Errorf("files: %s %s", c.CertFile(), c.KeyFile())
	}
	a := c.Client("agent-1")
	if a.Source != netip.MustParseAddr("198.51.100.10") || a.PolicyFile != "agent-1.toml" || a.Policy.Name != "agent-1 policy" || len(a.Policy.Allow) != 2 {
		t.Errorf("agent-1: %+v", a)
	}
	ci := c.Client("ci")
	if ci.Pool == nil || ci.Pool.Name != "eu" || ci.PolicyFile != "" || !ci.Policy.DenyPrivate {
		t.Errorf("ci: %+v", ci)
	}
	if c.Client("nobody") != nil {
		t.Error("a client that does not exist")
	}
	if got := len(c.Sources()); got != 4 {
		t.Errorf("sources: %v", c.Sources())
	}
	if d := a.Describe(); d != "agent-1: source 198.51.100.10; policy agent-1.toml (default deny, 2 allow rules, 0 deny rules, deny_private true)" {
		t.Errorf("describe: %s", d)
	}
	if d := ci.Describe(); !strings.HasPrefix(d, "ci: pool eu (3 addresses; it uses 198.51.100.") || !strings.Contains(d, "policy in its table") {
		t.Errorf("describe: %s", d)
	}
	if d := c.Client("ci-2").Describe(); !strings.HasSuffix(d, "(default allow, 0 allow rules, 1 deny rule, deny_private true)") {
		t.Errorf("describe: %s", d)
	}
}

func TestConfigErrors(t *testing.T) {
	name, good := demo(t)
	dir := filepath.Dir(name)
	h := HashHex("x")
	base := "version = 1\nlisten = \"127.0.0.1:8443\"\ncert = \"c\"\nkey = \"k\"\n"
	client := func(body string) string { return base + "[clients.a]\ntoken_sha256 = \"" + h + "\"\n" + body }
	cases := []struct{ src, want string }{
		{"", "missing version = 1"},
		{"version = 2\n", ":1: version must be 1"},
		{"version = 1\nlisten = \"x\"\n", "want an address and port"},
		{"version = 1\nlisten = \"h:99999\"\n", "port must be from 1"},
		{"version = 1\nlisten = \"h:1\"\ncert = \"c\"\n", "missing key"},
		{"version = 1\nlisten = 8443\n", "listen must be a string"},
		{"version = 1\nlisten = \"h:1\"\ncert = \"\"\n", ":3: cert must name a file"},
		{"version = 1\nlisten = \"h:1\"\ncert = \"c\"\nkey = \" \"\n", ":4: key must name a file"},
		{"version = 1\nname = \"bad name\"\n", "use letters, digits"},
		{"version = 1\nport = 1\n", `unknown key "port" at the top level`},
		{base, "no clients"},
		{base + "[client.a]\n", "unknown table [client.a]"},
		{base + "[clients.\"a b\"]\n", `client name "a b"`},
		{base + "[clients.a]\nsource = \"10.0.0.1\"\n", "client a has no token_sha256"},
		{client("token = \"x\"\n"), `unknown key "token" for a client`},
		{base + "[clients.a]\ntoken_sha256 = \"abc\"\n", "64 hexadecimal characters"},
		{base + "[clients.a]\ntoken_sha256 = \"abcd\"\n", "64 hexadecimal characters"},
		{client("default = \"deny\"\n"), "needs a source address"},
		{client("source = \"10.0.0.1\"\npool = \"p\"\ndefault = \"deny\"\n"), "both a source and a pool"},
		{client("source = \"10.0.0.300\"\n"), "is not an IP address"},
		{client("source = \"0.0.0.0\"\ndefault = \"deny\"\n"), "0.0.0.0 can't be a source address"},
		{client("source = \"::\"\ndefault = \"deny\"\n"), ":: can't be a source address"},
		{client("source = \"169.254.1.1\"\ndefault = \"deny\"\n"), "can't be a source address"},
		{client("source = \"255.255.255.255\"\ndefault = \"deny\"\n"), "can't be a source address"},
		{client("pool = \"p\"\ndefault = \"deny\"\n") + "[pools.p]\naddresses = [\"10.0.0.1\", \"0.0.0.0\"]\n", "0.0.0.0 can't be a source address"},
		{client("source = \"10.0.0.1\"\ndefault = \"deny\"\nallow_exit_host = \"yes\"\n"), "allow_exit_host must be true or false"},
		{client("source = \"10.0.0.1\"\n"), "client a has no policy"},
		{client("source = \"10.0.0.1\"\npolicy = \"p.toml\"\ndefault = \"deny\"\n"), "a policy file and policy keys"},
		{client("source = \"10.0.0.1\"\nallow = [\"a b\"]\n"), "f.toml:8: client a: allow entry"},
		{client("source = \"10.0.0.1\"\ndefault = \"maybe\"\n"), "f.toml:8: default must be"},
		{client("source = \"10.0.0.1\"\npolicy = \"missing.toml\"\n"), "client a: " + filepath.Join(dir, "missing.toml")},
		{client("pool = \"nope\"\ndefault = \"deny\"\n"), `:7: pool "nope" is not defined`},
		{client("source = \"10.0.0.1\"\ndefault = \"deny\"\n") + "[clients.b]\ntoken_sha256 = \"" + h + "\"\nsource = \"10.0.0.2\"\ndefault = \"deny\"\n", "same token as a"},
		{client("source = \"10.0.0.1\"\ndefault = \"deny\"\n") + "[clients.b]\ntoken_sha256 = \"" + HashHex("y") + "\"\nsource = \"10.0.0.1\"\ndefault = \"deny\"\n", "f.toml:9: source 10.0.0.1 is already client a's"},
		{client("source = \"10.0.0.1\"\ndefault = \"deny\"\n") + "[pools.p]\naddresses = [\"10.0.0.1\"]\n", "pool p's address 10.0.0.1 is already a's"},
		{client("pool = \"p\"\ndefault = \"deny\"\n") + "[pools.p]\naddresses = []\n", "pool p has no addresses"},
		{client("pool = \"p\"\ndefault = \"deny\"\n") + "[pools.p]\naddresses = [\"10.0.0.1\", \"10.0.0.1\"]\n", "listed twice"},
		{client("pool = \"p\"\ndefault = \"deny\"\n") + "[pools.p]\naddrs = [\"10.0.0.1\"]\n", `unknown key "addrs" for a pool`},
		{client("pool = \"p\"\ndefault = \"deny\"\n") + "[pools.p]\naddresses = \"10.0.0.1\"\n", "must be a list"},
		{client("pool = \"p\"\ndefault = \"deny\"\n") + "[pools.p]\naddresses = [1]\n", "strings only"},
		{client("pool = \"p\"\ndefault = \"deny\"\n") + "[pools.p]\naddresses = [\"fe80::1%eth0\"]\n", "is not an IP address"},
		{"version = 1\nx = {a = 1}\n", "f.toml:2: inline tables"},
	}
	for _, c := range cases {
		_, err := ParseConfig(c.src, filepath.Join(dir, "f.toml"), nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q:\n  got %v\n want %q", c.src, err, c.want)
		}
	}
	// A policy file without [policy], and one with a bad rule.
	os.WriteFile(filepath.Join(dir, "nopol.toml"), []byte("version = 1\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "badpol.toml"), []byte("version = 1\n[policy]\nallow = [\"*\"]\n"), 0o644)
	for file, want := range map[string]string{"nopol.toml": "has no [policy] table", "badpol.toml": "badpol.toml: allow entry"} {
		if _, err := ParseConfig(client("source = \"10.0.0.1\"\npolicy = \""+file+"\"\n"), filepath.Join(dir, "f.toml"), nil); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", file, err)
		}
	}
	// No loader in the browser: a policy file cannot be read.
	noFiles := func(string) (*config.File, error) { return nil, errors.New("policy files cannot be read here") }
	if _, err := ParseConfig(good, "exit-de.toml", noFiles); err == nil || !strings.Contains(err.Error(), "cannot be read here") {
		t.Errorf("no loader: %v", err)
	}
	if _, err := LoadConfig(filepath.Join(dir, "none.toml")); err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Errorf("missing file: %v", err)
	}
	// The name defaults to the file's.
	c, err := ParseConfig(client("source = \"10.0.0.1\"\ndefault = \"allow\"\n"), "/x/exit-nl.toml", nil)
	if err != nil || c.Name != "exit-nl" || len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "default allow without deny_private") {
		t.Errorf("%v %+v", err, c)
	}
	// Allow rules that take in private ranges, and the exit's own machine,
	// are warned about.
	c, err = ParseConfig(client("source = \"10.0.0.1\"\nallow_exit_host = true\nallow = [\"api.partner.test\", \"10.0.0.0/8\", \"0.0.0.0/0:443\", \"51.15.0.9\", \"::1\"]\n"), "/x/exit-nl.toml", nil)
	if err != nil || len(c.Warnings) != 4 || !strings.Contains(c.Warnings[0], "allows 10.0.0.0/8, which takes in private addresses") ||
		!strings.Contains(c.Warnings[1], "allows 0.0.0.0/0:443") || !strings.Contains(c.Warnings[2], "allows ::1") || !strings.Contains(c.Warnings[3], "may reach the exit's own machine (allow_exit_host)") {
		t.Errorf("warnings: %v %q", err, c.Warnings)
	}
	if d := c.Clients[0].Describe(); !strings.Contains(d, "source 10.0.0.1, may reach the exit's own machine;") {
		t.Errorf("describe: %s", d)
	}
}

func TestTokens(t *testing.T) {
	name, _ := demo(t)
	c, _ := LoadConfig(name)
	cls := c.BrokerClients()
	if cl := cls.Login("token-ci"); cl == nil || cl.Name != "ci" || cl.Policy != c.Client("ci").Policy || cl.Source != c.Client("ci").Address().String() {
		t.Errorf("token-ci: %+v", cl)
	}
	if cl := cls.Login("token-1"); cl == nil || cl.Name != "agent-1" || cl.Source != "198.51.100.10" {
		t.Errorf("token-1: %+v", cl)
	}
	for _, bad := range []string{"", "token-c", "token-ci ", "TOKEN-CI", HashHex("token-ci")} {
		if cl := cls.Login(bad); cl != nil {
			t.Errorf("%q let in %s", bad, cl.Name)
		}
	}
	a, err := NewToken()
	b, _ := NewToken()
	if err != nil || len(a) != 43 || a == b {
		t.Errorf("tokens %q %q", a, b)
	}
	if HashHex("abc") != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Error("SHA-256")
	}
}

func TestAddress(t *testing.T) {
	name, _ := demo(t)
	c, _ := LoadConfig(name)
	a, ci, ci2 := c.Client("agent-1"), c.Client("ci"), c.Client("ci-2")
	if a.Address().String() != "198.51.100.10" {
		t.Errorf("agent-1: %v", a.Address())
	}
	s1 := ci.Address()
	for i := 0; i < 20; i++ {
		if ci.Address() != s1 {
			t.Fatal("a pool client changed its address between connections")
		}
	}
	in := func(x netip.Addr) bool {
		for _, p := range ci.Pool.Addrs {
			if p == x {
				return true
			}
		}
		return false
	}
	if !in(s1) || !in(ci2.Address()) {
		t.Errorf("pool addresses: %v %v", s1, ci2.Address())
	}
}

// Every source has to be on the machine: on Linux all of 127.0.0.0/8 is,
// and 192.0.2.0/24 is for documentation only.
func TestCheckSources(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("127.0.0.2 is on the machine on Linux only")
	}
	h := HashHex("x")
	src := func(a string) string {
		return "version = 1\nlisten = \"127.0.0.1:0\"\ncert = \"c\"\nkey = \"k\"\n[clients.a]\ntoken_sha256 = \"" + h + "\"\nsource = \"" + a + "\"\ndefault = \"deny\"\n"
	}
	c, err := ParseConfig(src("127.0.0.2"), "f.toml", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CheckSources(); err != nil {
		t.Errorf("127.0.0.2: %v", err)
	}
	c, _ = ParseConfig(src("192.0.2.99"), "f.toml", nil)
	if err := c.CheckSources(); err == nil || err.Error() != "source address 192.0.2.99 is not on this machine" {
		t.Errorf("192.0.2.99: %v", err)
	}
}

// The exit knows its own machine without a list made at start: by binding
// to an address, or by asking where the system routes it.
func TestLocal(t *testing.T) {
	p := &exitPath{own: map[netip.Addr]bool{}}
	for _, a := range []string{"127.0.0.1", "127.9.9.9", "::1"} {
		if mine, err := p.local(netip.MustParseAddr(a)); !mine || err != nil {
			t.Errorf("%s: %v %v", a, mine, err)
		}
	}
	if mine, err := p.local(netip.MustParseAddr("192.0.2.99")); mine || err != nil {
		t.Errorf("192.0.2.99: %v %v", mine, err)
	}
	if mine, err := p.local(netip.MustParseAddr("2001:db8::99")); mine || err != nil {
		t.Errorf("2001:db8::99: %v %v", mine, err)
	}
	addrs, _ := net.InterfaceAddrs()
	for _, x := range addrs {
		n, ok := x.(*net.IPNet)
		if !ok || n.IP.IsLoopback() || n.IP.IsLinkLocalUnicast() {
			continue
		}
		a, _ := netip.AddrFromSlice(n.IP)
		if mine, err := p.local(a.Unmap()); !mine || err != nil {
			t.Errorf("this machine's %s: %v %v", a, mine, err)
		}
		p.anyBind = true // the route test alone
		if mine, err := p.local(a.Unmap()); !mine || err != nil {
			t.Errorf("this machine's %s, by its route: %v %v", a, mine, err)
		}
		p.anyBind = false
	}
}
