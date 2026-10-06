// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package exit

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vpnw.com/vpnw/internal/config"
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
}

func TestTokens(t *testing.T) {
	name, _ := demo(t)
	c, _ := LoadConfig(name)
	if cl := c.Lookup("token-ci"); cl == nil || cl.Name != "ci" {
		t.Errorf("token-ci: %v", cl)
	}
	for _, bad := range []string{"", "token-c", "token-ci ", "TOKEN-CI", HashHex("token-ci")} {
		if cl := c.Lookup(bad); cl != nil {
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

func TestIDs(t *testing.T) {
	good := []struct {
		user string
		ids  IDs
	}{
		{"vpnw", IDs{}},
		{"", IDs{}},
		{"r-3f9a1c/17", IDs{Run: "r-3f9a1c", Conn: 17}},
		{"r-3f9a1c/17/198.51.100.21", IDs{Run: "r-3f9a1c", Conn: 17, Source: "198.51.100.21"}},
		{"ci_job.42/18446744073709551615", IDs{Run: "ci_job.42", Conn: 18446744073709551615}},
	}
	for _, g := range good {
		ids, err := ParseSOCKSUser(g.user)
		if err != nil || ids != g.ids {
			t.Errorf("%q: %+v %v", g.user, ids, err)
		}
		if g.ids.Run != "" && ids.SOCKSUser() != g.user {
			t.Errorf("round trip %q: %q", g.user, ids.SOCKSUser())
		}
	}
	for user, want := range map[string]string{
		"r/0":                          "from 1 up",
		"r/01":                         "from 1 up",
		"r/-1":                         "from 1 up",
		"r/1x":                         "from 1 up",
		"r/18446744073709551616":       "too large",
		"/1":                           "go together",
		"r r/1":                        "not \" \"",
		"r/1/":                         "empty",
		"r/1/x/y":                      "RUN/CONN",
		"r/1/10.0.0.300":               "not an IP address",
		strings.Repeat("r", 65) + "/1": "1 to 64",
	} {
		if _, err := ParseSOCKSUser(user); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", user, err, want)
		}
	}
	if _, err := FromHeaders("r-1", "", ""); err == nil || !strings.Contains(err.Error(), "go together") {
		t.Errorf("run without conn: %v", err)
	}
	if ids, err := FromHeaders("", "", "::ffff:198.51.100.21"); err != nil || ids.Source != "198.51.100.21" {
		t.Errorf("source only: %+v %v", ids, err)
	}
}

func TestSourceFor(t *testing.T) {
	name, _ := demo(t)
	c, _ := LoadConfig(name)
	a, ci, ci2 := c.Client("agent-1"), c.Client("ci"), c.Client("ci-2")
	if s, err := a.SourceFor(""); err != nil || s.String() != "198.51.100.10" {
		t.Errorf("agent-1: %v %v", s, err)
	}
	s1, _ := ci.SourceFor("")
	for i := 0; i < 20; i++ {
		if s, _ := ci.SourceFor(""); s != s1 {
			t.Fatal("a pool client changed its address between connections")
		}
	}
	if s, err := ci.SourceFor("198.51.100.22"); err != nil || s.String() != "198.51.100.22" {
		t.Errorf("asking for a pool address: %v %v", s, err)
	}
	for _, want := range []string{"198.51.100.10", "203.0.113.10"} {
		if _, err := ci.SourceFor(want); err == nil || !strings.Contains(err.Error(), "is not one of the source addresses of client ci") {
			t.Errorf("ci asking for %s: %v", want, err)
		}
	}
	if _, err := a.SourceFor("198.51.100.20"); err == nil {
		t.Error("agent-1 used the pool's address")
	}
	if _, err := a.SourceFor("nonsense"); err == nil {
		t.Error("nonsense accepted")
	}
	// Names spread over the pool.
	s2, _ := ci2.SourceFor("")
	if !s1.IsValid() || !s2.IsValid() || len(ci.Addresses()) != 3 || len(a.Addresses()) != 1 {
		t.Error("addresses")
	}
}

// The exit decides with the Agent's request plan; spot checks here, the
// full comparison with the Agent's broker is in exit/server's tests and in
// the namespace tests.
func TestDecide(t *testing.T) {
	name, _ := demo(t)
	c, _ := LoadConfig(name)
	dns := map[string][]net.IP{
		"api.partner.test":      {net.ParseIP("51.15.0.10")},
		"intranet.partner.test": {net.ParseIP("10.50.0.5")},
		"files.partner.test":    {net.ParseIP("51.15.0.11")},
	}
	lookups := 0
	lookup := func(h string) ([]net.IP, error) {
		lookups++
		if ips, ok := dns[h]; ok {
			return ips, nil
		}
		return nil, errors.New("no such host")
	}
	a, ci := c.Client("agent-1"), c.Client("ci")
	cases := []struct {
		cl                *Client
		host              string
		port              int
		outcome, rule, ip string
	}{
		{a, "api.partner.test", 443, "dial", "allow[0]", ""},
		{a, "intranet.partner.test", 443, "denied", "deny_private", ""},
		{a, "attacker.test", 443, "denied", "default", ""},
		{a, "169.254.169.254", 80, "denied", "deny_private", "169.254.169.254"},
		{a, "bad..name", 80, "denied", "invalid", ""},
		{a, "missing.partner.test", 443, "failed", "", ""},
		{ci, "files.partner.test", 8080, "dial", "allow[0]", ""},
		{ci, "files.partner.test", 443, "denied", "default", ""},
		{ci, "51.15.0.99", 22, "dial", "allow[1]", "51.15.0.99"},
	}
	for _, k := range cases {
		p := k.cl.Decide(k.host, k.port, lookup)
		if p.Outcome != k.outcome || p.Rule != k.rule || p.IP != k.ip {
			t.Errorf("%s %s:%d: %+v", k.cl.Name, k.host, k.port, p)
		}
	}
	lookups = 0
	if p := a.Decide("attacker.test", 443, lookup); p.LookedUp || lookups != 0 {
		t.Error("a name the policy refuses was looked up")
	}
}
