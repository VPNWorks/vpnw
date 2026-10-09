// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// The example from the architecture document (v0.2, section 7).
const archExample = `version = 1
name = "research"

[network]
type = "proxy"
url = "socks5://127.0.0.1:1080"

[policy]
deny_private = true
allow = ["github.com", "*.githubusercontent.com"]

[trace]
enabled = true
format = "text"
`

func TestArchitectureExample(t *testing.T) {
	f, err := ParseFile("research.toml", archExample)
	if err != nil {
		t.Fatal(err)
	}
	if f.Name != "research" || f.Network == nil || f.Network.URL != "socks5://127.0.0.1:1080" || f.Network.DNS != "remote" {
		t.Errorf("network: %+v", f.Network)
	}
	if f.Policy == nil || !f.Policy.DenyPrivate || len(f.Policy.Allow) != 2 || f.Policy.Default != "" {
		t.Errorf("policy: %+v", f.Policy)
	}
	if f.Trace == nil || !f.Trace.Enabled || f.Trace.Format != "text" {
		t.Errorf("trace: %+v", f.Trace)
	}
}

func TestSyntax(t *testing.T) {
	src := "version = 1 # comment\r\n" +
		"name = 'lit\\eral'\n" +
		"[paths.office]\n" +
		"type = \"proxy\"\n" +
		"url = \"socks5://10.0.0.2:1080\"\n" +
		"dns = \"local\"\n" +
		"[policy]\n" +
		"allow = [\n  \"a.example\", # one\n  \"b.example\",\n]\n" +
		"deny = []\n" +
		"default = \"deny\"\n"
	f, err := ParseFile("x.toml", src)
	if err != nil {
		t.Fatal(err)
	}
	if f.Name != `lit\eral` {
		t.Errorf("literal string: %q", f.Name)
	}
	o := f.Paths["office"]
	if o == nil || o.DNS != "local" || o.Name != "office" {
		t.Errorf("office path: %+v", o)
	}
	if got := strings.Join(f.Policy.Allow, ","); got != "a.example,b.example" {
		t.Errorf("allow: %s", got)
	}
	d, err := Parse(`s = "tab\there \u00e9 \"q\""` + "\n")
	if err != nil || d.Tables[""].Keys["s"].Str != "tab\there é \"q\"" {
		t.Errorf("escapes: %v %+v", err, d)
	}
	n, err := Parse("a = -1_000\nb = +7\nc = 0\n")
	if err != nil || n.Tables[""].Keys["a"].Int != -1000 || n.Tables[""].Keys["b"].Int != 7 {
		t.Errorf("integers: %v", err)
	}
}

func TestErrors(t *testing.T) {
	cases := []struct{ src, want string }{
		{"name = \"x\"\n", "missing version"},
		{"version = 2\n", "unsupported version 2"},
		{"version = \"1\"\n", "version must be a number"},
		{"version = 1\n[policy]\nalow = [\"x\"]\n", `unknown key "alow" in [policy] (did you mean "allow"?)`},
		{"version = 1\n[polcy]\n", `unknown table [polcy] (did you mean "policy"?)`},
		{"version = 1\nversion = 1\n", "set twice"},
		{"version = 1\n[policy]\n[policy]\n", "defined twice"},
		{"version = 1\nx = {a = 1}\n", "inline tables"},
		{"version = 1\n[[paths]]\n", "arrays of tables"},
		{"version = 1\nx = 1.5\n", "whole decimal"},
		{"version = 1\nx = 0x10\n", "whole decimal"},
		{"version = 1\nx = 010\n", "must not start with 0"},
		{"version = 1\nx = \"\"\"a\"\"\"\n", "multi-line strings"},
		{"version = 1\na.b = 1\n", "dotted keys"},
		{"version = 1\nx = \"unterminated\n", "unterminated string"},
		{"version = 1\nx = [1, \"a\"]\n", "one kind of value"},
		{"version = 1\nx = [1, 2\n", "unterminated array"},
		{"version = 1\nx = nope\n", "strings need quotes"},
		{"version = 1\nx = \"a\" y = 1\n", "one key per line"},
		{"version = 1\nx = \"\\q\"\n", "unknown escape"},
		{"version = 1\n[network]\ntype = \"wireguard\"\n", "needs config = \"wg0.conf\""},
		{"version = 1\n[network]\ntype = \"wireguard\"\nconfig = \"w.conf\"\nurl = \"socks5://a:1\"\n", "a wireguard path has no url"},
		{"version = 1\n[network]\ntype = \"wireguard\"\nconfig = \"w.conf\"\ndns = \"remote\"\n", "dns for a wireguard path is"},
		{"version = 1\n[network]\ntype = \"proxy\"\nurl = \"socks5://a:1\"\nconfig = \"w.conf\"\n", "config is the wg-quick file of a wireguard path"},
		{"version = 1\n[network]\ntype = \"tunnel\"\n", "use \"direct\", \"proxy\" or \"wireguard\""},
		{"version = 1\n[network]\ntype = \"proxy\"\n", "needs url"},
		{"version = 1\n[network]\ntype = \"direct\"\nurl = \"socks5://x:1\"\n", "no url"},
		{"version = 1\n[network]\ntype = \"direct\"\ndns = \"remote\"\n", "always resolves names locally"},
		{"version = 1\n[paths.Office]\ntype = \"direct\"\n", "must be lowercase"},
		{"version = 1\n[paths.direct]\ntype = \"direct\"\n", "reserved path name"},
		{"version = 1\n[paths]\ntype = \"direct\"\n", "own table"},
		{"version = 1\n[policy]\ndefault = \"maybe\"\n", "allow\" or \"deny"},
		{"version = 1\n[policy]\nallow = \"github.com\"\n", "list of strings"},
		{"version = 1\n[policy]\ndeny_private = \"yes\"\n", "true or false"},
		{"version = 1\n[trace]\nformat = \"xml\"\n", "text\" or \"jsonl"},
		{"version = 1\n\x00", "NUL"},
		{"version = 1\n[a.b.c]\n", "at most two parts"},
		{"version = 1\nx = [[[[[[[[[1]]]]]]]]]\n", "nested too deeply"},
	}
	for _, c := range cases {
		_, err := ParseFile("f.toml", c.src)
		if err == nil {
			t.Errorf("%q: want error containing %q", c.src, c.want)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: error %q does not contain %q", c.src, err, c.want)
		}
	}
}

func TestLineNumbers(t *testing.T) {
	_, err := ParseFile("p.toml", "version = 1\n\n[policy]\n# c\nallow = [\"a\"]\nbogus = true\n")
	if err == nil || !strings.HasPrefix(err.Error(), "p.toml:6:") {
		t.Errorf("want p.toml:6: prefix, got %v", err)
	}
}

func TestMerge(t *testing.T) {
	a, _ := ParseFile("a.toml", "version = 1\n[paths.office]\ntype = \"proxy\"\nurl = \"socks5://1.2.3.4:1080\"\n")
	b, _ := ParseFile("b.toml", "version = 1\nname = \"agent\"\n[policy]\nallow = [\"x.example\"]\n")
	m, err := Merge(a, b)
	if err != nil || m.Paths["office"] == nil || m.Policy == nil || m.Name != "agent" {
		t.Fatalf("merge: %v %+v", err, m)
	}
	c, _ := ParseFile("c.toml", "version = 1\n[policy]\ndefault = \"allow\"\n")
	if _, err := Merge(b, c); err == nil || !strings.Contains(err.Error(), "already set in b.toml") {
		t.Errorf("duplicate policy: %v", err)
	}
	if _, err := Merge(a, a); err == nil {
		t.Error("duplicate path should fail")
	}
}

// Agent 0.2.0: a list of exits, a CA file and a token file.
func TestExitsKeys(t *testing.T) {
	src := "version = 1\n" +
		"[paths.exits]\n" +
		"type = \"proxy\"\n" +
		"urls = [\"https://198.51.100.2:8443\", \"https://203.0.113.2:8443\"]\n" +
		"ca_file = \"ca.pem\"\n" +
		"token_file = \"agent-1.token\"\n" +
		"[network]\n" +
		"type = \"proxy\"\n" +
		"url = \"socks5+tls://exit.example:8443\"\n" +
		"token_file = \"/etc/vpnw/token\"\n"
	f, err := ParseFile("conf/agent.toml", src)
	if err != nil {
		t.Fatal(err)
	}
	p := f.Paths["exits"]
	if p == nil || len(p.URLs) != 2 || p.URL != "" || p.CAFile != "ca.pem" || p.TokenFile != "agent-1.token" || p.File != "conf/agent.toml" || p.DNS != "remote" {
		t.Errorf("exits: %+v", p)
	}
	if f.Network.File != "conf/agent.toml" || f.Network.TokenFile != "/etc/vpnw/token" {
		t.Errorf("network: %+v", f.Network)
	}
	cases := []struct{ src, want string }{
		{"version = 1\n[paths.x]\ntype = \"proxy\"\nurl = \"https://a:1\"\nurls = [\"https://b:1\"]\n", "not both"},
		{"version = 1\n[paths.x]\ntype = \"proxy\"\nurls = []\n", "urls is empty"},
		{"version = 1\n[paths.x]\ntype = \"proxy\"\nurls = \"https://a:1\"\n", "list of strings"},
		{"version = 1\n[paths.x]\ntype = \"direct\"\nurls = [\"https://a:1\"]\n", "a direct path has no urls"},
		{"version = 1\n[paths.x]\ntype = \"direct\"\nca_file = \"ca.pem\"\n", "a direct path has no ca_file"},
		{"version = 1\n[paths.x]\ntype = \"proxy\"\nurl = \"https://a:1\"\ntoken_file = \"\"\n", "token_file is empty"},
		{"version = 1\n[paths.x]\ntype = \"proxy\"\nurl = \"https://a:1\"\nca_file = 1\n", "ca_file must be a string"},
		{"version = 1\n[paths.x]\ntype = \"proxy\"\nurl = \"https://a:1\"\ntoken_fle = \"t\"\n", `did you mean "token_file"`},
	}
	for _, c := range cases {
		if _, err := ParseFile("f.toml", c.src); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v, want %q", c.src, err, c.want)
		}
	}
}

// Exit reads a client's policy from inside its own table.
func TestPolicyFromTable(t *testing.T) {
	d, err := Parse("[clients.ci]\ntoken_sha256 = \"x\"\ndefault = \"deny\"\nallow = [\"a.example\"]\ndeny_private = true\n")
	if err != nil {
		t.Fatal(err)
	}
	ps, err := PolicyFromTable(d.Tables["clients.ci"])
	if err != nil || ps.Default != "deny" || !ps.DenyPrivate || len(ps.Allow) != 1 {
		t.Errorf("%v %+v", err, ps)
	}
	d, _ = Parse("[clients.ci]\ndefault = \"maybe\"\n")
	if _, err := PolicyFromTable(d.Tables["clients.ci"]); err == nil {
		t.Error("a bad default was accepted")
	}
}

func TestNamedNetwork(t *testing.T) {
	f, err := ParseFile("n.toml", "version = 1\n[network]\nname = \"internet\"\ntype = \"proxy\"\nurl = \"socks5h://127.0.0.1:1090\"\n")
	if err != nil || f.Network.Name != "internet" {
		t.Fatalf("%v %+v", err, f)
	}
}
