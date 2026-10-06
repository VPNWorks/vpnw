// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"vpnw.com/vpnw/internal/events"
	"vpnw.com/vpnw/internal/exit"
)

// syncBuf is a buffer two goroutines can share.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type files struct {
	dir, config, record string
	pool                *x509.CertPool
}

// setup writes a certificate, a key, a client policy file and an exit's
// configuration.
func setup(t *testing.T, notAfter time.Time) files {
	t.Helper()
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "exit-test"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	os.WriteFile(filepath.Join(dir, "exit.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	os.WriteFile(filepath.Join(dir, "exit.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600)
	os.WriteFile(filepath.Join(dir, "agent-1.toml"), []byte("version = 1\nname = \"agent-1\"\n[policy]\ndefault = \"deny\"\nallow = [\"127.0.0.1\", \"echo.test\"]\n"), 0o644)
	cfg := fmt.Sprintf(`version = 1
name = "exit-test"
listen = "127.0.0.1:0"
cert = "exit.crt"
key = "exit.key"

[clients.agent-1]
token_sha256 = %q
source = "127.0.0.2"
policy = "agent-1.toml"

[clients.ci]
token_sha256 = %q
pool = "lo"
default = "deny"
deny_private = true
allow = ["api.partner.test"]

[pools.lo]
addresses = ["127.0.0.4", "127.0.0.5"]
`, exit.HashHex("tok-1"), exit.HashHex("tok-ci"))
	name := filepath.Join(dir, "exit.toml")
	os.WriteFile(name, []byte(cfg), 0o644)
	pool := x509.NewCertPool()
	c, _ := x509.ParseCertificate(der)
	pool.AddCert(c)
	return files{dir: dir, config: name, record: filepath.Join(dir, "record.jsonl"), pool: pool}
}

// call runs the command. A serve that starts when it should have refused is
// stopped after 20 seconds, so its test fails instead of hanging.
func call(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	code := run(ctx, args, strings.NewReader(""), &out, &errb)
	return code, out.String(), errb.String()
}

func TestServe(t *testing.T) {
	f := setup(t, time.Now().Add(24*time.Hour))
	// A destination that says who connected.
	dl, _ := net.Listen("tcp", "127.0.0.1:0")
	defer dl.Close()
	go func() {
		for {
			c, err := dl.Accept()
			if err != nil {
				return
			}
			host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			fmt.Fprintf(c, "from %s\n", host)
			c.Close()
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	stderr := &syncBuf{}
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"serve", "--config", f.config, "--out", f.record, "-v"}, nil, io.Discard, stderr)
	}()
	re := regexp.MustCompile(`listening on (127\.0\.0\.1:\d+)`)
	var addr string
	for i := 0; i < 500 && addr == ""; i++ {
		if m := re.FindStringSubmatch(stderr.String()); m != nil {
			addr = m[1]
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == "" {
		cancel()
		t.Fatalf("serve did not start:\n%s", stderr.String())
	}
	tc, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: f.pool, ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	cred := base64.StdEncoding.EncodeToString([]byte("vpnw:tok-1"))
	fmt.Fprintf(tc, "CONNECT %s HTTP/1.1\r\nProxy-Authorization: Basic %s\r\nVPNW-Run: r-cli001\r\nVPNW-Conn: 3\r\n\r\n", dl.Addr(), cred)
	br := bufio.NewReader(tc)
	status, _ := br.ReadString('\n')
	br.ReadString('\n')
	line, _ := br.ReadString('\n')
	tc.Close()
	if !strings.HasPrefix(status, "HTTP/1.1 200") || line != "from 127.0.0.2\n" {
		t.Fatalf("%q %q", status, line)
	}
	// The exit records the close when its relay ends, which can come after
	// the next connection's events; wait for it so the record's order holds.
	for i := 0; i < 500 && !strings.Contains(stderr.String(), "   close  "); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	// A wrong token, over TLS.
	tc, _ = tls.Dial("tcp", addr, &tls.Config{RootCAs: f.pool, ServerName: "127.0.0.1"})
	fmt.Fprintf(tc, "CONNECT %s HTTP/1.1\r\nProxy-Authorization: Basic %s\r\n\r\n", dl.Addr(), base64.StdEncoding.EncodeToString([]byte("vpnw:nope")))
	status, _ = bufio.NewReader(tc).ReadString('\n')
	tc.Close()
	if !strings.HasPrefix(status, "HTTP/1.1 407") {
		t.Errorf("wrong token: %q", status)
	}
	time.Sleep(100 * time.Millisecond)
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("serve ended with %d:\n%s", code, stderr.String())
	}
	b, _ := os.ReadFile(f.record)
	evs, err := events.Read(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	for _, e := range evs {
		types = append(types, e.Type)
	}
	want := "run.start,connection.attempt,policy.allow,connection.open,connection.close,auth.deny,run.end"
	if strings.Join(types, ",") != want {
		t.Errorf("record %v\nwant %s", types, want)
	}
	if evs[1].Str("client_run") != "r-cli001" || evs[1].Int("client_conn") != 3 || evs[3].Str("source") != "127.0.0.2" || evs[6].Int("auth_denied") != 1 {
		t.Errorf("record fields %+v", evs)
	}
	for _, w := range []string{"agent-1 r-cli001/3", "open   127.0.0.1 from 127.0.0.2", "refused a client at 127.0.0.1", "unknown token", "summary  1 connections: 1 opened"} {
		if !strings.Contains(stderr.String(), w) {
			t.Errorf("output lacks %q:\n%s", w, stderr.String())
		}
	}
}

func TestServeNotPossible(t *testing.T) {
	f := setup(t, time.Now().Add(24*time.Hour))
	src, _ := os.ReadFile(f.config)
	// A source address this machine does not have.
	bad := filepath.Join(f.dir, "bad-source.toml")
	os.WriteFile(bad, []byte(strings.Replace(string(src), "127.0.0.2", "192.0.2.77", 1)), 0o644)
	if code, _, stderr := call("serve", "--config", bad); code != exitUnavailable || !strings.Contains(stderr, "source address 192.0.2.77 is not on this machine") {
		t.Errorf("bad source: %d %s", code, stderr)
	}
	// A listener someone else has.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	busy := filepath.Join(f.dir, "busy.toml")
	os.WriteFile(busy, []byte(strings.Replace(string(src), "127.0.0.1:0", l.Addr().String(), 1)), 0o644)
	if code, _, stderr := call("serve", "--config", busy); code != exitUnavailable || !strings.Contains(stderr, "cannot listen on") {
		t.Errorf("busy: %d %s", code, stderr)
	}
	nocert := filepath.Join(f.dir, "nocert.toml")
	os.WriteFile(nocert, []byte(strings.Replace(string(src), "exit.crt", "missing.crt", 1)), 0o644)
	if code, _, stderr := call("serve", "--config", nocert); code != exitConfig || !strings.Contains(stderr, "missing.crt") {
		t.Errorf("missing certificate: %d %s", code, stderr)
	}
	if code, _, stderr := call("serve", "--config", f.config, "--out", filepath.Join(f.dir, "no", "r.jsonl")); code != exitConfig || !strings.Contains(stderr, "cannot write") {
		t.Errorf("bad --out: %d %s", code, stderr)
	}
}

func TestCheck(t *testing.T) {
	f := setup(t, time.Now().Add(24*time.Hour))
	code, out, _ := call("check", "--config", f.config)
	if code != 0 || !strings.Contains(out, "exit exit-test on 127.0.0.1:0, 2 clients, 1 pools; certificate") ||
		!strings.Contains(out, "agent-1: source 127.0.0.2; policy agent-1.toml (default deny, 2 allow rules, 0 deny rules, deny_private false)") {
		t.Errorf("check: %d\n%s", code, out)
	}
	if !strings.Contains(out, "valid until") {
		t.Errorf("no expiry date:\n%s", out)
	}
}

func TestToken(t *testing.T) {
	code, out, _ := call("token")
	m := regexp.MustCompile(`^token: (\S{43})\ntoken_sha256 = "([0-9a-f]{64})"\n$`).FindStringSubmatch(out)
	if code != 0 || m == nil || exit.HashHex(m[1]) != m[2] {
		t.Fatalf("token: %q", out)
	}
	dir := t.TempDir()
	tf := filepath.Join(dir, "t")
	os.WriteFile(tf, []byte(m[1]+"\n"), 0o600)
	if code, out, _ := call("token", "--from", tf); code != 0 || out != fmt.Sprintf("token_sha256 = %q\n", m[2]) {
		t.Errorf("--from: %q", out)
	}
	os.WriteFile(tf, []byte("\n"), 0o600)
	if code, _, _ := call("token", "--from", tf); code != exitConfig {
		t.Error("empty token file")
	}
	if code, _, _ := call("token", "--from", filepath.Join(dir, "none")); code != exitConfig {
		t.Error("missing token file")
	}
}

func TestDecide(t *testing.T) {
	f := setup(t, time.Now().Add(24*time.Hour))
	dns := filepath.Join(f.dir, "dns.json")
	os.WriteFile(dns, []byte(`{"api.partner.test": ["51.15.0.10"], "intranet.partner.test": ["10.50.0.5"]}`), 0o644)
	code, out, _ := call("decide", "--config", f.config, "--client", "ci", "--dns", dns, "api.partner.test:443", "169.254.169.254:80", "evil.test:443")
	if code != exitFound || !strings.Contains(out, "allow   api.partner.test:443  from 127.0.0.") ||
		!strings.Contains(out, "DENY    169.254.169.254:80  deny_private: 169.254.169.254: link-local address") ||
		!strings.Contains(out, "DENY    evil.test:443  default: no allow rule matches evil.test:443") {
		t.Errorf("decide: %d\n%s", code, out)
	}
	code, out, _ = call("decide", "--config", f.config, "--client", "ci", "--dns", dns, "--json", "api.partner.test:443")
	var d decision
	if code != 0 || json.Unmarshal([]byte(out), &d) != nil || d.Outcome != "allow" || d.Rule != "allow[0]" || len(d.Addrs) != 1 {
		t.Errorf("decide --json: %d %s", code, out)
	}
	code, out, _ = call("decide", "--config", f.config, "--client", "agent-1", "--dns", dns, "echo.test:80")
	if code != 0 || !strings.Contains(out, "failed  echo.test:80  dns: no such host") {
		t.Errorf("decide failed lookup: %d %s", code, out)
	}
}

func TestJoinCommand(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, evs func(b *events.Bus)) string {
		p := filepath.Join(dir, name)
		fh, _ := os.Create(p)
		j := events.NewJSONL(fh)
		run := "r-cli001"
		if strings.HasPrefix(name, "exit") {
			run = "x-cli001"
		}
		b := events.NewBus(run, nil)
		b.Add(j)
		evs(b)
		j.Close()
		return p
	}
	agent := write("agent.jsonl", func(b *events.Bus) {
		b.Emit(events.RunStart, 0, "exits", 0, nil)
		b.Emit(events.ConnectionAttempt, 1, "exits", 1, map[string]any{"host": "api.partner.test", "port": 443})
		b.Emit(events.ConnectionOpen, 1, "exits", 1, map[string]any{"exit": "127.0.0.1:8443"})
		b.Emit(events.ConnectionAttempt, 1, "exits", 2, map[string]any{"host": "evil.test", "port": 443})
		b.Emit(events.PolicyDeny, 1, "exits", 2, map[string]any{"rule": "default"})
	})
	good := write("exit-good.jsonl", func(b *events.Bus) {
		b.Emit(events.ConnectionAttempt, 0, "exit-test", 1, map[string]any{"host": "api.partner.test", "port": 443, "client_run": "r-cli001", "client_conn": 1})
		b.Emit(events.ConnectionOpen, 0, "exit-test", 1, map[string]any{"source": "127.0.0.2"})
	})
	bad := write("exit-bad.jsonl", func(b *events.Bus) {
		b.Emit(events.ConnectionAttempt, 0, "exit-test", 1, map[string]any{"host": "api.partner.test", "port": 443, "client_run": "r-cli001", "client_conn": 7})
		b.Emit(events.ConnectionOpen, 0, "exit-test", 1, map[string]any{"source": "127.0.0.2"})
	})
	code, out, _ := call("join", "--agent", agent, "--exit", good)
	if code != 0 || !strings.Contains(out, "Joined: 1 of the 1 connections that reached an exit.") || !strings.Contains(out, "r-cli001/1  api.partner.test:443  exit-test  Agent: open; exit: open from 127.0.0.2") {
		t.Errorf("join: %d\n%s", code, out)
	}
	code, out, _ = call("join", "--agent", agent, "--exit", bad, "--json")
	var r exit.JoinReport
	if code != exitFound || json.Unmarshal([]byte(out), &r) != nil || len(r.Problems) != 2 {
		t.Errorf("join bad: %d\n%s", code, out)
	}
	code, out, _ = call("join", "--agent", agent, "--exit", bad)
	if code != exitFound || !strings.Contains(out, "does not join: ") {
		t.Errorf("join bad text: %d\n%s", code, out)
	}
	notjson := filepath.Join(dir, "x.jsonl")
	os.WriteFile(notjson, []byte("nope\n"), 0o644)
	if code, _, stderr := call("join", "--agent", agent, "--exit", notjson); code != exitConfig || !strings.Contains(stderr, "x.jsonl: line 1: not a valid event") {
		t.Errorf("bad record: %d %s", code, stderr)
	}
}

func TestErrors(t *testing.T) {
	f := setup(t, time.Now().Add(24*time.Hour))
	cases := []struct {
		args []string
		code int
		want string
	}{
		{nil, exitConfig, "Usage:"},
		{[]string{"frob"}, exitConfig, "unknown command"},
		{[]string{"serve"}, exitConfig, "--config FILE is required"},
		{[]string{"serve", "--nope"}, exitConfig, "serve: flag provided but not defined"},
		{[]string{"serve", "--config", f.config, "extra"}, exitConfig, "unexpected argument"},
		{[]string{"check"}, exitConfig, "--config FILE is required"},
		{[]string{"check", "--config", filepath.Join(f.dir, "none.toml")}, exitConfig, "no such file"},
		{[]string{"check", "x"}, exitConfig, "unexpected argument"},
		{[]string{"token", "x"}, exitConfig, "unexpected argument"},
		{[]string{"decide", "--config", f.config}, exitConfig, "--client NAME is required"},
		{[]string{"decide", "--config", f.config, "--client", "nobody", "a:1"}, exitConfig, "no client \"nobody\""},
		{[]string{"decide", "--config", f.config, "--client", "ci"}, exitConfig, "at least one HOST:PORT"},
		{[]string{"decide", "--config", f.config, "--client", "ci", "nohost"}, exitConfig, "want HOST:PORT"},
		{[]string{"decide", "--config", f.config, "--client", "ci", "a:b"}, exitConfig, "bad port"},
		{[]string{"decide", "--config", f.config, "--client", "ci", "--dns", f.config, "a:1"}, exitConfig, "JSON object"},
		{[]string{"decide", "--bogus"}, exitConfig, "decide:"},
		{[]string{"decide"}, exitConfig, "--config FILE is required"},
		{[]string{"join"}, exitConfig, "at least one --agent"},
		{[]string{"join", "--agent", "x", "--exit", "y", "z"}, exitConfig, "unexpected argument"},
		{[]string{"join", "--agent", filepath.Join(f.dir, "none"), "--exit", "y"}, exitConfig, "no such file"},
	}
	for _, c := range cases {
		code, out, stderr := call(c.args...)
		if code != c.code || !strings.Contains(out+stderr, c.want) {
			t.Errorf("%v: exit %d, %q; want %d and %q", c.args, code, out+stderr, c.code, c.want)
		}
	}
	if code, out, _ := call("version"); code != 0 || !strings.HasPrefix(out, "vpnw-exit 0.1.0 (") {
		t.Errorf("version: %s", out)
	}
	if code, out, _ := call("help"); code != 0 || !strings.Contains(out, "vpnw-exit serve") {
		t.Errorf("help: %s", out)
	}
	dns := filepath.Join(f.dir, "dns.json")
	os.WriteFile(dns, []byte(`{"a.test": ["not-an-ip"]}`), 0o644)
	if code, _, stderr := call("decide", "--config", f.config, "--client", "ci", "--dns", dns, "a.test:1"); code != exitConfig || !strings.Contains(stderr, "is not an address") {
		t.Errorf("bad dns file: %s", stderr)
	}
}
