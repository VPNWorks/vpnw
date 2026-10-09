// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package path

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/VPNWorks/vpnw/internal/config"
)

func TestFromURL(t *testing.T) {
	cases := []struct {
		in     string
		scheme string
		remote bool
		user   string
		err    string
	}{
		{in: "socks5://127.0.0.1:1080", scheme: "socks5"},
		{in: "socks5h://10.8.0.1:1080", scheme: "socks5", remote: true},
		{in: "http://proxy.office:3128", scheme: "http", remote: true},
		{in: "socks5://alice:s3cret@127.0.0.1:1080", scheme: "socks5", user: "alice"},
		{in: "https://proxy:443", scheme: "http", remote: true},
		{in: "https://:tok@proxy:443", scheme: "http", remote: true, user: "vpnw"},
		{in: "socks5+tls://vpnw:tok@exit.example:8443", scheme: "socks5", remote: true, user: "vpnw"},
		{in: "https://tok@proxy:443", err: "put the token after a colon"},
		{in: "ftp://proxy:21", err: "unsupported proxy scheme"},
		{in: "socks5://127.0.0.1", err: "needs a port"},
		{in: "socks5://127.0.0.1:1080/path", err: "only a host and port"},
		{in: "socks5://127.0.0.1:abc", err: "not a proxy URL"},
		{in: "127.0.0.1:1080", err: "not a proxy URL"},
	}
	for _, c := range cases {
		p, err := FromURL("x", c.in)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s: error %v, want one containing %q", c.in, err, c.err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.in, err)
			continue
		}
		px := p.(*Proxy)
		if px.Scheme != c.scheme || px.Remote != c.remote || px.User != c.user {
			t.Errorf("%s: got scheme %s remote %v user %q", c.in, px.Scheme, px.Remote, px.User)
		}
	}
}

func TestPasswordsNeverShown(t *testing.T) {
	p, err := FromURL("office", "socks5://alice:s3cret@127.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Describe(); strings.Contains(d, "s3cret") || strings.Contains(d, "alice") {
		t.Errorf("Describe leaks credentials: %s", d)
	}
	if r := Redact("socks5://alice:s3cret@127.0.0.1:1080"); strings.Contains(r, "s3cret") {
		t.Errorf("Redact leaks the password: %s", r)
	}
	_, err = FromURL("x", "socks5://alice:s3cret@127.0.0.1")
	if err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Errorf("error message leaks the password: %v", err)
	}
	// Found by FuzzFromURL: an "@" before "://" used to stop the redaction.
	for _, raw := range []string{"@://:s3cret@", "a@socks5://u:s3cret@h:1", "socks5://u:s3c/ret@h:1"} {
		if r := Redact(raw); strings.Contains(r, "s3c") {
			t.Errorf("Redact(%q) = %q", raw, r)
		}
	}
}

// Found by FuzzExitAnswer: a proxy's status line could put control
// characters, terminal escapes among them, into vpnw's messages.
func TestStatusLineMadePrintable(t *testing.T) {
	c := &scripted{r: bytes.NewReader([]byte("HTTP/1.1 403 \x1b[2Jgone\r\n\r\n"))}
	_, err := httpConnect(c, "example.com", 443, "", "", nil)
	if err == nil || err.Error() != "http exit answered 403 ?[2Jgone" {
		t.Errorf("got %v", err)
	}
}

func TestFromSpecDNS(t *testing.T) {
	p, err := FromSpec(&config.PathSpec{Name: "office", Type: "proxy", URL: "socks5://10.8.0.1:1080", DNS: "remote"})
	if err != nil {
		t.Fatal(err)
	}
	if !p.RemoteDNS() || p.ID() != "office" {
		t.Errorf("want remote DNS on path office, got %v %s", p.RemoteDNS(), p.ID())
	}
	p, err = FromSpec(&config.PathSpec{Name: "office", Type: "proxy", URL: "socks5h://10.8.0.1:1080", DNS: "local"})
	if err != nil {
		t.Fatal(err)
	}
	if p.RemoteDNS() {
		t.Error("dns = \"local\" in the config must win over socks5h://")
	}
}

func TestDirectNeedsAnAddress(t *testing.T) {
	if _, err := (&Direct{}).Dial(context.Background(), "example.com", nil, 443); err == nil {
		t.Error("the direct path must refuse to dial a name it was not given an address for")
	}
}

// fakeSOCKS answers one SOCKS5 CONNECT and records what it was asked for.
type fakeSOCKS struct {
	ln        net.Listener
	wantUser  string
	wantPass  string
	replyCode byte
	gotHost   chan string
}

func newFakeSOCKS(t *testing.T, user, pass string, reply byte) *fakeSOCKS {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSOCKS{ln: ln, wantUser: user, wantPass: pass, replyCode: reply, gotHost: make(chan string, 1)}
	go f.serve()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeSOCKS) serve() {
	c, err := f.ln.Accept()
	if err != nil {
		return
	}
	defer c.Close()
	br := bufio.NewReader(c)
	var hdr [2]byte
	io.ReadFull(br, hdr[:])
	methods := make([]byte, hdr[1])
	io.ReadFull(br, methods)
	if f.wantUser != "" {
		c.Write([]byte{0x05, 0x02})
		var v [2]byte
		io.ReadFull(br, v[:])
		u := make([]byte, v[1])
		io.ReadFull(br, u)
		var pl [1]byte
		io.ReadFull(br, pl[:])
		pw := make([]byte, pl[0])
		io.ReadFull(br, pw)
		if string(u) != f.wantUser || string(pw) != f.wantPass {
			c.Write([]byte{0x01, 0x01})
			return
		}
		c.Write([]byte{0x01, 0x00})
	} else {
		c.Write([]byte{0x05, 0x00})
	}
	var req [4]byte
	io.ReadFull(br, req[:])
	var host string
	switch req[3] {
	case 0x01:
		var a [4]byte
		io.ReadFull(br, a[:])
		host = net.IP(a[:]).String()
	case 0x03:
		var l [1]byte
		io.ReadFull(br, l[:])
		n := make([]byte, l[0])
		io.ReadFull(br, n)
		host = string(n)
	}
	var port [2]byte
	io.ReadFull(br, port[:])
	f.gotHost <- host
	c.Write([]byte{0x05, f.replyCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if f.replyCode == 0 {
		io.WriteString(c, "hello through socks")
	}
}

func TestSOCKS5Connect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Remote DNS: the name goes to the exit.
	f := newFakeSOCKS(t, "", "", 0x00)
	p := &Proxy{Name: "office", Scheme: "socks5", Addr: f.ln.Addr().String(), Remote: true}
	c, err := p.Dial(ctx, "tracker.office.internal", nil, 443)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(c)
	c.Close()
	if got := <-f.gotHost; got != "tracker.office.internal" {
		t.Errorf("exit was asked for %q, want the name", got)
	}
	if string(b) != "hello through socks" {
		t.Errorf("relayed %q", b)
	}

	// Local DNS: only the address that was checked goes to the exit.
	f = newFakeSOCKS(t, "", "", 0x00)
	p = &Proxy{Name: "p", Scheme: "socks5", Addr: f.ln.Addr().String()}
	c, err = p.Dial(ctx, "api.github.com", net.ParseIP("140.82.112.6"), 443)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if got := <-f.gotHost; got != "140.82.112.6" {
		t.Errorf("exit was asked for %q, want the checked address", got)
	}

	// Credentials, right and wrong.
	f = newFakeSOCKS(t, "alice", "s3cret", 0x00)
	p = &Proxy{Name: "p", Scheme: "socks5", Addr: f.ln.Addr().String(), User: "alice", Pass: "s3cret", Remote: true}
	if c, err = p.Dial(ctx, "example.com", nil, 80); err != nil {
		t.Fatalf("right password refused: %v", err)
	}
	c.Close()
	f = newFakeSOCKS(t, "alice", "s3cret", 0x00)
	p = &Proxy{Name: "p", Scheme: "socks5", Addr: f.ln.Addr().String(), User: "alice", Pass: "wrong", Remote: true}
	if _, err = p.Dial(ctx, "example.com", nil, 80); err == nil || !strings.Contains(err.Error(), "refused the password") {
		t.Errorf("wrong password: %v", err)
	}

	// An exit that refuses the destination.
	f = newFakeSOCKS(t, "", "", 0x04)
	p = &Proxy{Name: "p", Scheme: "socks5", Addr: f.ln.Addr().String(), Remote: true}
	if _, err = p.Dial(ctx, "unknown.internal", nil, 80); err == nil || !strings.Contains(err.Error(), "host unreachable") {
		t.Errorf("refusal not explained: %v", err)
	}
}

func TestHTTPConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 2)
	go func() {
		for i := 0; i < 2; i++ {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			br := bufio.NewReader(c)
			line, _ := br.ReadString('\n')
			auth := ""
			for {
				l, _ := br.ReadString('\n')
				if strings.HasPrefix(l, "Proxy-Authorization: ") {
					auth = strings.TrimSpace(strings.TrimPrefix(l, "Proxy-Authorization: "))
				}
				if l == "\r\n" || l == "" {
					break
				}
			}
			got <- strings.TrimSpace(line) + "|" + auth
			if strings.Contains(line, "denied.example") {
				io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
			} else {
				// Bytes right after the headers must reach the client.
				io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\nearly bytes")
			}
			c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p := &Proxy{Name: "p", Scheme: "http", Addr: ln.Addr().String(), User: "bob", Pass: "pw", Remote: true}
	c, err := p.Dial(ctx, "api.github.com", nil, 443)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(c)
	c.Close()
	if string(b) != "early bytes" {
		t.Errorf("bytes after the CONNECT reply were lost: %q", b)
	}
	req := <-got
	want := "CONNECT api.github.com:443 HTTP/1.1|Basic " + base64.StdEncoding.EncodeToString([]byte("bob:pw"))
	if req != want {
		t.Errorf("request %q, want %q", req, want)
	}
	if _, err := p.Dial(ctx, "denied.example", nil, 443); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("a 403 from the exit must fail the dial: %v", err)
	}
}

func TestHealth(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close() // nothing listens there now
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	p := &Proxy{Name: "office", Scheme: "socks5", Addr: addr}
	if err := p.Health(ctx); err == nil || !strings.Contains(err.Error(), "not reachable") {
		t.Errorf("health of a dead proxy: %v", err)
	}
}
