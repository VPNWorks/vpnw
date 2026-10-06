// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"vpnw.com/vpnw/internal/events"
	"vpnw.com/vpnw/internal/exit"
)

// fuzzConfig has two clients. Only allowed.test may ever be dialed for c,
// from c's address, and only other.test for d, from d's.
func fuzzServer(f *testing.F) func() (*Server, *[]string, *events.Memory, *sync.Mutex) {
	src := fmt.Sprintf(`version = 1
listen = "127.0.0.1:0"
cert = "c"
key = "k"
[clients.c]
token_sha256 = %q
source = "127.0.0.2"
default = "deny"
deny_private = true
allow = ["allowed.test"]
[clients.d]
token_sha256 = %q
source = "127.0.0.3"
default = "deny"
allow = ["other.test", "8.8.4.0/24"]
`, exit.HashHex("tok-c"), exit.HashHex("tok-d"))
	cfg, err := exit.ParseConfig(src, "fuzz.toml", nil)
	if err != nil {
		f.Fatal(err)
	}
	dns := map[string][]net.IP{
		"allowed.test": {net.ParseIP("93.184.215.14")},
		"other.test":   {net.ParseIP("8.8.8.8")},
		"evil.test":    {net.ParseIP("10.0.0.1")},
	}
	return func() (*Server, *[]string, *events.Memory, *sync.Mutex) {
		var dials []string
		var mu sync.Mutex
		mem := &events.Memory{}
		bus := events.NewBus("x-fuzz", nil)
		bus.Add(mem)
		s := &Server{Config: cfg, Resolver: &fakeDNS{m: dns}, Bus: bus, DialTimeout: time.Second,
			Dial: func(_ context.Context, src netip.Addr, dst net.IP, port int) (net.Conn, error) {
				mu.Lock()
				dials = append(dials, src.String()+">"+dst.String())
				mu.Unlock()
				return nil, errors.New("fuzz does not dial")
			}}
		return s, &dials, mem, &mu
	}
}

func checkFuzz(t *testing.T, s *Server, input []byte, dials *[]string, mem *events.Memory, mu *sync.Mutex) {
	c := &fakeConn{r: bytes.NewReader(input)}
	done := make(chan struct{})
	go func() {
		s.Handle(c)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the exit hung on this input")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, d := range *dials {
		if d != "127.0.0.2>93.184.215.14" && d != "127.0.0.3>8.8.8.8" && !strings.HasPrefix(d, "127.0.0.3>8.8.4.") {
			t.Fatalf("dialed %s, which no client's policy allows from that address", d)
		}
	}
	for _, e := range mem.Snapshot() {
		for k, v := range e.Fields {
			if str, ok := v.(string); ok {
				for _, r := range str {
					if r < 0x20 || r == 0x7f {
						t.Fatalf("event %s field %s holds a control character: %q", e.Type, k, str)
					}
				}
			}
		}
	}
}

// FuzzHTTPFront feeds arbitrary bytes to the exit as a client would after
// TLS, starting with HTTP. Whatever arrives, the exit must not crash or
// hang, must never dial what the client's policy refuses or dial without a
// valid token, and must keep its record printable.
func FuzzHTTPFront(f *testing.F) {
	for _, s := range []string{
		"CONNECT allowed.test:443 HTTP/1.1\r\nProxy-Authorization: " + basic("tok-c") + "\r\nVPNW-Run: r-1\r\nVPNW-Conn: 1\r\n\r\n",
		"CONNECT evil.test:443 HTTP/1.1\r\nProxy-Authorization: " + basic("tok-c") + "\r\n\r\n",
		"CONNECT allowed.test:443 HTTP/1.1\r\nProxy-Authorization: " + basic("tok-d") + "\r\n\r\n",
		"CONNECT other.test:443 HTTP/1.1\r\nProxy-Authorization: " + basic("tok-d") + "\r\nVPNW-Source: 127.0.0.2\r\n\r\n",
		"CONNECT 8.8.4.4:53 HTTP/1.1\r\nProxy-Authorization: " + basic("tok-d") + "\r\n\r\n",
		"CONNECT allowed.test:443 HTTP/1.1\r\n\r\n",
		"GET /health HTTP/1.1\r\nAuthorization: Bearer tok-c\r\n\r\n",
		"CONNECT [::ffff:127.0.0.1]:22 HTTP/1.1\r\nProxy-Authorization: " + basic("tok-c") + "\r\n\r\n",
		"GET http://allowed.test/ HTTP/1.1\r\n\r\n",
	} {
		f.Add([]byte(s))
	}
	mk := fuzzServer(f)
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 0 && input[0] == 0x05 {
			return // that is SOCKS5, the other target's
		}
		s, dials, mem, mu := mk()
		checkFuzz(t, s, input, dials, mem, mu)
	})
}

// FuzzSOCKSFront does the same for SOCKS5.
func FuzzSOCKSFront(f *testing.F) {
	login := func(user, pass string) []byte {
		b := []byte{5, 1, 2, 1, byte(len(user))}
		b = append(b, user...)
		b = append(b, byte(len(pass)))
		return append(b, pass...)
	}
	name := func(cmd byte, host string, port int) []byte {
		b := []byte{5, cmd, 0, 3, byte(len(host))}
		b = append(b, host...)
		return append(b, byte(port>>8), byte(port))
	}
	for _, s := range [][]byte{
		append(login("r-1/1", "tok-c"), name(1, "allowed.test", 443)...),
		append(login("vpnw", "tok-c"), name(1, "evil.test", 443)...),
		append(login("r-1/2/127.0.0.3", "tok-c"), name(1, "allowed.test", 443)...),
		append(login("vpnw", "tok-d"), 5, 1, 0, 1, 8, 8, 4, 4, 0, 53),
		append(login("vpnw", "wrong"), name(1, "allowed.test", 443)...),
		append(login("vpnw", "tok-c"), name(3, "allowed.test", 443)...),
		{5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 0, 80},
		{5, 0},
	} {
		f.Add(s)
	}
	mk := fuzzServer(f)
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) == 0 || input[0] != 0x05 {
			return // that is HTTP, the other target's
		}
		s, dials, mem, mu := mk()
		checkFuzz(t, s, input, dials, mem, mu)
	})
}

// fakeConn serves a fixed input, then EOF, and keeps what the exit writes.
type fakeConn struct {
	r   *bytes.Reader
	out bytes.Buffer
}

func (c *fakeConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *fakeConn) Write(p []byte) (int, error) { return c.out.Write(p) }
func (c *fakeConn) Close() error                { return nil }
func (c *fakeConn) LocalAddr() net.Addr         { return &net.TCPAddr{} }
func (c *fakeConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 4000}
}
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }
