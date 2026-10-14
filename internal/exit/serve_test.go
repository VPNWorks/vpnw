// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package exit

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/VPNWorks/vpnw/internal/broker"
	"github.com/VPNWorks/vpnw/internal/events"
	"github.com/VPNWorks/vpnw/internal/path"
)

type names map[string][]net.IP

func (n names) LookupIP(_ context.Context, host string) ([]net.IP, error) {
	if ips, ok := n[host]; ok {
		return ips, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// echo answers "hello <line>" and reports the address each connection came
// from.
func echo(t *testing.T) (int, chan string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	from := make(chan string, 16)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			from <- c.RemoteAddr().(*net.TCPAddr).IP.String()
			go func(c net.Conn) {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				fmt.Fprintf(c, "hello %s", line)
			}(c)
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, from
}

// testExit serves an exit from its file over TLS, in this process, and
// returns its address and record. The CA's certificate is dir/ca.pem.
func testExit(t testing.TB, dir, src string) (string, *events.Memory) {
	t.Helper()
	now := time.Now()
	ca, caPEM, _, err := NewCA(now)
	if err != nil {
		t.Fatal(err)
	}
	crt, key, err := ca.Issue([]string{"127.0.0.1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "ca.pem"), caPEM, 0o644)
	kp, err := tls.X509KeyPair(crt, key)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfig(src, filepath.Join(dir, "exit.toml"), nil)
	if err != nil {
		t.Fatal(err)
	}
	mem := &events.Memory{}
	bus := events.NewBus("x-test", nil)
	bus.Add(mem)
	b := &broker.Broker{
		Exit:     &broker.Exit{Name: cfg.Name, Clients: cfg.BrokerClients()},
		Resolver: names{"echo.test": {net.ParseIP("127.0.0.1")}},
		Bus:      bus,
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go b.Serve(tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{kp}, MinVersion: tls.VersionTLS12}))
	t.Cleanup(func() { l.Close(); b.Shutdown(time.Second) })
	return l.Addr().String(), mem
}

// The exit and the client's path code, end to end in one process: the
// health check, the IDs, a refusal with its reason, both front ends, and a
// client that leaves from its own address.
func TestExitWithClientPath(t *testing.T) {
	source := "127.0.0.1"
	if runtime.GOOS == "linux" {
		source = "127.0.0.2"
	}
	dir := t.TempDir()
	src := `version = 1
name = "exit-test"
listen = "127.0.0.1:0"
cert = "c"
key = "k"

[clients.agent]
token_sha256 = "` + HashHex("token-agent") + `"
source = "` + source + `"
allow_exit_host = true
default = "deny"
allow = ["echo.test"]

[clients.guest]
token_sha256 = "` + HashHex("token-guest") + `"
source = "127.0.0.1"
default = "deny"
allow = ["echo.test"]
`
	addr, mem := testExit(t, dir, src)
	port, from := echo(t)
	os.WriteFile(filepath.Join(dir, "agent.token"), []byte("token-agent\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "wrong.token"), []byte("token-wrong\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "guest.token"), []byte("token-guest\n"), 0o600)
	ctx := context.Background()
	for _, scheme := range []string{"https", "socks5+tls"} {
		p, err := path.Build("exit", []string{scheme + "://" + addr}, path.Options{CAFile: "ca.pem", TokenFile: "agent.token", Dir: dir})
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Health(ctx); err != nil {
			t.Fatalf("%s health: %v", scheme, err)
		}
		ci := &path.Conn{Run: "r-test", ID: 5}
		c, err := p.Dial(path.WithConn(ctx, ci), "echo.test", nil, port)
		if err != nil {
			t.Fatalf("%s dial: %v", scheme, err)
		}
		io.WriteString(c, "hi\n")
		line, _ := bufio.NewReader(c).ReadString('\n')
		c.Close()
		if strings.TrimSpace(line) != "hello hi" || ci.Exit != addr {
			t.Errorf("%s: %q via %q", scheme, line, ci.Exit)
		}
		if got := <-from; got != source {
			t.Errorf("%s: the connection left from %s, not %s", scheme, got, source)
		}
		_, err = p.Dial(path.WithConn(ctx, &path.Conn{Run: "r-test", ID: 6}), "evil.test", nil, 443)
		want := "the exit refused it (default): no allow rule matches evil.test:443"
		if scheme != "https" {
			want = "connection not allowed"
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s refusal: %v", scheme, err)
		}
		wrong, _ := path.Build("exit", []string{scheme + "://" + addr}, path.Options{CAFile: "ca.pem", TokenFile: "wrong.token", Dir: dir})
		if err := wrong.Health(ctx); err == nil || !strings.Contains(err.Error(), "the exit refused the token") {
			t.Errorf("%s wrong token: %v", scheme, err)
		}
	}
	// Without allow_exit_host, the exit's own machine is out of reach, even
	// when the client's policy allows it: echo.test is on its loopback.
	guest, _ := path.Build("exit", []string{"https://" + addr}, path.Options{CAFile: "ca.pem", TokenFile: "guest.token", Dir: dir})
	if _, err := guest.Dial(path.WithConn(ctx, &path.Conn{Run: "r-guest", ID: 1}), "echo.test", nil, port); err == nil || !strings.Contains(err.Error(), "127.0.0.1 is the exit's own machine, which client guest may not reach (allow_exit_host)") {
		t.Errorf("guest reached the exit's machine: %v", err)
	}
	select {
	case got := <-from:
		t.Errorf("the echo server saw a connection from %s", got)
	default:
	}
	// A client that trusts another CA doesn't get as far as the token.
	other := t.TempDir()
	_, caPEM, _, _ := NewCA(time.Now())
	os.WriteFile(filepath.Join(other, "ca.pem"), caPEM, 0o644)
	p, _ := path.Build("exit", []string{"https://" + addr}, path.Options{CAFile: filepath.Join(other, "ca.pem"), TokenFile: filepath.Join(dir, "agent.token")})
	if err := p.Health(ctx); err == nil || !strings.Contains(err.Error(), "certificate not accepted") {
		t.Errorf("another CA: %v", err)
	}
	// The record: both connections, each with the client's IDs.
	var ids []string
	for _, e := range mem.Snapshot() {
		if e.Type == events.ConnectionAttempt {
			ids = append(ids, fmt.Sprintf("%v %v/%v %v", e.Fields["proto"], e.Fields["client_run"], e.Fields["client_conn"], e.Fields["host"]))
		}
	}
	if strings.Join(ids, ", ") != "http-connect r-test/5 echo.test, http-connect r-test/6 evil.test, socks5 r-test/5 echo.test, socks5 r-test/6 evil.test, http-connect r-guest/1 echo.test" {
		t.Errorf("record: %v", ids)
	}
}

// benchExit is an exit in this process with one client that may reach
// echo.test, and that client's path to it.
func benchExit(b *testing.B) (path.Path, int) {
	dir := b.TempDir()
	src := "version = 1\nlisten = \"127.0.0.1:0\"\ncert = \"c\"\nkey = \"k\"\n[clients.agent]\ntoken_sha256 = \"" + HashHex("token-agent") + "\"\nsource = \"127.0.0.1\"\nallow_exit_host = true\ndefault = \"deny\"\nallow = [\"echo.test\"]\n"
	addr, _ := testExit(b, dir, src)
	os.WriteFile(filepath.Join(dir, "agent.token"), []byte("token-agent\n"), 0o600)
	p, err := path.Build("exit", []string{"https://" + addr}, path.Options{CAFile: "ca.pem", TokenFile: "agent.token", Dir: dir})
	if err != nil {
		b.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(io.Discard, c)
				c.Write([]byte("ok"))
			}(c)
		}
	}()
	return p, l.Addr().(*net.TCPAddr).Port
}

// BenchmarkExitConnect opens one connection through an exit: TLS to the
// exit (resumed after the first, as vpnw does), the request with the token
// and IDs, the decision with the client's policy, and the dial.
func BenchmarkExitConnect(b *testing.B) {
	p, port := benchExit(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := p.Dial(path.WithConn(ctx, &path.Conn{Run: "r-bench", ID: uint64(i + 1)}), "echo.test", nil, port)
		if err != nil {
			b.Fatal(err)
		}
		c.Close()
	}
}

// BenchmarkExitThroughput sends data through an exit, both ends on this
// machine.
func BenchmarkExitThroughput(b *testing.B) {
	p, port := benchExit(b)
	buf := make([]byte, 1<<20)
	b.SetBytes(int64(len(buf)))
	c, err := p.Dial(path.WithConn(context.Background(), &path.Conn{Run: "r-bench", ID: 1}), "echo.test", nil, port)
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.Write(buf); err != nil {
			b.Fatal(err)
		}
	}
}
