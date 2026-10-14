// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/VPNWorks/vpnw/internal/events"
)

func TestTextLevels(t *testing.T) {
	var all, dec bytes.Buffer
	b := events.NewBus("r-1", nil)
	b.Add(NewText(&all, All))
	b.Add(NewText(&dec, Decisions))
	b.Emit(events.ConnectionAttempt, 1, "direct", 1, map[string]any{"host": "a.example", "port": 443, "proto": "http-connect"})
	b.Emit(events.PolicyAllow, 1, "direct", 1, map[string]any{"rule": "allow[0]", "text": "a.example", "reason": "x"})
	b.Emit(events.ConnectionAttempt, 1, "direct", 2, map[string]any{"host": "b.example", "port": 443, "proto": "http-connect"})
	b.Emit(events.PolicyDeny, 1, "direct", 2, map[string]any{"rule": "default", "reason": "no allow rule matches b.example:443"})
	if strings.Count(all.String(), "\n") != 4 {
		t.Errorf("all:\n%s", all.String())
	}
	if strings.Count(dec.String(), "\n") != 1 || !strings.Contains(dec.String(), "DENY") || !strings.Contains(dec.String(), "b.example:443") {
		t.Errorf("decisions:\n%s", dec.String())
	}
}

// A switch between exits is a decision-level line; an open through an exit
// names it.
func TestTextExits(t *testing.T) {
	var all, dec bytes.Buffer
	b := events.NewBus("r-1", nil)
	b.Add(NewText(&all, All))
	b.Add(NewText(&dec, Decisions))
	b.Emit(events.ConnectionAttempt, 1, "exits", 4, map[string]any{"host": "api.partner.test", "port": 443, "proto": "http-connect"})
	b.Emit(events.PathSwitch, 1, "exits", 4, map[string]any{"from": "198.51.100.2:8443", "to": "203.0.113.2:8443", "error": "proxy 198.51.100.2:8443: connection refused", "ms": 1})
	b.Emit(events.ConnectionOpen, 1, "exits", 4, map[string]any{"host": "api.partner.test", "ms": 9, "exit": "203.0.113.2:8443"})
	want := "switch  exit 198.51.100.2:8443 stopped answering after 1 ms (proxy 198.51.100.2:8443: connection refused); moving to 203.0.113.2:8443"
	if !strings.Contains(dec.String(), want) || strings.Count(dec.String(), "\n") != 1 {
		t.Errorf("decisions:\n%s", dec.String())
	}
	if !strings.Contains(all.String(), "open  exit resolves api.partner.test via exits (exit 203.0.113.2:8443)  (9 ms)") {
		t.Errorf("all:\n%s", all.String())
	}
	found := false
	for _, typ := range events.Types {
		found = found || typ == events.PathSwitch
	}
	if !found {
		t.Error("path.switch is missing from events.Types")
	}
}

// Every event type renders as one line at the all level, and the levels
// drop what they should.
func TestEveryType(t *testing.T) {
	var all, dec, quiet bytes.Buffer
	b := events.NewBus("r-1", nil)
	b.Add(NewText(&all, All))
	b.Add(NewText(&dec, Decisions))
	b.Add(NewText(&quiet, Quiet))
	b.Emit(events.RunStart, 0, "office", 0, map[string]any{"mode": "guard", "backend": "sealed",
		"policy": map[string]any{"name": "p", "default": "deny", "allow_rules": 2, "deny_rules": 0, "deny_private": true}})
	b.Emit(events.ProcessStart, 7, "office", 0, map[string]any{"cmd": "curl"})
	b.Emit(events.ConnectionAttempt, 7, "office", 1, map[string]any{"ip": "2001:db8::1", "port": 443, "proto": "socks5"})
	b.Emit(events.DNSQuery, 7, "office", 2, map[string]any{"host": "a.example"})
	b.Emit(events.DNSResult, 7, "office", 2, map[string]any{"host": "a.example", "ips": []string{"192.0.2.1"}, "ms": 3})
	b.Emit(events.DNSResult, 7, "office", 3, map[string]any{"host": "b.example", "error": "no such host"})
	b.Emit(events.PolicyAllow, 7, "office", 1, map[string]any{"rule": "default"})
	b.Emit(events.ConnectionOpen, 7, "office", 1, map[string]any{"host": "a.example", "ms": 4})
	b.Emit(events.ConnectionClose, 7, "office", 1, map[string]any{"bytes_up": 1200, "bytes_down": 3e6, "ms": 1500})
	b.Emit(events.ConnectionError, 7, "office", 4, map[string]any{"error": "connection refused"})
	b.Emit(events.PluginError, 0, "", 0, map[string]any{"plugin": "geo", "type": "guard", "error": "panic: boom"})
	b.Emit("plugin.geo.note", 7, "office", 1, map[string]any{"country": "NL", "n": 2})
	b.Emit(events.ProcessExit, 7, "office", 0, map[string]any{"code": 0, "signal": "SIGTERM", "ms": 61000})
	b.Emit(events.RunEnd, 0, "office", 0, map[string]any{"connections": 1, "opened": 1})
	for _, want := range []string{
		"guard  run r-1  path office  backend sealed  policy p (default deny, 2 allow rules, 0 deny rules, deny_private true)",
		"start  pid 7  curl", "→ [2001:db8::1]:443", "dns a.example = 192.0.2.1  (3 ms)", "dns b.example failed: no such host",
		"allow  [2001:db8::1]:443  default allow", "open  exit resolves a.example via office", "close  sent 1.2 KB  received 3.0 MB",
		"#4     error  : connection refused", "guard plugin geo stopped: panic: boom", "#1     plugin.geo.note  country=NL n=2",
		"killed by SIGTERM", "summary  1 connection: 1 opened",
	} {
		if !strings.Contains(all.String(), want) {
			t.Errorf("all lacks %q:\n%s", want, all.String())
		}
	}
	if strings.Contains(dec.String(), "plugin.geo.note") || !strings.Contains(dec.String(), "stopped: panic: boom") {
		t.Errorf("decisions:\n%s", dec.String())
	}
	if strings.Count(quiet.String(), "\n") != 1 {
		t.Errorf("quiet prints the summary only:\n%s", quiet.String())
	}
}

// At an exit, every line of a connection names the client, an open says
// where it left from, and a request without a valid token is a decision.
func TestTextExitServer(t *testing.T) {
	var all, dec bytes.Buffer
	b := events.NewBus("x-1", nil)
	b.Add(NewText(&all, All))
	b.Add(NewText(&dec, Decisions))
	b.Emit(events.RunStart, 0, "", 0, map[string]any{"mode": "exit", "exit": "exit-de", "listen": "198.51.100.2:8443", "clients": 2, "cert_for": "198.51.100.2", "cert_until": "2028-10-14"})
	b.Emit(events.ConnectionAttempt, 0, "direct", 1, map[string]any{"host": "api.partner.test", "port": 443, "proto": "http-connect", "client": "agent-1", "client_run": "r-3f9a1c", "client_conn": uint64(17), "source": "198.51.100.10", "peer": "192.0.2.7:51234"})
	b.Emit(events.ConnectionOpen, 0, "direct", 1, map[string]any{"ip": "51.15.0.10", "host": "api.partner.test", "ms": 3, "source": "198.51.100.10"})
	b.Emit(events.ConnectionAttempt, 0, "direct", 2, map[string]any{"ip": "169.254.169.254", "port": 80, "proto": "socks5", "client": "agent-1"})
	b.Emit(events.PolicyDeny, 0, "direct", 2, map[string]any{"rule": "deny_private", "reason": "169.254.169.254: link-local address"})
	b.Emit(events.AuthDeny, 0, "", 0, map[string]any{"peer": "203.0.113.9:40000", "proto": "http-connect", "reason": "the token is not known here", "host": "api.partner.test", "port": 443})
	b.Emit(events.RunEnd, 0, "", 0, map[string]any{"connections": 2, "opened": 1, "denied": 1, "failed": 0, "bytes_up": 10, "bytes_down": 20, "auth_denied": 1})
	for _, want := range []string{
		"exit exit-de  run x-1  listening on 198.51.100.2:8443  2 clients  certificate for 198.51.100.2 until 2028-10-14",
		"#2     DENY   agent-1 → 169.254.169.254:80  169.254.169.254: link-local address",
		"REFUSED  203.0.113.9:40000  http-connect  the token is not known here  (asked for api.partner.test:443)",
		"summary  2 connections: 1 opened, 1 denied, 0 failed  sent 10 B  received 20 B  1 request without a valid token",
	} {
		if !strings.Contains(dec.String(), want) {
			t.Errorf("decisions lack %q:\n%s", want, dec.String())
		}
	}
	for _, want := range []string{
		"#1   agent-1 → api.partner.test:443  http-connect  its run r-3f9a1c #17",
		"#1     open  51.15.0.10 from 198.51.100.10  (3 ms)",
	} {
		if !strings.Contains(all.String(), want) {
			t.Errorf("all lacks %q:\n%s", want, all.String())
		}
	}
}

// The console forgets a connection after its last event, so an exit that
// serves for months doesn't pile up every connection it has seen.
func TestTextForgets(t *testing.T) {
	var buf bytes.Buffer
	x := NewText(&buf, All)
	b := events.NewBus("x-1", nil)
	b.Add(x)
	for i := uint64(1); i <= 300; i++ {
		b.Emit(events.ConnectionAttempt, 0, "direct", i, map[string]any{"host": "a.example", "port": 443, "proto": "http-connect"})
		switch i % 3 {
		case 0:
			b.Emit(events.ConnectionClose, 0, "direct", i, map[string]any{"bytes_up": 1, "bytes_down": 1, "ms": 1})
		case 1:
			b.Emit(events.ConnectionError, 0, "direct", i, map[string]any{"error": "refused"})
		case 2:
			b.Emit(events.PolicyDeny, 0, "direct", i, map[string]any{"rule": "default", "reason": "no"})
		}
	}
	if len(x.hosts) != 0 {
		t.Errorf("the console still holds %d connections", len(x.hosts))
	}
	if !strings.Contains(buf.String(), "#298   error  a.example:443: refused") || !strings.Contains(buf.String(), "#299   DENY   a.example:443  no") {
		t.Errorf("the lines lost their hosts:\n%s", buf.String()[len(buf.String())-300:])
	}
}

// A run through a tunnel plugin: what it started with, each move, and each
// tunnel that closed, and why.
func TestTextTunnels(t *testing.T) {
	var all, dec bytes.Buffer
	b := events.NewBus("r-1", nil)
	b.Add(NewText(&all, All))
	b.Add(NewText(&dec, Decisions))
	b.Emit(events.RunStart, 0, "rotate", 0, map[string]any{"mode": "trace", "backend": "sealed",
		"tunnel": map[string]any{"plugin": "rotate", "config": "b.conf", "keep": 600,
			"skipped": []any{map[string]any{"config": "a.conf", "error": "line 3: PostUp is a wg-quick shell hook"}}}})
	b.Emit(events.ConnectionOpen, 7, "rotate", 1, map[string]any{"ip": "93.184.215.14", "ms": 4, "tunnel": "b.conf", "exit": "198.51.100.7:51820"})
	b.Emit(events.TunnelSwitch, 0, "rotate", 0, map[string]any{"from": "b.conf", "to": "c.conf", "why": "due", "ms": 40, "peer": "203.0.113.9:51820"})
	b.Emit(events.TunnelSwitch, 0, "rotate", 0, map[string]any{"from": "c.conf", "to": "b.conf", "why": "failed", "error": "nothing came back through it for 20s", "ms": 0, "again": true, "peer": "198.51.100.7:51820"})
	b.Emit(events.TunnelError, 0, "rotate", 0, map[string]any{"config": "d.conf", "error": "no WireGuard handshake from 192.0.2.4:51820 within 12s"})
	b.Emit(events.TunnelError, 0, "rotate", 0, map[string]any{"error": "the plugin has no other config; b.conf stays in use"})
	b.Emit(events.TunnelClose, 0, "rotate", 0, map[string]any{"config": "c.conf", "why": "drained"})
	b.Emit(events.TunnelClose, 0, "rotate", 0, map[string]any{"config": "e.conf", "why": "limit", "cut": 2})
	b.Emit(events.TunnelClose, 0, "rotate", 0, map[string]any{"config": "f.conf", "why": "replaced", "by": "f2.conf", "cut": 1})
	for _, want := range []string{
		"trace  run r-1  path rotate  tunnel b.conf from rotate, kept 10m",
		"tunnel  skipped a.conf: line 3: PostUp is a wg-quick shell hook",
		"open  93.184.215.14 via rotate (b.conf, exit 198.51.100.7:51820)",
		"tunnel  rotated from b.conf to c.conf up in 40 ms (peer 203.0.113.9:51820)",
		"tunnel  c.conf stopped answering (nothing came back through it for 20s); moved back to b.conf, whose tunnel was still up (peer 198.51.100.7:51820)",
		"tunnel  d.conf not used: no WireGuard handshake from 192.0.2.4:51820 within 12s",
		"tunnel  the plugin has no other config; b.conf stays in use",
		"tunnel  c.conf closed after its last connection",
		"tunnel  e.conf closed with 2 connections still open: too many tunnels were winding down",
		"tunnel  f.conf closed with 1 connection still open: the new tunnel of f2.conf has the same key and peer",
	} {
		if !strings.Contains(all.String(), want) {
			t.Errorf("all lacks %q:\n%s", want, all.String())
		}
	}
	if strings.Contains(dec.String(), "closed") || !strings.Contains(dec.String(), "stopped answering") {
		t.Errorf("decisions:\n%s", dec.String())
	}
}
