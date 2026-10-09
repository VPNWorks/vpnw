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
