// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"net"
	"strings"
	"testing"
	"time"

	"vpnw.com/vpnw/internal/config"
	"vpnw.com/vpnw/internal/events"
	"vpnw.com/vpnw/internal/policy"
)

type trace struct {
	mem *events.Memory
	bus *events.Bus
	n   uint64
}

func newTrace(run string) *trace {
	m := &events.Memory{}
	b := events.NewBus(run, func() time.Time { return time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC) })
	b.Add(m)
	return &trace{mem: m, bus: b}
}

func (t *trace) conn(host string, port int, outcome string, up, down int64) {
	t.n++
	f := map[string]any{"port": port, "proto": "http-connect"}
	if net.ParseIP(host) != nil {
		f["ip"] = host
	} else {
		f["host"] = host
	}
	t.bus.Emit(events.ConnectionAttempt, 1, "direct", t.n, f)
	switch outcome {
	case "open":
		t.bus.Emit(events.ConnectionOpen, 1, "direct", t.n, map[string]any{"ms": 3})
		t.bus.Emit(events.ConnectionClose, 1, "direct", t.n, map[string]any{"bytes_up": up, "bytes_down": down, "ms": 20})
	case "deny":
		t.bus.Emit(events.PolicyDeny, 1, "direct", t.n, map[string]any{"rule": "default", "reason": "no allow rule matches"})
	case "error":
		t.bus.Emit(events.ConnectionError, 1, "direct", t.n, map[string]any{"error": "connection refused"})
	}
}

func TestLearn(t *testing.T) {
	tr := newTrace("r-1")
	tr.conn("api.github.com", 443, "open", 900, 20000)
	tr.conn("api.github.com", 443, "open", 800, 12000)
	tr.conn("pypi.org", 443, "open", 400, 9000)
	tr.conn("files.pythonhosted.org", 443, "open", 300, 400000)
	tr.conn("evil.example", 443, "deny", 0, 0)
	tr.conn("203.0.113.7", 8443, "open", 50000, 100)
	tr.conn("down.example", 443, "error", 0, 0)
	res := FromEvents(tr.mem.Snapshot(), Options{Name: "agent"})

	if strings.Join(res.Allowed, ",") != "api.github.com,pypi.org,files.pythonhosted.org,203.0.113.7" {
		t.Errorf("allowed order: %v", res.Allowed)
	}
	if len(res.Denied) != 1 || res.Denied[0] != "evil.example" {
		t.Errorf("denied: %v", res.Denied)
	}
	if len(res.FlaggedIPs) != 1 || len(res.FlaggedHeavy) != 1 {
		t.Errorf("flags: %v %v", res.FlaggedIPs, res.FlaggedHeavy)
	}
	for _, want := range []string{`"api.github.com",`, "2 connections, port 443", `#   "evil.example"`, "raw IP address", "sent 50.0 KB"} {
		if !strings.Contains(res.TOML, want) {
			t.Errorf("TOML lacks %q:\n%s", want, res.TOML)
		}
	}
	if len(res.Unreached) != 1 || res.Unreached[0] != "down.example" {
		t.Errorf("unreached: %v", res.Unreached)
	}
	if !strings.Contains(res.TOML, `#   "down.example"  (connection refused)`) {
		t.Errorf("an unreached destination should be listed in a comment:\n%s", res.TOML)
	}

	// The output must be a valid policy that allows exactly what opened.
	f, err := config.ParseFile("learned.toml", res.TOML)
	if err != nil {
		t.Fatalf("learned policy does not parse: %v\n%s", err, res.TOML)
	}
	p, err := policy.New(f.Policy, f.Name)
	if err != nil {
		t.Fatal(err)
	}
	check := func(host string, port int, want bool) {
		tg := policy.Target{Host: host, Port: port}
		if ip := net.ParseIP(host); ip != nil {
			tg = policy.Target{IP: ip, Port: port}
		}
		var addrs []net.IP
		if tg.Host != "" {
			addrs = []net.IP{net.ParseIP("140.82.121.6")}
		}
		if got := p.Decide(tg, addrs).Allow; got != want {
			t.Errorf("%s:%d allow=%v, want %v", host, port, got, want)
		}
	}
	check("api.github.com", 443, true)
	check("files.pythonhosted.org", 443, true)
	check("203.0.113.7", 8443, false) // documentation range: deny_private wins
	check("evil.example", 443, false)
	check("down.example", 443, false)
}

func TestLearnPortsAndWildcards(t *testing.T) {
	tr := newTrace("r-2")
	for _, h := range []string{"a.cdn.example.com", "b.cdn.example.com", "c.cdn.example.com"} {
		tr.conn(h, 443, "open", 10, 10)
	}
	tr.conn("db.example.com", 5432, "open", 10, 10)
	res := FromEvents(tr.mem.Snapshot(), Options{Ports: true, Wildcards: true})
	if !strings.Contains(res.TOML, `"*.cdn.example.com"`) || !strings.Contains(res.TOML, `"db.example.com:5432"`) {
		t.Errorf("unexpected:\n%s", res.TOML)
	}
	if _, err := config.ParseFile("x", res.TOML); err != nil {
		t.Errorf("does not parse: %v", err)
	}
}

func TestLearnEmpty(t *testing.T) {
	res := FromEvents(nil, Options{})
	f, err := config.ParseFile("x", res.TOML)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := policy.New(f.Policy, "x")
	if p.Default != policy.Deny {
		t.Error("an empty learned policy must deny everything")
	}
}
