// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package budget

import (
	"fmt"
	"strings"
	"testing"

	"github.com/VPNWorks/vpnw/plugins/sdk"
)

func mustParse(t *testing.T, s map[string]string) *Rules {
	t.Helper()
	r, err := Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"500": 500, "10MB": 10_000_000, "10 mb": 10_000_000, "1.5GiB": 1610612736, "2KiB": 2048, "0": 0, "none": 0, "1B": 1, "3tb": 3e12} {
		got, err := ParseSize(in)
		if err != nil || got != want {
			t.Errorf("%q: %d %v, want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "MB", "-1", "1XB", "0.1", "1e3", "1..2MB", "99999999999TiB"} {
		if _, err := ParseSize(in); err == nil {
			t.Errorf("%q: no error", in)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, c := range []struct {
		s    map[string]string
		want string
	}{
		{map[string]string{}, "budget needs the hosts to allow"},
		{map[string]string{"allow": " ; ; "}, "lists no hosts"},
		{map[string]string{"allow": "a.example", "limit": "1"}, `no setting "limit"`},
		{map[string]string{"allow": "a.example", "up": "lots"}, "budget.up"},
		{map[string]string{"allow": "a.example up=1MB down"}, `"down" after a.example`},
		{map[string]string{"allow": "a.example rate=5"}, `"rate" is not up, down or requests`},
		{map[string]string{"allow": "a.example requests=-2"}, "not a number of connections"},
		{map[string]string{"allow": "up=1MB"}, "give the host first"},
		{map[string]string{"allow": "a.example; A.example."}, "listed twice"},
		{map[string]string{"allow": "a..example"}, "is not a host"},
		{map[string]string{"allow": "*.-"}, "not a domain pattern"},
		{map[string]string{"allow": "http://a.example"}, "is not a host"},
		{map[string]string{"allow": "*.a..b"}, "not a domain pattern"},
	} {
		_, err := Parse(c.s)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v, want %q", c.s, err, c.want)
		}
	}
}

func req(host string) *sdk.Request {
	return &sdk.Request{Run: "r", Conn: 1, Path: "direct", Host: host, Port: 443, Proto: "http-connect"}
}

// Hosts on the list get their entry's budget; patterns cover only the
// names under them and share one budget; the rest are refused.
func TestDecide(t *testing.T) {
	r := mustParse(t, map[string]string{
		"allow": "api.github.com up=1MB requests=2; *.npmjs.org down=500MB; 10.0.0.7; *.deep.npmjs.org up=5KB",
		"up":    "10MB",
	})
	d := r.Decide(req("api.github.com"))
	if d.Deny || d.Budget == nil || *d.Budget != (sdk.Budget{Key: "api.github.com", Up: 1e6, Reason: "budget for api.github.com: 1 MB up, 2 connections"}) {
		t.Fatalf("github: %+v %+v", d, d.Budget)
	}
	d = r.Decide(req("registry.npmjs.org"))
	if d.Deny || d.Budget.Key != "*.npmjs.org" || d.Budget.Up != 10e6 || d.Budget.Down != 500e6 {
		t.Fatalf("npm: %+v %+v", d, d.Budget)
	}
	// Another name under the pattern counts against the same budget.
	if d := r.Decide(req("evil.npmjs.org")); d.Budget.Key != "*.npmjs.org" {
		t.Fatalf("subdomain: %+v", d.Budget)
	}
	// The longer pattern wins.
	if d := r.Decide(req("x.deep.npmjs.org")); d.Budget.Key != "*.deep.npmjs.org" || d.Budget.Up != 5000 {
		t.Fatalf("deep: %+v", d.Budget)
	}
	for _, h := range []string{"npmjs.org", "github.com", "api.github.com.evil.example", "xnpmjs.org"} {
		if d := r.Decide(req(h)); !d.Deny || d.Reason != h+" is not on the budget allowlist" {
			t.Errorf("%s: %+v", h, d)
		}
	}
	// An address, asked for directly or as a name.
	if d := r.Decide(&sdk.Request{IP: "10.0.0.7", Port: 22}); d.Deny || d.Budget.Key != "10.0.0.7" {
		t.Errorf("ip: %+v", d)
	}
	if d := r.Decide(&sdk.Request{IP: "10.0.0.8", Port: 22}); !d.Deny {
		t.Errorf("other ip: %+v", d)
	}
	// Requests: two for github, then refused.
	if d := r.Decide(req("API.GitHub.com.")); d.Deny {
		t.Fatalf("second: %+v", d)
	}
	if d := r.Decide(req("api.github.com")); !d.Deny || d.Reason != "request budget spent: 2 connections (budget for api.github.com: 1 MB up, 2 connections)" {
		t.Fatalf("third: %+v", d)
	}
}

// With *, each host has its own budget; with no limits at all, no budget is
// put on the connection.
func TestAnyHost(t *testing.T) {
	r := mustParse(t, map[string]string{"allow": "*", "up": "1KiB"})
	a, b := r.Decide(req("a.example")), r.Decide(req("b.example"))
	if a.Budget.Key == b.Budget.Key || a.Budget.Key != "* a.example" || a.Budget.Up != 1024 {
		t.Fatalf("%+v %+v", a.Budget, b.Budget)
	}
	if d := mustParse(t, map[string]string{"allow": "*"}).Decide(req("a.example")); d.Deny || d.Budget != nil {
		t.Fatalf("no limits: %+v", d)
	}
	// An entry can lift a default.
	r = mustParse(t, map[string]string{"allow": "big.example up=none; small.example", "up": "1KB"})
	if d := r.Decide(req("big.example")); d.Budget != nil {
		t.Fatalf("big: %+v", d.Budget)
	}
	long := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + ".example"
	if d := mustParse(t, map[string]string{"allow": "*", "up": "1KB"}).Decide(req(long)); len(d.Budget.Key) > 128 {
		t.Fatalf("long key %d", len(d.Budget.Key))
	}
}

// At an exit each client has budgets of its own.
func TestClients(t *testing.T) {
	r := mustParse(t, map[string]string{"allow": "api.example up=1MB requests=1"})
	q := req("api.example")
	q.Client = "agent-1"
	d := r.Decide(q)
	if d.Budget.Key != "agent-1 api.example" || !strings.Contains(d.Budget.Reason, "client agent-1") {
		t.Fatalf("%+v", d.Budget)
	}
	if d := r.Decide(q); !d.Deny {
		t.Fatalf("agent-1 again: %+v", d)
	}
	q.Client = "agent-2"
	if d := r.Decide(q); d.Deny {
		t.Fatalf("agent-2: %+v", d)
	}
}

func TestFormatSize(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 500: "500 B", 1000: "1 KB", 1024: "1 KiB", 10e6: "10 MB", 1610612736: "1536 MiB", 1500: "1500 B"} {
		if got := FormatSize(n); got != want {
			t.Errorf("%d: %q, want %q", n, got, want)
		}
	}
}

// Through the SDK, as vpnw calls it.
func TestPlugin(t *testing.T) {
	sdk.Register(Plugin())
	if err := sdk.CallInit([]byte(`{"plugin":"budget","command":"guard","settings":{"allow":"a.example up=2KB"}}`)); err != nil {
		t.Fatal(err)
	}
	d, err := sdk.CallDecision([]byte(`{"run":"r","conn":1,"path":"direct","host":"a.example","port":443,"proto":"http-connect"}`))
	if err != nil || d.Deny || d.Budget == nil || d.Budget.Up != 2000 {
		t.Fatalf("%+v %v", d, err)
	}
	if err := sdk.CallInit([]byte(`{"plugin":"budget","command":"guard","settings":{"allow":"a.example","speed":"1"}}`)); err == nil {
		t.Fatal("unknown setting taken")
	}
}

// At an exit, one client filling its request counters leaves the others
// theirs.
func TestCountersPerClient(t *testing.T) {
	r := mustParse(t, map[string]string{"allow": "*", "requests": "5"})
	q := req("")
	q.Client = "greedy"
	for i := 0; i < MaxCounters; i++ {
		q.Host = fmt.Sprintf("h%d.example", i)
		if d := r.Decide(q); d.Deny {
			t.Fatalf("%d: %+v", i, d)
		}
	}
	q.Host = "one-more.example"
	if d := r.Decide(q); !d.Deny {
		t.Fatal("greedy got past the limit")
	}
	q.Client = "other"
	if d := r.Decide(q); d.Deny {
		t.Fatalf("other: %+v", d)
	}
}

// Asked before the lookup, Budget refuses what it would refuse and counts
// nothing.
func TestLookupStage(t *testing.T) {
	r := mustParse(t, map[string]string{"allow": "a.example up=1KB requests=1"})
	q := req("b.example")
	q.Stage = "lookup"
	if d := r.Decide(q); !d.Deny {
		t.Fatalf("unlisted at lookup: %+v", d)
	}
	q.Host = "a.example"
	for i := 0; i < 3; i++ {
		if d := r.Decide(q); d.Deny || d.Budget != nil {
			t.Fatalf("listed at lookup: %+v", d)
		}
	}
	if d := r.Decide(req("a.example")); d.Deny || d.Budget == nil {
		t.Fatalf("the decision: %+v", d)
	}
	if d := r.Decide(q); !d.Deny {
		t.Fatal("at lookup once the requests are spent")
	}
}
