// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"vpnw.com/vpnw/internal/config"
	"vpnw.com/vpnw/internal/events"
	"vpnw.com/vpnw/internal/path"
	"vpnw.com/vpnw/internal/plan"
	"vpnw.com/vpnw/internal/policy"
)

// exitPath stands in for a proxy that resolves names at its exit: every
// connection lands on the echo server.
type exitPath struct{ port int }

func (exitPath) ID() string       { return "office" }
func (exitPath) Kind() string     { return "socks5" }
func (exitPath) RemoteDNS() bool  { return true }
func (exitPath) Describe() string { return "test exit" }
func (e exitPath) Dial(ctx context.Context, host string, ip net.IP, port int) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", "127.0.0.1:"+strconv.Itoa(e.port))
}
func (exitPath) Health(context.Context) error { return nil }

// observed is what the real broker did with one request, read from its events.
type observed struct {
	outcome  string // denied, dial, failed
	rule     string
	lookedUp bool
}

func runBroker(t *testing.T, pol *policy.Policy, p path.Path, dns *fakeDNS, target string) observed {
	t.Helper()
	mem := &events.Memory{}
	bus := events.NewBus("r-plan", nil)
	bus.Add(mem)
	b := &Broker{Policy: pol, Path: p, Resolver: dns, Bus: bus, DialTimeout: 2 * time.Second}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go b.Serve(l)
	c, _ := connect(t, l.Addr().String(), target, "")
	c.Close()
	deadline := time.Now().Add(2 * time.Second)
	var o observed
	for time.Now().Before(deadline) {
		o = observed{}
		done := false
		for _, e := range mem.Snapshot() {
			switch e.Type {
			case events.DNSQuery:
				o.lookedUp = true
			case events.PolicyDeny:
				o.outcome, o.rule, done = "denied", e.Str("rule"), true
			case events.PolicyAllow:
				o.rule = e.Str("rule")
			case events.ConnectionOpen:
				o.outcome, done = "dial", true
			case events.ConnectionError:
				if o.outcome == "" {
					o.outcome, done = "failed", true
				}
			}
		}
		if done {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	l.Close()
	b.Shutdown(time.Second)
	return o
}

func TestPlanMatchesBroker(t *testing.T) {
	port, _ := echoServer(t)
	dnsMap := map[string][]net.IP{
		"echo.test":     {net.ParseIP("127.0.0.1")},
		"api.echo.test": {net.ParseIP("127.0.0.1")},
		"public.test":   {net.ParseIP("127.0.0.1")},
	}
	policies := map[string]*config.PolicySpec{
		"none":                  nil,
		"allow-list":            {Default: "deny", Allow: []string{"echo.test", "missing.test"}},
		"allow-list+private":    {Default: "deny", DenyPrivate: true, Allow: []string{"echo.test", "missing.test"}},
		"default-allow+private": {Default: "allow", DenyPrivate: true},
		"deny-name":             {Default: "allow", Deny: []string{"echo.test"}},
		"deny-range":            {Default: "allow", Deny: []string{"127.0.0.0/8"}},
		"wildcard":              {Default: "deny", Allow: []string{"*.echo.test"}},
		"address-allow":         {Default: "deny", Allow: []string{"127.0.0.1"}},
		"port-rule":             {Default: "deny", Allow: []string{fmt.Sprintf("echo.test:%d", port)}},
	}
	hosts := []string{"echo.test", "api.echo.test", "missing.test", "127.0.0.1", "public.test", "bad..name", "2130706433"}
	n := 0
	for pname, spec := range policies {
		var pol *policy.Policy
		if spec != nil {
			var err error
			if pol, err = policy.New(spec, pname); err != nil {
				t.Fatal(err)
			}
		}
		for _, remote := range []bool{false, true} {
			if remote && pol != nil && pol.CheckRemoteDNS("office") != nil {
				continue // the CLI refuses this combination before any request
			}
			for _, h := range hosts {
				target := net.JoinHostPort(h, strconv.Itoa(port))
				dns := &fakeDNS{m: dnsMap}
				var p path.Path = &path.Direct{}
				if remote {
					p = exitPath{port: port}
				}
				got := runBroker(t, pol, p, dns, target)
				pl := plan.Request(pol, h, port, remote, func(host string) ([]net.IP, error) {
					return (&fakeDNS{m: dnsMap}).LookupIP(context.Background(), host)
				})
				want := observed{outcome: pl.Outcome, rule: pl.Rule, lookedUp: pl.LookedUp}
				if got != want {
					t.Errorf("policy %s, remote %v, %s: broker did %+v, plan says %+v (%s %s)",
						pname, remote, h, got, want, pl.Reason, pl.Error)
				}
				n++
			}
		}
	}
	if n < 100 {
		t.Errorf("only %d cases compared", n)
	}
}
