// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"vpnw.com/vpnw/internal/broker"
	"vpnw.com/vpnw/internal/config"
	"vpnw.com/vpnw/internal/events"
	"vpnw.com/vpnw/internal/exit"
	"vpnw.com/vpnw/internal/policy"
)

// The same requests, decided by the Agent's broker and by the exit, with
// the same policy and the same answers from DNS: names, wildcards at several
// depths, addresses, ranges, ports, deny rules, deny_private, default allow
// and deny, names that do not resolve, and names the policy engine refuses.

var diffDNS = map[string][]net.IP{
	"api.partner.test":      {net.ParseIP("51.15.0.10")},
	"www.partner.test":      {net.ParseIP("51.15.0.11")},
	"deep.a.partner.test":   {net.ParseIP("51.15.0.12")},
	"partner.test":          {net.ParseIP("51.15.0.13")},
	"intranet.partner.test": {net.ParseIP("10.50.0.5")},
	"mixed.partner.test":    {net.ParseIP("51.15.0.14"), net.ParseIP("192.168.1.20")},
	"meta.partner.test":     {net.ParseIP("169.254.169.254")},
	"nat64.partner.test":    {net.ParseIP("64:ff9b::a00:1")},
	"loop.test":             {net.ParseIP("127.0.0.1")},
	"public.test":           {net.ParseIP("93.184.215.14")},
	"evil.test":             {net.ParseIP("66.66.0.66")},
	"evilpartner.test":      {net.ParseIP("66.66.0.67")},
}

var diffHosts = []string{
	"api.partner.test", "www.partner.test", "deep.a.partner.test", "partner.test", "intranet.partner.test",
	"mixed.partner.test", "meta.partner.test", "nat64.partner.test", "loop.test", "public.test", "evil.test",
	"evilpartner.test", "missing.partner.test", "API.Partner.Test", "api.partner.test.", "bad..name", "2130706433",
	"0x7f.1", "51.15.0.10", "51.15.0.99", "10.50.0.5", "169.254.169.254", "127.0.0.1", "66.66.0.66",
	"::1", "::ffff:10.0.0.1", "2606:4700::1111",
}

var diffPolicies = []struct {
	name string
	spec config.PolicySpec
}{
	{"allow list", config.PolicySpec{Default: "deny", Allow: []string{"api.partner.test", "*.partner.test"}}},
	{"allow list, deny_private", config.PolicySpec{Default: "deny", DenyPrivate: true, Allow: []string{"api.partner.test", "*.partner.test"}}},
	{"default allow, deny_private", config.PolicySpec{Default: "allow", DenyPrivate: true}},
	{"default allow", config.PolicySpec{Default: "allow"}},
	{"deny names", config.PolicySpec{Default: "allow", Deny: []string{"evil.test", "*.partner.test"}}},
	{"deny ranges", config.PolicySpec{Default: "allow", Deny: []string{"51.15.0.0/24", "169.254.0.0/16", "::1"}}},
	{"address allow", config.PolicySpec{Default: "deny", Allow: []string{"51.15.0.10", "66.66.0.0/16", "2606:4700::/32"}}},
	{"ports", config.PolicySpec{Default: "deny", Allow: []string{"api.partner.test:443", "*.partner.test:8080", "51.15.0.0/24:443"}}},
	{"implied deny", config.PolicySpec{Allow: []string{"public.test", "evil.test:8080"}}},
	{"mixed", config.PolicySpec{Default: "deny", DenyPrivate: true, Allow: []string{"*.partner.test", "public.test", "51.15.0.0/24"},
		Deny: []string{"www.partner.test", "51.15.0.11"}}},
	{"implied allow, deny_private", config.PolicySpec{DenyPrivate: true, Deny: []string{"evil.test"}}},
}

// exitTOML writes an exit configuration with one client, "c", whose policy
// is spec, written in its table.
func exitTOML(spec config.PolicySpec, token string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "version = 1\nlisten = \"127.0.0.1:0\"\ncert = \"c\"\nkey = \"k\"\n[clients.c]\ntoken_sha256 = %q\nsource = \"127.0.0.2\"\n", exit.HashHex(token))
	if spec.Default != "" {
		fmt.Fprintf(&b, "default = %q\n", spec.Default)
	}
	fmt.Fprintf(&b, "deny_private = %v\n", spec.DenyPrivate)
	list := func(k string, l []string) {
		if len(l) == 0 {
			return
		}
		q := make([]string, len(l))
		for i, s := range l {
			q[i] = strconv.Quote(s)
		}
		fmt.Fprintf(&b, "%s = [%s]\n", k, strings.Join(q, ", "))
	}
	list("allow", spec.Allow)
	list("deny", spec.Deny)
	return b.String()
}

// recPath is a local-DNS path for the broker that records dials and fails.
type recPath struct {
	mu    sync.Mutex
	dials []string
}

func (*recPath) ID() string       { return "rec" }
func (*recPath) Kind() string     { return "direct" }
func (*recPath) RemoteDNS() bool  { return false }
func (*recPath) Describe() string { return "records dials" }
func (r *recPath) Dial(_ context.Context, host string, ip net.IP, port int) (net.Conn, error) {
	r.mu.Lock()
	r.dials = append(r.dials, ip.String())
	r.mu.Unlock()
	return nil, errors.New("not dialing in this test")
}
func (*recPath) Health(context.Context) error { return nil }

type step struct{ typ, detail string }

// steps reads one request's record: each event's type with what decides
// it, leaving out timings and the errors of dials that this test fails.
func steps(evs []events.Event) []step {
	var out []step
	for _, e := range evs {
		var d string
		switch e.Type {
		case events.ConnectionAttempt:
			d = fmt.Sprintf("%s %s %d", e.Str("host"), e.Str("ip"), e.Int("port"))
		case events.DNSQuery:
			d = e.Str("host")
		case events.DNSResult:
			d = fmt.Sprint(e.Fields["ips"], e.Str("error"))
		case events.PolicyAllow, events.PolicyDeny:
			d = e.Str("rule") + " | " + e.Str("text") + " | " + e.Str("reason")
		case events.ConnectionError:
			if strings.HasPrefix(e.Str("error"), "dns: ") || e.Str("error") == "port out of range" {
				d = e.Str("error")
			}
		default:
			continue
		}
		out = append(out, step{e.Type, d})
	}
	return out
}

// ask sends one CONNECT through handle on an in-memory connection and waits
// until the handler is done.
func ask(handle func(net.Conn), req string) {
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() { handle(b); close(done) }()
	a.SetDeadline(time.Now().Add(10 * time.Second))
	go io.WriteString(a, req)
	io.ReadAll(a)
	a.Close()
	<-done
}

func TestExitDecidesAsTheAgent(t *testing.T) {
	compared, allowed, denied, failed := 0, 0, 0, 0
	lookup := func(h string) ([]net.IP, error) {
		if ips, ok := diffDNS[h]; ok {
			return ips, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: h, IsNotFound: true}
	}
	for _, p := range diffPolicies {
		pol, err := policy.New(&p.spec, "t")
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := exit.ParseConfig(exitTOML(p.spec, "tok"), "diff.toml", nil)
		if err != nil {
			t.Fatalf("%s: %v", p.name, err)
		}
		for _, h := range diffHosts {
			for _, port := range []int{443, 8080} {
				target := net.JoinHostPort(h, strconv.Itoa(port))
				// The Agent's broker.
				am := &events.Memory{}
				abus := events.NewBus("r-diff", nil)
				abus.Add(am)
				rp := &recPath{}
				b := &broker.Broker{Policy: pol, Path: rp, Resolver: &fakeDNS{m: diffDNS}, Bus: abus, DialTimeout: 3 * time.Second}
				ask(b.Handle, "CONNECT "+target+" HTTP/1.1\r\n\r\n")
				// The exit, asked by a client that does no checking of its own.
				xm := &events.Memory{}
				xbus := events.NewBus("x-diff", nil)
				xbus.Add(xm)
				var xdials []string
				var mu sync.Mutex
				s := &Server{Config: cfg, Resolver: &fakeDNS{m: diffDNS}, Bus: xbus, DialTimeout: 3 * time.Second,
					Dial: func(_ context.Context, _ netip.Addr, dst net.IP, _ int) (net.Conn, error) {
						mu.Lock()
						xdials = append(xdials, dst.String())
						mu.Unlock()
						return nil, errors.New("not dialing in this test")
					}}
				ask(s.Handle, "CONNECT "+target+" HTTP/1.1\r\nProxy-Authorization: "+basic("tok")+"\r\n\r\n")

				as, xs := steps(am.Snapshot()), steps(xm.Snapshot())
				var v4 []string
				for _, d := range rp.dials {
					if net.ParseIP(d).To4() != nil {
						v4 = append(v4, d)
					}
				}
				if fmt.Sprint(as) != fmt.Sprint(xs) || strings.Join(v4, ",") != strings.Join(xdials, ",") {
					t.Errorf("%s, %s:\n  Agent %v dialed %v\n  exit  %v dialed %v", p.name, target, as, rp.dials, xs, xdials)
				}
				// And the request plan, which the offline command and the
				// browser use, says the same.
				pl := cfg.Clients[0].Decide(h, port, lookup)
				switch {
				case strings.Contains(fmt.Sprint(as), "policy.deny"):
					denied++
					if pl.Outcome != "denied" {
						t.Errorf("%s %s: plan %+v", p.name, target, pl)
					}
				case strings.Contains(fmt.Sprint(as), "policy.allow"):
					allowed++
					if pl.Rule == "" {
						t.Errorf("%s %s: plan %+v", p.name, target, pl)
					}
				default:
					failed++
					if pl.Outcome != "failed" {
						t.Errorf("%s %s: plan %+v", p.name, target, pl)
					}
				}
				compared++
			}
		}
	}
	if compared < 500 || allowed < 50 || denied < 100 {
		t.Errorf("only %d requests compared (%d allowed, %d denied)", compared, allowed, denied)
	}
	t.Logf("RESULT differential-unit: %d requests under %d policies, the exit and the Agent's broker recorded the same steps for every one (%d allowed, %d denied, %d failed before a decision)",
		compared, len(diffPolicies), allowed, denied, failed)
}
