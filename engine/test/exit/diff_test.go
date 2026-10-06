// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package exittest

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"testing"

	"vpnw.com/vpnw/internal/events"
)

// The policies of the differential test, as [policy] tables.
var diffPolicies = []client{
	{name: "p-allowlist", policy: "default = \"deny\"\ndeny_private = true\nallow = [\"api.partner.test\", \"*.partner.test\"]\n"},
	{name: "p-defaultallow", policy: "default = \"allow\"\ndeny_private = true\ndeny = [\"attacker.test\", \"www.partner.test\"]\n"},
	{name: "p-ranges", policy: "default = \"deny\"\nallow = [\"51.15.0.0/24\", \"66.66.0.66\", \"public.test:443\"]\ndeny = [\"51.15.0.11\", \"*.partner.test:8080\"]\n"},
	{name: "p-ports", policy: "default = \"deny\"\nallow = [\"*.partner.test:80\", \"api.partner.test:8080\", \"10.50.0.0/16\"]\n"},
	{name: "p-implied", policy: "allow = [\"public.test\", \"deep.a.partner.test\", \"mixed.partner.test\"]\ndeny_private = true\n"},
}

var diffTargets = []string{
	"api.partner.test:80", "api.partner.test:8080", "www.partner.test:80", "deep.a.partner.test:80", "partner.test:80",
	"intranet.partner.test:80", "meta.partner.test:80", "mixed.partner.test:80", "attacker.test:443", "evilpartner.test:80",
	"public.test:443", "public.test:80", "missing.partner.test:80", "51.15.0.10:80", "51.15.0.11:443", "10.50.0.5:80",
	"169.254.169.254:80", "66.66.0.66:443", "127.0.0.1:80", "API.PARTNER.TEST:80", "bad..name:80", "2130706433:80",
}

// decisions reads, from a record, what was decided for each request: the
// rule and the reason, or the error that stopped it before a decision.
func decisions(evs []events.Event, keep func(*events.Event) bool) map[uint64]string {
	out := map[uint64]string{}
	ours := map[uint64]bool{}
	for i := range evs {
		e := &evs[i]
		switch e.Type {
		case events.ConnectionAttempt:
			ours[e.Conn] = keep(e)
		case events.PolicyAllow, events.PolicyDeny:
			if ours[e.Conn] && out[e.Conn] == "" {
				verb := "allow"
				if e.Type == events.PolicyDeny {
					verb = "deny"
				}
				out[e.Conn] = verb + " " + e.Str("rule") + ": " + e.Str("reason")
			}
		case events.ConnectionError:
			if ours[e.Conn] && out[e.Conn] == "" {
				out[e.Conn] = "failed: " + e.Str("error")
			}
		}
	}
	return out
}

func connectScript(targets []string) string {
	var q []string
	for _, t := range targets {
		q = append(q, fmt.Sprintf("%q", t))
	}
	return "import socket\n" +
		"for t in [" + strings.Join(q, ", ") + "]:\n" +
		"    s = socket.create_connection(('127.0.0.1', 3128), timeout=20)\n" +
		"    s.sendall(('CONNECT %s HTTP/1.1\\r\\nHost: %s\\r\\n\\r\\n' % (t, t)).encode())\n" +
		"    print('STATUS', t, s.makefile('rb').readline().decode().strip(), flush=True)\n" +
		"    s.close()\n"
}

// On the same requests, the exit decides exactly as the Agent does: each
// policy file is used by the Agent, resolving names itself, and by exit-de,
// asked directly by a client that does no checking, with one DNS server.
func TestExitAgreesWithAgent(t *testing.T) {
	w := build(t)
	w.dns.mu.Lock()
	w.dns.names["mixed.partner.test"] = []net.IP{net.ParseIP("51.15.0.15"), net.ParseIP("192.168.1.20")}
	w.dns.mu.Unlock()
	for i := range diffPolicies {
		diffPolicies[i].token = fmt.Sprintf("tok-%s-%d", diffPolicies[i].name, i)
		w.tokenFile(diffPolicies[i])
	}
	de := w.startExit("exit-de", w.exitConfig("exit-de", deListen, exitPort, "exit-de", diffPolicies))
	total, agreed := 0, 0
	kinds := map[string]int{}
	for pi, c := range diffPolicies {
		// The Agent.
		out, p, trace := w.runAgent(c.name, []string{"guard", "--backend", "sealed", "--policy", c.name + ".toml", "--direct"}, connectScript(diffTargets))
		if len(lines(out, "STATUS")) != len(diffTargets) {
			t.Fatalf("%s: the workload stopped early:\n%s\n%s", c.name, out, p.out.String())
		}
		atAgent := decisions(trace, func(*events.Event) bool { return true })
		// The exit, asked directly, with IDs to find each request in its
		// record.
		run := fmt.Sprintf("diff-%d", pi)
		for i, target := range diffTargets {
			w.tamperIDs(c.token, "exit-de", target, "", run, uint64(i+1))
		}
		de.stop()
		atExit := map[uint64]string{}
		byExitConn := decisions(readRecord(t, de.record), func(e *events.Event) bool { return e.Str("client_run") == run })
		for _, e := range readRecord(t, de.record) {
			if e.Type == events.ConnectionAttempt && e.Str("client_run") == run {
				atExit[uint64(e.Int("client_conn"))] = byExitConn[e.Conn]
			}
		}
		for i, target := range diffTargets {
			a, x := atAgent[uint64(i+1)], atExit[uint64(i+1)]
			total++
			if a == "" || a != x {
				t.Errorf("%s, %s:\n  Agent: %s\n  exit:  %s", c.name, target, a, x)
				continue
			}
			agreed++
			kinds[strings.SplitN(a, " ", 2)[0]]++
		}
		de = w.startExit("exit-de", w.exitConfig("exit-de", deListen, exitPort, "exit-de", diffPolicies))
	}
	var parts []string
	for _, k := range sortedKinds(kinds) {
		parts = append(parts, fmt.Sprintf("%d %s", kinds[k], map[string]string{"allow": "allowed", "deny": "denied", "failed:": "not resolvable"}[k]))
	}
	t.Logf("RESULT differential: %d requests under %d policies, decided by the Agent (vpnw guard, sealed, resolving names itself) and by exit-de (vpnw-exit, asked directly by a client that does no checking), with the same policy files and one DNS server: %d of %d agree on the decision, the rule and the reason (%s)",
		total, len(diffPolicies), agreed, total, strings.Join(parts, ", "))
}

func sortedKinds(m map[string]int) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}
