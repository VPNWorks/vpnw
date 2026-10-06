// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build js && wasm

// Command vpnw-wasm exposes the engine's pure decision code to the browser
// demo: the same policy engine, event model and learn code that the vpnw
// binary uses. The demo simulates agents, hosts, DNS and the sealed boundary
// in JavaScript and feeds every connection attempt through this code, so the
// decisions shown in the browser are made by the real engine, not a rewrite.
package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"syscall/js"
	"time"

	"vpnw.com/vpnw/internal/config"
	"vpnw.com/vpnw/internal/events"
	"vpnw.com/vpnw/internal/learn"
	"vpnw.com/vpnw/internal/plan"
	"vpnw.com/vpnw/internal/policy"
	"vpnw.com/vpnw/internal/version"
)

func main() {
	js.Global().Set("vpnwEngine", js.ValueOf(map[string]any{
		"version":     version.Version,
		"schema":      version.Schema,
		"compile":     js.FuncOf(compile),
		"decide":      js.FuncOf(decide),
		"parseConfig": js.FuncOf(parseConfig),
		"learn":       js.FuncOf(learnFn),
		"parseRule":   js.FuncOf(parseRule),
		"plan":        js.FuncOf(planFn),
	}))
	select {}
}

var errNoSuchHost = errors.New("no such host")

func fail(msg string) any { return map[string]any{"ok": false, "error": msg} }

// compile validates a policy written as TOML and returns its summary, or the
// exact error the CLI would print.
func compile(_ js.Value, args []js.Value) any {
	f, err := config.ParseFile("policy.toml", args[0].String())
	if err != nil {
		return fail(err.Error())
	}
	if f.Policy == nil {
		return fail("no [policy] table")
	}
	p, err := policy.New(f.Policy, orName(f.Name, "policy"))
	if err != nil {
		return fail(err.Error())
	}
	sum := p.Summary()
	b, _ := json.Marshal(sum)
	return map[string]any{"ok": true, "summary": string(b)}
}

// decide runs one destination through a policy. args: policyTOML, host, port,
// remoteDNS, addrsCSV. It returns the decision and whether a lookup was
// needed, exactly as the broker would compute it.
func decide(_ js.Value, args []js.Value) any {
	f, err := config.ParseFile("policy.toml", args[0].String())
	if err != nil || f.Policy == nil {
		return fail("policy: " + errStr(err))
	}
	p, err := policy.New(f.Policy, orName(f.Name, "policy"))
	if err != nil {
		return fail(err.Error())
	}
	host := args[1].String()
	port := args[2].Int()
	remote := args[3].Bool()
	var addrs []net.IP
	if args[4].String() != "" {
		for _, s := range splitCSV(args[4].String()) {
			if ip := net.ParseIP(s); ip != nil {
				addrs = append(addrs, ip)
			}
		}
	}
	h, ip, nerr := policy.NormalizeHost(host)
	if nerr != nil {
		return map[string]any{"ok": true, "allow": false, "rule": "invalid", "reason": nerr.Error(), "needed_dns": false}
	}
	t := policy.Target{Host: h, IP: ip, Port: port, RemoteDNS: remote}
	need := p.NeedsAddresses(t)
	var d policy.Decision
	if need {
		d = p.Decide(t, addrs)
	} else {
		d = p.Decide(t, nil)
	}
	return map[string]any{"ok": true, "allow": d.Allow, "rule": d.Rule, "text": d.Text, "reason": d.Reason, "needed_dns": need}
}

// plan works out what the broker would do with one request, with the same
// code the broker's test checks it against. args: policyTOML ("" for no
// policy), host, port, remoteDNS, dnsJSON (an object mapping each name the
// DNS knows to its addresses; any other name does not resolve). It returns
// the plan as JSON.
func planFn(_ js.Value, args []js.Value) any {
	var pol *policy.Policy
	if src := args[0].String(); src != "" {
		f, err := config.ParseFile("policy.toml", src)
		if err != nil {
			return fail(err.Error())
		}
		if f.Policy == nil {
			return fail("no [policy] table")
		}
		if pol, err = policy.New(f.Policy, orName(f.Name, "policy")); err != nil {
			return fail(err.Error())
		}
		if args[3].Bool() {
			// The demo has one path that resolves names at its exit: the office.
			if err := pol.CheckRemoteDNS("office"); err != nil {
				return fail(err.Error())
			}
		}
	}
	var dns map[string][]string
	if err := json.Unmarshal([]byte(args[4].String()), &dns); err != nil {
		return fail("dns map: " + err.Error())
	}
	lookup := func(host string) ([]net.IP, error) {
		list, ok := dns[host]
		if !ok {
			return nil, errNoSuchHost
		}
		var ips []net.IP
		for _, a := range list {
			if ip := net.ParseIP(a); ip != nil {
				ips = append(ips, ip)
			}
		}
		return ips, nil
	}
	pl := plan.Request(pol, args[1].String(), args[2].Int(), args[3].Bool(), lookup)
	b, _ := json.Marshal(pl)
	return map[string]any{"ok": true, "plan": string(b)}
}

// parseRule checks one rule and says how it was read.
func parseRule(_ js.Value, args []js.Value) any {
	r, err := policy.ParseRule(args[0].String())
	if err != nil {
		return fail(err.Error())
	}
	kind := map[policy.Kind]string{policy.KindExact: "host", policy.KindWildcard: "wildcard", policy.KindIP: "address", policy.KindCIDR: "range"}[r.Kind]
	return map[string]any{"ok": true, "kind": kind, "port": r.Port}
}

// parseConfig validates a full config file (network, paths, policy, trace).
func parseConfig(_ js.Value, args []js.Value) any {
	f, err := config.ParseFile("vpnw.toml", args[0].String())
	if err != nil {
		return fail(err.Error())
	}
	out := map[string]any{"ok": true, "name": f.Name}
	if f.Network != nil {
		out["network"] = f.Network.Type
	}
	var paths []any
	for _, n := range f.PathNames() {
		paths = append(paths, n)
	}
	out["paths"] = paths
	return out
}

// learnFn turns a JSONL trace into a policy, like `vpnw learn`.
func learnFn(_ js.Value, args []js.Value) any {
	evs, err := events.Read(stringReader(args[0].String()))
	if err != nil {
		return fail(err.Error())
	}
	opt := learn.Options{Name: args[1].String(), Now: time.Now()}
	if len(args) > 2 {
		opt.Wildcards = args[2].Bool()
	}
	res := learn.FromEvents(evs, opt)
	return map[string]any{
		"ok": true, "toml": res.TOML, "allowed": len(res.Allowed), "denied": len(res.Denied), "unreached": len(res.Unreached),
		"flagged_ips": len(res.FlaggedIPs), "flagged_heavy": len(res.FlaggedHeavy),
	}
}

func orName(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func errStr(err error) string {
	if err == nil {
		return "no [policy] table"
	}
	return err.Error()
}

func stringReader(s string) io.Reader { return strings.NewReader(s) }

func splitCSV(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == ',' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
