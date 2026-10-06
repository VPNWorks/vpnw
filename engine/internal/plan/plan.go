// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package plan works out what the broker does with one request, without any
// network I/O: the same steps as the broker, in the same order. The browser
// demo uses it to show real decisions for the requests it simulates, and the
// broker's TestPlanMatchesBroker keeps the two in step.
package plan

import (
	"errors"
	"net"
	"strings"

	"vpnw.com/vpnw/internal/policy"
)

// Plan is what the broker would do with one request.
type Plan struct {
	// Outcome is "denied" (the policy refused it), "dial" (the broker would
	// now connect through the path) or "failed" (it stops before dialing,
	// for example because the name does not resolve).
	Outcome string `json:"outcome"`
	Rule    string `json:"rule,omitempty"`
	Text    string `json:"text,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Error   string `json:"error,omitempty"`
	// Host or IP as the broker normalized it.
	Host string `json:"host,omitempty"`
	IP   string `json:"ip,omitempty"`
	// LookedUp reports whether a DNS lookup was made, and Addrs its answer:
	// the addresses the broker would dial, or checked, or both.
	LookedUp bool     `json:"looked_up"`
	Addrs    []string `json:"addrs,omitempty"`
	// ExitResolves is true when the path resolves the name at its exit.
	ExitResolves bool `json:"exit_resolves"`
}

// Request follows the same steps as the broker, in the same order: check the
// destination, look the name up only when the policy needs its addresses,
// decide, and, for a local-DNS path, look the name up before dialing. lookup
// answers the DNS questions; pol may be nil (no policy).
func Request(pol *policy.Policy, rawHost string, port int, remoteDNS bool, lookup func(host string) ([]net.IP, error)) Plan {
	host, ip, nerr := policy.NormalizeHost(rawHost)
	pl := Plan{Host: host, ExitResolves: remoteDNS && host != ""}
	if ip != nil {
		pl.IP = ip.String()
	}
	if nerr != nil {
		reason := strings.TrimPrefix(nerr.Error(), policy.ErrInvalid.Error()+": ")
		if pol != nil {
			pl.Outcome, pl.Rule, pl.Reason = "denied", "invalid", reason
			return pl
		}
		pl.Outcome, pl.Error = "failed", reason
		return pl
	}
	if port < 1 || port > 65535 {
		pl.Outcome, pl.Error = "failed", "port out of range"
		return pl
	}
	t := policy.Target{Host: host, IP: ip, Port: port, RemoteDNS: remoteDNS}
	var addrs []net.IP
	resolve := func() error {
		pl.LookedUp = true
		ips, err := lookup(host)
		if err == nil && len(ips) == 0 {
			err = errors.New("no addresses")
		}
		if err != nil {
			pl.Outcome, pl.Error = "failed", "dns: "+dnsMessage(err)
			return err
		}
		addrs = ips
		for _, a := range ips {
			pl.Addrs = append(pl.Addrs, a.String())
		}
		return nil
	}
	if pol != nil {
		var d policy.Decision
		if pol.NeedsAddresses(t) {
			if resolve() != nil {
				return pl
			}
			d = pol.Decide(t, addrs)
		} else {
			d = pol.Decide(t, nil)
		}
		pl.Rule, pl.Text, pl.Reason = d.Rule, d.Text, d.Reason
		if !d.Allow {
			pl.Outcome = "denied"
			return pl
		}
	}
	if host != "" && !remoteDNS && addrs == nil {
		if resolve() != nil {
			return pl
		}
	}
	pl.Outcome = "dial"
	return pl
}
