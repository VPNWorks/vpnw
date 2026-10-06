// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package client is Lab's stand-in VPN client: a small program that opens a
// TUN device, carries IP packets over UDP to the stand-in server, installs
// its routes and its DNS setting, and reconnects when the server stops
// answering. It runs in four modes. One is correct; the other three each
// have one planted fault, so the bench has something to catch.
//
// The tunnel is not encrypted and the client authenticates nothing: it is a
// test fixture with a VPN client's routing, firewall and timing, not a VPN.
package client

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Mode is how a stand-in client behaves.
type Mode struct {
	Name string
	// Strict routing: a rule sends every packet without the client's mark
	// to the client's own table, which holds only the tunnel, so routes
	// pushed into the main table never apply. Without it, the client uses
	// routes 0.0.0.0/1 and 128.0.0.0/1 in the main table, which a more
	// specific route beats.
	Strict bool
	// KillSwitch drops everything that leaves the physical link except the
	// client's own tunnel packets, while connected and while not, and
	// stays in place if the client crashes.
	KillSwitch bool
	// LocalAccess lets traffic to the local network through, in routing
	// and in the kill switch, as many apps do so printers keep working.
	LocalAccess bool
	// PinDNS drops DNS to any server but the VPN's resolver.
	PinDNS bool
	// HoldDNS puts the VPN's resolver back whenever something else changes
	// the device's DNS setting.
	HoldDNS bool
	// HomeDNSWhileDown points DNS at the home network's resolver while the
	// tunnel is down, "so names keep working".
	HomeDNSWhileDown bool
	// HoldRoutes keeps the tunnel's routes while the tunnel is down, on a
	// persistent TUN device that keeps them through a crash too: a routing
	// kill switch. Without it, the routes go when the tunnel does.
	HoldRoutes bool
}

// Modes are the stand-in clients. Only "correct" should pass every
// scenario.
var Modes = map[string]Mode{
	"correct":        {Name: "correct", Strict: true, KillSwitch: true, PinDNS: true, HoldDNS: true},
	"dns-leak":       {Name: "dns-leak", Strict: true, KillSwitch: true, LocalAccess: true, HomeDNSWhileDown: true},
	"no-kill-switch": {Name: "no-kill-switch", Strict: true, HoldDNS: true},
	"follows-routes": {Name: "follows-routes", PinDNS: true, HoldDNS: true, HoldRoutes: true},
}

// ModeNames lists the modes in a fixed order.
func ModeNames() []string {
	return []string{"correct", "dns-leak", "no-kill-switch", "follows-routes"}
}

// FindMode returns the mode with the given name.
func FindMode(name string) (Mode, error) {
	m, ok := Modes[name]
	if !ok {
		return m, fmt.Errorf("unknown mode %q; the modes are %s", name, strings.Join(ModeNames(), ", "))
	}
	return m, nil
}

// Options configure a client.
type Options struct {
	Mode    Mode
	Server  netip.AddrPort // the stand-in server
	Dev     string         // the physical link
	Tun     string         // the TUN device to create
	Addr    netip.Prefix   // the client's tunnel address
	DNS     netip.Addr     // the VPN's resolver, through the tunnel
	HomeDNS netip.Addr     // the home network's resolver
	HomeNet netip.Prefix   // the local network
	Resolv  string         // the device's DNS setting, in resolv.conf form
	Mark    uint32         // the firewall mark on the client's own packets
	Table   int            // the client's routing table, for strict routing

	Keepalive time.Duration // how often to check the server is there
	DeadAfter time.Duration // how long without an answer before reconnecting
	Retry     time.Duration // how often to try to reconnect
	Settle    time.Duration // how long to wait after the link comes back
	Tick      time.Duration // how often the client looks at the time, the link and DNS
}

// Defaults fills in what o leaves empty, with the test world's values.
func (o *Options) Defaults() {
	def := func(d *time.Duration, v time.Duration) {
		if *d == 0 {
			*d = v
		}
	}
	def(&o.Keepalive, 100*time.Millisecond)
	def(&o.DeadAfter, time.Second)
	def(&o.Retry, 300*time.Millisecond)
	def(&o.Settle, time.Second)
	def(&o.Tick, 25*time.Millisecond)
	if o.Tun == "" {
		o.Tun = "tun0"
	}
	if o.Mark == 0 {
		o.Mark = 0x51
	}
	if o.Table == 0 {
		o.Table = 51820
	}
}

// TableName is the client's nftables table.
const TableName = "vpnw_lab_client"

// Rules returns the nftables script for the client's firewall: the kill
// switch and the DNS pin, as its mode wants them. Loading the script
// replaces the table in one step; for a mode with neither, the script only
// removes the table.
func Rules(o Options) string {
	m := o.Mode
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %[1]s\ndelete table inet %[1]s\n", TableName)
	if !m.KillSwitch && !m.PinDNS {
		return b.String()
	}
	fmt.Fprintf(&b, "table inet %s {\n", TableName)
	b.WriteString("\tchain output {\n\t\ttype filter hook output priority filter; policy accept;\n")
	if m.PinDNS {
		fmt.Fprintf(&b, "\t\tmeta l4proto { tcp, udp } th dport 53 ip daddr != %s drop comment \"DNS only to the VPN's resolver\"\n", o.DNS)
	}
	if m.KillSwitch {
		fmt.Fprintf(&b, "\t\toifname %q jump physical\n", o.Dev)
	}
	b.WriteString("\t}\n")
	if m.KillSwitch {
		b.WriteString("\tchain physical {\n")
		fmt.Fprintf(&b, "\t\tmeta mark %#x ip daddr %s udp dport %d accept comment \"the tunnel itself\"\n", o.Mark, o.Server.Addr(), o.Server.Port())
		if m.LocalAccess {
			fmt.Fprintf(&b, "\t\tip daddr %s accept comment \"the local network\"\n", o.HomeNet)
		}
		b.WriteString("\t\tdrop comment \"kill switch\"\n\t}\n")
	}
	b.WriteString("}\n")
	return b.String()
}
