// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package lab is the part of VPN Works Lab that decides: it reads a
// recording of one scenario run and says whether anything left the device
// outside the tunnel, which probes, and when.
//
// Lab runs a VPN app inside a private test network, keeps a probe sending
// DNS queries, TCP connections and UDP datagrams, and breaks things on a
// timetable: the VPN server goes silent or away, the app is killed, the link
// drops, the local network pushes a route or a new DNS server. Observers on
// the far side record every arrival with its source address. An arrival from
// the VPN's exit address came through the tunnel; one from the home
// network's public address, or at the home router's resolver, left outside
// it.
//
// This package holds the recording format, the scenarios and their
// timetables, and the verdict. It makes no system calls, so the browser demo
// runs the same verdict code on recorded runs. The test network, the
// stand-in VPN clients and the probe live in the subpackages.
package lab

// Version is the Lab engine's version.
const Version = "0.1.0"

// Event types, the "ev" field of a recording line.
const (
	EvRun     = "run"     // the first line: what ran, and the addresses that tell paths apart
	EvStep    = "step"    // a step of the timetable, when the bench carried it out
	EvSent    = "sent"    // the probe sent something
	EvArrival = "arrival" // an observer saw a probe arrive
	EvClient  = "client"  // the app under test reported a change of its own
	EvApp     = "app"     // the bench started, killed or stopped the app
)

// Probe kinds.
const (
	DNS = "dns"
	TCP = "tcp"
	UDP = "udp"
)

// How a probe was sent.
const (
	Direct = "direct" // straight from the program, like an app that ignores proxy settings
	Proxy  = "proxy"  // through the proxy settings (SOCKS5), like an app that honors them
)

// Observers, the "at" field of an arrival.
const (
	AtHomeDNS = "home-dns" // the home router's resolver: anything here left outside the tunnel
	AtVPNDNS  = "vpn-dns"  // the VPN's resolver, reached only through the tunnel
	AtZoneDNS = "zone-dns" // the name server for the probe's zone, on the internet
	AtTCP     = "tcp"      // the TCP observer on the internet
	AtUDP     = "udp"      // the UDP observer on the internet
)

// Steps of a timetable.
const (
	StepStart    = "start"
	StepFaultOn  = "fault-on"
	StepFaultOff = "fault-off"
	StepStop     = "stop"
)

func oneOf(s string, list ...string) bool {
	for _, x := range list {
		if s == x {
			return true
		}
	}
	return false
}
