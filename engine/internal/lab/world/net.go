// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package world builds Lab's test network: four private network namespaces
// with the stand-in servers and observers in them, and the faults the bench
// turns on and off.
//
//	device     the laptop: the app under test and the probe
//	home       the home router: NAT to the internet, a DNS resolver, and
//	           the source of a pushed route or a new DNS server
//	internet   observers for DNS, TCP and UDP that record every arrival
//	           with its source address
//	vpn        the stand-in VPN server: the tunnel's end, NAT out to the
//	           internet from one exit address, a resolver reached through
//	           the tunnel, and a SOCKS5 proxy for the Agent
//
// Addresses come from the documentation ranges (192.0.2.0/24,
// 198.51.100.0/24, 203.0.113.0/24) and private ranges, so nothing here can
// be mistaken for a real network.
package world

import "net/netip"

// Addresses and ports of the test world.
var (
	HomeNet     = netip.MustParsePrefix("192.168.1.0/24")
	DeviceAddr  = netip.MustParseAddr("192.168.1.10") // the laptop on the home network
	RouterAddr  = netip.MustParseAddr("192.168.1.1")  // the home router and its resolver
	RouterDNS2  = netip.MustParseAddr("192.168.1.53") // the second resolver address, for a DNS change
	HomePublic  = netip.MustParseAddr("203.0.113.2")  // the home network's public address
	ISPAddr     = netip.MustParseAddr("203.0.113.1")  // the internet's side of the home line
	ServerAddr  = netip.MustParseAddr("192.0.2.10")   // the VPN server: tunnel endpoint and proxy
	ExitAddr    = netip.MustParseAddr("192.0.2.20")   // the VPN's exit address
	DCAddr      = netip.MustParseAddr("192.0.2.1")    // the internet's side of the VPN's line
	ObservedNet = netip.MustParsePrefix("198.51.100.0/24")
	Observer    = netip.MustParseAddr("198.51.100.10") // the TCP and UDP observers
	ZoneDNS     = netip.MustParseAddr("198.51.100.53") // the name server for the probe's zone
	TunnelNet   = netip.MustParsePrefix("10.66.0.0/24")
	TunnelPeer  = netip.MustParseAddr("10.66.0.1") // the server's end of the tunnel, and the VPN's resolver
	TunnelAddr  = netip.MustParseAddr("10.66.0.2") // the client's end of the tunnel
)

const (
	TunnelPort = 51820 // the stand-in VPN server's UDP port
	ProxyPort  = 1080  // the SOCKS5 proxy at the VPN server, for the Agent
	TCPPort    = 80    // the TCP observer
	UDPPort    = 9     // the UDP observer
	DNSPort    = 53
	DeviceLink = "eth0" // the device's physical link
	TunnelDev  = "tun0" // the tunnel device, on the device and at the server
)
