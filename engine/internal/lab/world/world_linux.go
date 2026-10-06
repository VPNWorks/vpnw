// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package world

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"

	"vpnw.com/vpnw/internal/lab"
	"vpnw.com/vpnw/internal/lab/netlink"
	"vpnw.com/vpnw/internal/testnet"
)

// World is one test network, built for one run and thrown away after it.
type World struct {
	Device, Home, Internet, VPN *testnet.NS
	Dir                         string // the run's directory
	Resolv                      string // the device's resolver setting, in resolv.conf form

	rec        recorder
	server     *server
	exitDNS    *forwarder // DNS from the exit address, for the resolver and the proxy
	vpnWorkers *workers   // the proxy's dials, made inside the vpn namespace
	mu         sync.Mutex
	closers    []func()
	fault      string
}

// Check reports whether this machine can build a world: user and network
// namespaces, the TUN driver and nftables.
func Check() error {
	if _, err := exec.LookPath("nft"); err != nil {
		return errors.New("nft is not installed (nftables builds the world's NAT, faults and kill switches)")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		return errors.New("/dev/net/tun is missing: the TUN driver is needed for the tunnel")
	}
	return nil
}

// Build builds a world. dir holds the device's resolver setting and is
// created if missing. Build needs root in its own user namespace; the
// command and the tests get it with testnet.Reexec.
func Build(dir string) (w *World, err error) {
	if err := Check(); err != nil {
		return nil, err
	}
	w = &World{Dir: dir, Resolv: filepath.Join(dir, "resolv.conf")}
	defer func() {
		if err != nil {
			w.Close()
			w = nil
		}
	}()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	for _, p := range []struct {
		ns   **testnet.NS
		name string
	}{{&w.Device, "device"}, {&w.Home, "home"}, {&w.Internet, "internet"}, {&w.VPN, "vpn"}} {
		if *p.ns, err = testnet.NewNS(p.name); err != nil {
			return nil, err
		}
	}
	type step struct {
		ns *testnet.NS
		fn func() error
	}
	addr := func(dev, cidr string) func() error {
		return func() error { return netlink.AddAddr(dev, netip.MustParsePrefix(cidr)) }
	}
	up := func(dev string) func() error { return func() error { return netlink.SetUp(dev, true) } }
	route := func(dst string, via netip.Addr, dev string) func() error {
		return func() error {
			return netlink.AddRoute(netlink.Route{Dst: netip.MustParsePrefix(dst), Gateway: via, Dev: dev})
		}
	}
	steps := []step{
		{w.Device, func() error { return testnet.AddVeth(DeviceLink, "lan0") }},
		{w.Device, func() error { return testnet.MoveLink("lan0", w.Home) }},
		{w.Home, func() error { return testnet.AddVeth("wan0", "isp0") }},
		{w.Home, func() error { return testnet.MoveLink("isp0", w.Internet) }},
		{w.VPN, func() error { return testnet.AddVeth("wan0", "dc0") }},
		{w.VPN, func() error { return testnet.MoveLink("dc0", w.Internet) }},

		{w.Device, addr(DeviceLink, "192.168.1.10/24")},
		{w.Device, up(DeviceLink)},
		{w.Device, route("0.0.0.0/0", RouterAddr, DeviceLink)},

		{w.Home, addr("lan0", "192.168.1.1/24")},
		{w.Home, addr("lan0", "192.168.1.53/24")},
		{w.Home, up("lan0")},
		{w.Home, addr("wan0", "203.0.113.2/24")},
		{w.Home, up("wan0")},
		{w.Home, route("0.0.0.0/0", ISPAddr, "wan0")},

		{w.Internet, addr("isp0", "203.0.113.1/24")},
		{w.Internet, up("isp0")},
		{w.Internet, addr("dc0", "192.0.2.1/24")},
		{w.Internet, up("dc0")},
		{w.Internet, addr("lo", "198.51.100.10/32")},
		{w.Internet, addr("lo", "198.51.100.53/32")},

		{w.VPN, addr("wan0", "192.0.2.10/24")},
		{w.VPN, addr("wan0", "192.0.2.20/24")},
		{w.VPN, up("wan0")},
		{w.VPN, route("0.0.0.0/0", DCAddr, "wan0")},
	}
	for _, s := range steps {
		if err := s.ns.Do(s.fn); err != nil {
			return nil, fmt.Errorf("world, %s: %w", s.ns.Name, err)
		}
	}
	for _, ns := range []*testnet.NS{w.Device, w.Home, w.Internet, w.VPN} {
		// Refusals are ICMP errors, which Linux rate-limits; lift the
		// limits so a refused packet is refused at once.
		for _, kv := range [][2]string{{"net/ipv4/icmp_ratelimit", "0"}, {"net/ipv4/icmp_msgs_per_sec", "100000"}, {"net/ipv4/icmp_msgs_burst", "100000"}} {
			if err := ns.Sysctl(kv[0], kv[1]); err != nil {
				return nil, err
			}
		}
	}
	for _, ns := range []*testnet.NS{w.Home, w.Internet, w.VPN} {
		if err := ns.Sysctl("net/ipv4/ip_forward", "1"); err != nil {
			return nil, err
		}
	}
	if err := nft(w.Home, `table ip lab_nat {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "wan0" ip saddr 192.168.1.0/24 masquerade
	}
}
`); err != nil {
		return nil, err
	}
	if err := nft(w.VPN, `table ip lab_nat {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "wan0" ip saddr 10.66.0.0/24 snat to 192.0.2.20
	}
}
`); err != nil {
		return nil, err
	}
	if err := w.SetDNS(RouterAddr); err != nil {
		return nil, err
	}
	for _, start := range []func() error{w.startObservers, w.startServer, w.startResolvers, w.startProxy} {
		if err := start(); err != nil {
			return nil, err
		}
	}
	return w, nil
}

// Close stops the servers and removes the namespaces.
func (w *World) Close() {
	w.mu.Lock()
	closers := w.closers
	w.closers = nil
	w.mu.Unlock()
	for i := len(closers) - 1; i >= 0; i-- {
		closers[i]()
	}
	for _, ns := range []*testnet.NS{w.Device, w.Home, w.Internet, w.VPN} {
		if ns != nil {
			ns.Close()
		}
	}
}

func (w *World) onClose(fn func()) {
	w.mu.Lock()
	w.closers = append(w.closers, fn)
	w.mu.Unlock()
}

// nft loads an nftables script in a namespace.
func nft(ns *testnet.NS, script string) error {
	return ns.Do(func() error {
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("nft in %s: %v: %s", ns.Name, err, strings.TrimSpace(string(out)))
		}
		return nil
	})
}

// SetDNS is the device's network settings taking a DNS server from the
// home network, as they do at every DHCP lease.
func (w *World) SetDNS(a netip.Addr) error { return WriteResolv(w.Resolv, a) }

// LinkDown takes the device's physical link down. Linux drops every route
// through it.
func (w *World) LinkDown() error {
	return w.Device.Do(func() error { return netlink.SetUp(DeviceLink, false) })
}

// LinkUp brings the device's link back, and gives it its default route
// again, as the home network's DHCP does. The route names its device: a
// route found through the policy rules could land on the tunnel.
func (w *World) LinkUp() error {
	return w.Device.Do(func() error {
		if err := netlink.SetUp(DeviceLink, true); err != nil {
			return err
		}
		err := netlink.AddRoute(netlink.Route{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: RouterAddr, Dev: DeviceLink})
		if errors.Is(err, syscall.EEXIST) {
			err = nil
		}
		return err
	})
}

// PushedRoute is the route the home network pushes: the observers' range
// through the home router, like a DHCP option 121 route.
var PushedRoute = netlink.Route{Dst: ObservedNet, Gateway: RouterAddr, Dev: DeviceLink}

// PushRoute adds the pushed route to the device, or withdraws it.
func (w *World) PushRoute(on bool) error {
	return w.Device.Do(func() error {
		if on {
			return netlink.AddRoute(PushedRoute)
		}
		return netlink.DelRoute(PushedRoute)
	})
}

// Server faults.
const (
	ServerSilent = "silent" // every packet to and from the server's address is dropped
	ServerGone   = "gone"   // the server's address refuses everything
)

// SetServerFault turns a server fault on, or with "" off. It works on the
// address, so the tunnel and the proxy are hit alike.
func (w *World) SetServerFault(kind string) error {
	var rules string
	switch kind {
	case "":
	case ServerSilent:
		rules = `
	chain input {
		type filter hook input priority -10; policy accept;
		ip daddr 192.0.2.10 drop
	}
	chain output {
		type filter hook output priority -10; policy accept;
		ip saddr 192.0.2.10 drop
	}`
	case ServerGone:
		rules = `
	chain input {
		type filter hook input priority -10; policy accept;
		ip daddr 192.0.2.10 meta l4proto tcp reject with tcp reset
		ip daddr 192.0.2.10 reject with icmp type port-unreachable
	}
	chain output {
		type filter hook output priority -10; policy accept;
		ip saddr 192.0.2.10 udp sport 51820 drop
	}`
	default:
		return fmt.Errorf("unknown server fault %q", kind)
	}
	script := "table inet lab_fault\ndelete table inet lab_fault\n"
	if rules != "" {
		script += "table inet lab_fault {" + rules + "\n}\n"
	}
	if err := nft(w.VPN, script); err != nil {
		return err
	}
	w.mu.Lock()
	w.fault = kind
	w.mu.Unlock()
	return nil
}

// Arrivals returns what the observers saw of one run's probes, in time
// order.
func (w *World) Arrivals(run string) []lab.Event {
	w.rec.mu.Lock()
	defer w.rec.mu.Unlock()
	var out []lab.Event
	for _, a := range w.rec.list {
		if a.p.Run != run {
			continue
		}
		out = append(out, lab.Event{T: a.t, Ev: lab.EvArrival, Kind: a.p.Kind, Via: a.p.Via, Seq: a.p.Seq, At: a.at, Src: a.src})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].T.Before(out[j].T) })
	return out
}
