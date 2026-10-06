// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package world

import (
	"bufio"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"vpnw.com/vpnw/internal/lab"
	"vpnw.com/vpnw/internal/lab/wire"
	"vpnw.com/vpnw/internal/testnet"
)

// recorder keeps every arrival the observers saw.
type recorder struct {
	mu   sync.Mutex
	list []arrival
}

type arrival struct {
	t   time.Time
	p   wire.Probe
	at  string
	src netip.Addr
}

func (r *recorder) add(t time.Time, p wire.Probe, at string, src netip.Addr) {
	r.mu.Lock()
	r.list = append(r.list, arrival{t, p, at, src.Unmap()})
	r.mu.Unlock()
}

// listenUDP opens a UDP socket in a namespace.
func listenUDP(ns *testnet.NS, a netip.AddrPort) (*net.UDPConn, error) {
	var c *net.UDPConn
	err := ns.Do(func() (err error) {
		c, err = net.ListenUDP("udp4", net.UDPAddrFromAddrPort(a))
		return err
	})
	return c, err
}

func (w *World) serveUDP(ns *testnet.NS, a netip.AddrPort, fn func(c *net.UDPConn, t time.Time, msg []byte, from netip.AddrPort)) error {
	c, err := listenUDP(ns, a)
	if err != nil {
		return err
	}
	w.onClose(func() { c.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			fn(c, time.Now(), append([]byte(nil), buf[:n]...), from)
		}
	}()
	return nil
}

// startObservers starts the internet's observers: TCP and UDP at
// 198.51.100.10, and the name server for the probe's zone at 198.51.100.53,
// which answers every name in the zone with the observers' address.
func (w *World) startObservers() error {
	var ln net.Listener
	err := w.Internet.Do(func() (err error) {
		ln, err = net.Listen("tcp4", netip.AddrPortFrom(Observer, TCPPort).String())
		return err
	})
	if err != nil {
		return err
	}
	w.onClose(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			t := time.Now()
			go func() {
				defer c.Close()
				c.SetReadDeadline(time.Now().Add(3 * time.Second))
				line, err := bufio.NewReaderSize(c, 128).ReadString('\n')
				if err != nil && line == "" {
					return
				}
				if p, err := wire.ParseTag(line); err == nil {
					w.rec.add(t, p, lab.AtTCP, c.RemoteAddr().(*net.TCPAddr).AddrPort().Addr())
				}
			}()
		}
	}()
	err = w.serveUDP(w.Internet, netip.AddrPortFrom(Observer, UDPPort), func(_ *net.UDPConn, t time.Time, msg []byte, from netip.AddrPort) {
		if p, err := wire.ParseTag(string(msg)); err == nil {
			w.rec.add(t, p, lab.AtUDP, from.Addr())
		}
	})
	if err != nil {
		return err
	}
	return w.serveUDP(w.Internet, netip.AddrPortFrom(ZoneDNS, DNSPort), func(c *net.UDPConn, t time.Time, msg []byte, from netip.AddrPort) {
		q, err := wire.ParseQuery(msg)
		if err != nil {
			return
		}
		if p, err := wire.ParseName(q.Name); err == nil {
			w.rec.add(t, p, lab.AtZoneDNS, from.Addr())
		}
		rcode := wire.RcodeNXDom
		if q.Name == wire.Zone || strings.HasSuffix(q.Name, "."+wire.Zone) {
			rcode = wire.RcodeOK
		}
		c.WriteToUDPAddrPort(wire.Answer(msg, q, rcode, Observer, 1), from)
	})
}

// startResolvers starts the home router's resolver, on both its addresses,
// and the VPN's resolver at the tunnel's far end. Each records the probes
// it is asked about and forwards every query to the zone's name server,
// over the network, from its own side's address.
func (w *World) startResolvers() error {
	home, err := w.newForwarder(w.Home, HomePublic)
	if err != nil {
		return err
	}
	for _, a := range []netip.Addr{RouterAddr, RouterDNS2} {
		if err := w.resolver(w.Home, netip.AddrPortFrom(a, DNSPort), lab.AtHomeDNS, home); err != nil {
			return err
		}
	}
	if w.exitDNS, err = w.newForwarder(w.VPN, ExitAddr); err != nil {
		return err
	}
	return w.resolver(w.VPN, netip.AddrPortFrom(TunnelPeer, DNSPort), lab.AtVPNDNS, w.exitDNS)
}

func (w *World) resolver(ns *testnet.NS, listen netip.AddrPort, at string, f *forwarder) error {
	return w.serveUDP(ns, listen, func(c *net.UDPConn, t time.Time, msg []byte, client netip.AddrPort) {
		q, err := wire.ParseQuery(msg)
		if err != nil {
			return
		}
		if p, err := wire.ParseName(q.Name); err == nil {
			w.rec.add(t, p, at, client.Addr())
		}
		f.ask(msg, func(ans []byte) { c.WriteToUDPAddrPort(ans, client) })
	})
}
