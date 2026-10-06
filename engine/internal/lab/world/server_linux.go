// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package world

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"vpnw.com/vpnw/internal/lab/netlink"
	"vpnw.com/vpnw/internal/lab/wire"
)

// server is the stand-in VPN server: one client at a time, IP packets in
// plain UDP frames between the client and a TUN device, and NAT behind it.
// It answers Hello and Ping, and takes the address of whatever valid frame
// came last as its client's, as a roaming VPN does.
type server struct {
	conn *net.UDPConn
	tun  *os.File
	mu   sync.Mutex
	peer netip.AddrPort

	Hellos, Pings, In, Out atomic.Int64
}

// ServerStats counts what the server saw: handshakes, keepalives, and
// packets carried in from the client and out to it.
type ServerStats struct{ Hellos, Pings, In, Out int64 }

// ServerStats returns the server's counts so far.
func (w *World) ServerStats() ServerStats {
	s := w.server
	return ServerStats{s.Hellos.Load(), s.Pings.Load(), s.In.Load(), s.Out.Load()}
}

func (w *World) startServer() error {
	s := &server{}
	err := w.VPN.Do(func() error {
		var err error
		if s.tun, err = netlink.OpenTUN(TunnelDev, false); err != nil {
			return err
		}
		if err := netlink.AddAddr(TunnelDev, netip.PrefixFrom(TunnelPeer, TunnelNet.Bits())); err != nil {
			return err
		}
		return netlink.SetUp(TunnelDev, true)
	})
	if err != nil {
		if s.tun != nil {
			s.tun.Close()
		}
		return err
	}
	w.onClose(func() { s.tun.Close() })
	if s.conn, err = listenUDP(w.VPN, netip.AddrPortFrom(ServerAddr, TunnelPort)); err != nil {
		return err
	}
	w.onClose(func() { s.conn.Close() })
	w.server = s
	go s.fromClients()
	go s.fromTUN()
	return nil
}

func (s *server) setPeer(a netip.AddrPort) {
	s.mu.Lock()
	s.peer = a
	s.mu.Unlock()
}

func (s *server) fromClients() {
	buf := make([]byte, 65536)
	out := make([]byte, 0, 64)
	for {
		n, from, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		typ, payload, err := wire.ParseFrame(buf[:n])
		if err != nil {
			continue
		}
		switch typ {
		case wire.Hello:
			s.Hellos.Add(1)
			s.setPeer(from)
			s.conn.WriteToUDPAddrPort(wire.AppendFrame(out[:0], wire.Welcome, payload), from)
		case wire.Ping:
			s.Pings.Add(1)
			s.setPeer(from)
			s.conn.WriteToUDPAddrPort(wire.AppendFrame(out[:0], wire.Pong, payload), from)
		case wire.Data:
			s.In.Add(1)
			s.setPeer(from)
			s.tun.Write(payload)
		}
	}
}

func (s *server) fromTUN() {
	buf := make([]byte, 65536)
	for {
		n, err := s.tun.Read(buf[wire.FrameHeader:])
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}
			continue
		}
		s.mu.Lock()
		peer := s.peer
		s.mu.Unlock()
		if !peer.IsValid() || n < 20 || buf[wire.FrameHeader]>>4 != 4 {
			continue
		}
		frame := wire.AppendFrame(buf[:0], wire.Data, nil)
		s.Out.Add(1)
		s.conn.WriteToUDPAddrPort(frame[:wire.FrameHeader+n], peer)
	}
}

// startProxy starts a SOCKS5 proxy at the VPN server's address, for the
// Agent's path. It takes CONNECT to an IPv4 address or a name, resolves
// names at the zone's name server, and connects out from the exit address,
// so what it carries arrives the way tunnel traffic does.
func (w *World) startProxy() error {
	var ln net.Listener
	err := w.VPN.Do(func() (err error) {
		ln, err = net.Listen("tcp4", netip.AddrPortFrom(ServerAddr, ProxyPort).String())
		return err
	})
	if err != nil {
		return err
	}
	w.onClose(func() { ln.Close() })
	if w.vpnWorkers, err = w.newWorkers(w.VPN, 4); err != nil {
		return err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			go w.socks(c)
		}
	}()
	return nil
}

// SOCKS5 reply codes.
const (
	socksOK          = 0x00
	socksFailure     = 0x01
	socksHostUnreach = 0x04
	socksRefused     = 0x05
	socksNoCommand   = 0x07
	socksNoAddress   = 0x08
)

func (w *World) socks(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	reply := func(code byte) error {
		_, err := c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
		return err
	}
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil || hdr[0] != 5 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	noAuth := false
	for _, m := range methods {
		noAuth = noAuth || m == 0
	}
	if !noAuth {
		c.Write([]byte{5, 0xff})
		return
	}
	c.Write([]byte{5, 0})
	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil || req[0] != 5 {
		return
	}
	var dst netip.Addr
	switch req[3] {
	case 1:
		var a [4]byte
		if _, err := io.ReadFull(c, a[:]); err != nil {
			return
		}
		dst = netip.AddrFrom4(a)
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(c, name); err != nil {
			return
		}
		var err error
		if dst, err = w.lookup(string(name)); err != nil {
			reply(socksHostUnreach)
			return
		}
	default:
		reply(socksNoAddress)
		return
	}
	var pb [2]byte
	if _, err := io.ReadFull(c, pb[:]); err != nil {
		return
	}
	if req[1] != 1 {
		reply(socksNoCommand)
		return
	}
	var out net.Conn
	var err error
	w.vpnWorkers.do(func() {
		d := net.Dialer{LocalAddr: net.TCPAddrFromAddrPort(netip.AddrPortFrom(ExitAddr, 0)), Timeout: 3 * time.Second}
		out, err = d.Dial("tcp4", netip.AddrPortFrom(dst, binary.BigEndian.Uint16(pb[:])).String())
	})
	if err != nil {
		reply(socksRefused)
		return
	}
	defer out.Close()
	if reply(socksOK) != nil {
		return
	}
	c.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() { io.Copy(out, c); out.(*net.TCPConn).CloseWrite(); done <- struct{}{} }()
	go func() { io.Copy(c, out); c.(*net.TCPConn).CloseWrite(); done <- struct{}{} }()
	<-done
	<-done
}

// lookup resolves a name at the zone's name server, from the exit address.
func (w *World) lookup(name string) (netip.Addr, error) {
	msg, err := wire.Query(uint16(time.Now().UnixNano()), name)
	if err != nil {
		return netip.Addr{}, err
	}
	ans, err := w.exitDNS.query(msg)
	if err != nil {
		return netip.Addr{}, err
	}
	r, err := wire.ParseAnswer(ans)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(r.Addrs) == 0 {
		return netip.Addr{}, errors.New("no address for " + name)
	}
	return r.Addrs[0], nil
}
