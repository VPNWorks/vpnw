// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package client

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"vpnw.com/vpnw/internal/lab"
	"vpnw.com/vpnw/internal/lab/netlink"
	"vpnw.com/vpnw/internal/lab/wire"
	"vpnw.com/vpnw/internal/lab/world"
)

// Client is a running stand-in client.
type Client struct {
	o    Options
	log  io.Writer
	logm sync.Mutex
	tun  *os.File
	conn *net.UDPConn
	up   atomic.Bool

	frames chan frame
	done   chan struct{}
	nonce  [8]byte

	linkUp      bool
	settleUntil time.Time
	lastHeard   time.Time
	lastPing    time.Time
	lastHello   time.Time
	dnsSet      bool // the client has put its resolver in place at least once
	lastDNS     time.Time
	routesIn    bool
}

type frame struct {
	typ     byte
	payload []byte
	err     error
}

// Run starts a client and runs it until stop is closed, then shuts it down
// cleanly: routes, rules, firewall and DNS as they were. A client that is
// killed instead leaves everything as it was at that moment, as a crash
// does. log receives the client's changes as recording lines.
func Run(o Options, log io.Writer, stop <-chan struct{}) error {
	o.Defaults()
	c := &Client{o: o, log: log, frames: make(chan frame, 64), done: make(chan struct{})}
	c.note("start", o.Mode.Name)
	if err := c.setup(); err != nil {
		c.note("error", err.Error())
		return err
	}
	go c.readServer()
	go c.readTUN()
	err := c.loop(stop)
	close(c.done)
	c.shutdown()
	return err
}

// note writes one change to the log, at once, so a crash loses nothing
// written before it.
func (c *Client) note(state, detail string) {
	if c.log == nil {
		return
	}
	e := lab.Event{T: time.Now(), Ev: lab.EvClient, State: state, Note: detail}
	c.logm.Lock()
	c.log.Write(append(e.AppendJSON(nil), '\n'))
	c.logm.Unlock()
}

func ignore(err error, codes ...syscall.Errno) error {
	for _, c := range codes {
		if errors.Is(err, c) {
			return nil
		}
	}
	return err
}

func (c *Client) setup() error {
	o, m := c.o, c.o.Mode
	// The firewall comes first, so a client that starts with a kill
	// switch never has a moment without one.
	if err := loadRules(Rules(o)); err != nil {
		return err
	}
	var err error
	if c.tun, err = netlink.OpenTUN(o.Tun, m.HoldRoutes); err != nil {
		return err
	}
	if err := ignore(netlink.AddAddr(o.Tun, o.Addr), syscall.EEXIST); err != nil {
		return err
	}
	if err := netlink.SetUp(o.Tun, true); err != nil {
		return err
	}
	for _, r := range c.rules() {
		if err := ignore(netlink.AddRule(r), syscall.EEXIST); err != nil {
			return err
		}
	}
	if err := c.dial(); err != nil {
		return err
	}
	rand.Read(c.nonce[:])
	c.linkUp = linkIsUp(o.Dev)
	return nil
}

// dial opens the tunnel's socket: marked, so strict routing lets it out by
// the main table and the kill switch lets it through, and bound to the
// physical link, so it never routes into the tunnel itself.
func (c *Client) dial() error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, int(c.o.Mark)); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("mark the tunnel's socket: %w", err)
	}
	if err := syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, c.o.Dev); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("bind the tunnel's socket to %s: %w", c.o.Dev, err)
	}
	// Connected, so the server's refusals come back as ECONNREFUSED.
	if err := syscall.Connect(fd, &syscall.SockaddrInet4{Port: int(c.o.Server.Port()), Addr: c.o.Server.Addr().As4()}); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("connect the tunnel's socket to %s: %w", c.o.Server, err)
	}
	f := os.NewFile(uintptr(fd), "tunnel")
	defer f.Close()
	fc, err := net.FileConn(f)
	if err != nil {
		return err
	}
	c.conn = fc.(*net.UDPConn)
	return nil
}

func (c *Client) rules() []netlink.Rule {
	if !c.o.Mode.Strict {
		return nil
	}
	rs := []netlink.Rule{{Priority: 100, Table: c.o.Table, Mark: c.o.Mark, Invert: true}}
	if c.o.Mode.LocalAccess {
		rs = append(rs, netlink.Rule{Priority: 90, Table: netlink.MainTable, Dst: c.o.HomeNet})
	}
	return rs
}

func (c *Client) routes() []netlink.Route {
	if c.o.Mode.Strict {
		return []netlink.Route{{Dst: netip.MustParsePrefix("0.0.0.0/0"), Dev: c.o.Tun, Table: c.o.Table}}
	}
	return []netlink.Route{{Dst: netip.MustParsePrefix("0.0.0.0/1"), Dev: c.o.Tun}, {Dst: netip.MustParsePrefix("128.0.0.0/1"), Dev: c.o.Tun}}
}

func loadRules(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func linkIsUp(dev string) bool {
	ifi, err := net.InterfaceByName(dev)
	return err == nil && ifi.Flags&net.FlagUp != 0
}

func (c *Client) send(typ byte, payload []byte) {
	c.conn.Write(wire.AppendFrame(nil, typ, payload))
}

// readServer passes the server's frames, and refusals, to the loop.
func (c *Client) readServer() {
	buf := make([]byte, 65536)
	for {
		n, err := c.conn.Read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			c.deliver(frame{err: err})
			continue
		}
		typ, payload, err := wire.ParseFrame(buf[:n])
		if err != nil {
			continue
		}
		if typ == wire.Data {
			c.tun.Write(payload)
		}
		c.deliver(frame{typ: typ, payload: append([]byte(nil), payload...)})
	}
}

// deliver hands a frame to the loop, unless the client is shutting down.
func (c *Client) deliver(f frame) {
	select {
	case c.frames <- f:
	case <-c.done:
	}
}

// readTUN carries packets from the tunnel device to the server while the
// tunnel is up, and drops them while it is down.
func (c *Client) readTUN() {
	buf := make([]byte, 65536)
	for {
		n, err := c.tun.Read(buf[wire.FrameHeader:])
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}
			continue
		}
		if !c.up.Load() {
			continue
		}
		f := wire.AppendFrame(buf[:0], wire.Data, nil)
		c.conn.Write(f[:wire.FrameHeader+n])
	}
}

func (c *Client) loop(stop <-chan struct{}) error {
	t := time.NewTicker(c.o.Tick)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return nil
		case f := <-c.frames:
			c.onFrame(f)
		case now := <-t.C:
			c.onTick(now)
		}
	}
}

func (c *Client) onFrame(f frame) {
	now := time.Now()
	if f.err != nil {
		if errors.Is(f.err, syscall.ECONNREFUSED) && c.up.Load() {
			c.down("the server refused the tunnel's packets")
		}
		return
	}
	c.lastHeard = now
	if f.typ == wire.Welcome && !c.up.Load() && string(f.payload) == string(c.nonce[:]) {
		c.bringUp()
	}
}

func (c *Client) onTick(now time.Time) {
	// The physical link.
	if up := linkIsUp(c.o.Dev); up != c.linkUp {
		c.linkUp = up
		if up {
			c.note("link", "up")
			c.settleUntil = now.Add(c.o.Settle)
		} else {
			c.note("link", "down")
			if c.up.Load() {
				c.down("the link went down")
			}
		}
	}
	// DNS: put the VPN's resolver back if something changed it.
	if c.o.Mode.HoldDNS && c.dnsSet && now.Sub(c.lastDNS) >= 4*c.o.Tick {
		c.lastDNS = now
		if a, err := world.ReadResolv(c.o.Resolv); err != nil || a != c.o.DNS {
			c.setDNS(c.o.DNS, "put back")
		}
	}
	if c.up.Load() {
		if now.Sub(c.lastHeard) > c.o.DeadAfter {
			c.down(fmt.Sprintf("no answer from the server for %s", c.o.DeadAfter))
			return
		}
		if now.Sub(c.lastPing) >= c.o.Keepalive {
			c.lastPing = now
			c.send(wire.Ping, c.nonce[:])
		}
		return
	}
	if !c.linkUp || now.Before(c.settleUntil) {
		return
	}
	if now.Sub(c.lastHello) >= c.o.Retry {
		c.lastHello = now
		rand.Read(c.nonce[:])
		c.send(wire.Hello, c.nonce[:])
	}
}

func (c *Client) bringUp() {
	c.up.Store(true)
	c.lastHeard = time.Now()
	c.note("up", "")
	added := false
	for _, r := range c.routes() {
		err := netlink.AddRoute(r)
		if err == nil {
			added = true
		}
		if err := ignore(err, syscall.EEXIST); err != nil {
			c.note("error", err.Error())
		}
	}
	if added || !c.routesIn {
		c.note("routes", "installed")
	}
	c.routesIn = true
	c.setDNS(c.o.DNS, "")
	c.dnsSet = true
}

func (c *Client) down(reason string) {
	c.up.Store(false)
	c.note("down", reason)
	if c.o.Mode.HoldRoutes {
		c.note("routes", "held")
	} else {
		for _, r := range c.routes() {
			if err := ignore(netlink.DelRoute(r), syscall.ESRCH, syscall.ENODEV); err != nil {
				c.note("error", err.Error())
			}
		}
		c.routesIn = false
		c.note("routes", "removed")
	}
	if c.o.Mode.HomeDNSWhileDown {
		c.setDNS(c.o.HomeDNS, "while reconnecting")
	}
}

func (c *Client) setDNS(a netip.Addr, why string) {
	if cur, err := world.ReadResolv(c.o.Resolv); err == nil && cur == a {
		return
	}
	if err := world.WriteResolv(c.o.Resolv, a); err != nil {
		c.note("error", err.Error())
		return
	}
	note := a.String()
	if why != "" {
		note += " (" + why + ")"
	}
	c.note("dns", note)
}

// shutdown takes everything down as it was before the client started.
func (c *Client) shutdown() {
	c.up.Store(false)
	for _, r := range c.routes() {
		netlink.DelRoute(r)
	}
	for _, r := range c.rules() {
		netlink.DelRule(r)
	}
	loadRules(fmt.Sprintf("table inet %[1]s\ndelete table inet %[1]s\n", TableName))
	if c.o.HomeDNS.IsValid() {
		world.WriteResolv(c.o.Resolv, c.o.HomeDNS)
	}
	if c.conn != nil {
		c.conn.Close()
	}
	if c.tun != nil {
		if c.o.Mode.HoldRoutes {
			netlink.DropPersist(c.tun)
		}
		c.tun.Close()
	}
	c.note("stop", "")
}
