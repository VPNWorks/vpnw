// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package probe is Lab's probe: a program on the device that, every
// interval, sends a DNS query for a name unique to the moment, opens a short
// TCP connection and sends a UDP datagram, each tagged with a sequence
// number, to the observers on the internet. It writes a line for every
// probe it sends; the observers write a line for every probe that arrives.
//
// It sends probes two ways. Direct, as a program that ignores proxy
// settings does: DNS to the resolver in the device's setting, TCP and UDP
// straight to the observers. And through the proxy settings (SOCKS5), as a
// program that honors them does: TCP to the observers by address, and DNS
// by asking the proxy to connect to the probe's name.
package probe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"

	"vpnw.com/vpnw/internal/lab"
	"vpnw.com/vpnw/internal/lab/wire"
	"vpnw.com/vpnw/internal/lab/world"
)

// Options configure the probe.
type Options struct {
	Run      string        // the run's id, in every name and tag
	Interval time.Duration // between ticks
	Epoch    time.Time     // tick k is at Epoch + k*Interval; a restarted probe goes on counting
	Until    time.Time     // the last tick is at or before this; zero: until stopped
	Resolv   string        // the device's DNS setting, read before every direct DNS probe
	Target   netip.Addr    // the observers
	TCPPort  uint16
	UDPPort  uint16
	DNSPort  uint16 // the resolver's port; 53 when zero
	Direct   bool   // send probes straight, ignoring proxy settings
	Proxy    string // send probes through this SOCKS5 proxy too, such as socks5h://127.0.0.1:1080
	Timeout  time.Duration
}

// Stats counts what the probe did.
type Stats struct {
	Ticks int
	Sent  int
}

// Run sends probes until o.Until or until stop is closed, and writes a
// line to log for every probe.
func Run(o Options, log io.Writer, stop <-chan struct{}) (Stats, error) {
	var st Stats
	if err := wire.CheckRun(o.Run); err != nil {
		return st, err
	}
	if o.Interval <= 0 {
		return st, errors.New("the interval must be above 0")
	}
	if !o.Direct && o.Proxy == "" {
		return st, errors.New("nothing to send: give direct probes, a proxy, or both")
	}
	if o.Timeout <= 0 {
		o.Timeout = 900 * time.Millisecond
	}
	if o.DNSPort == 0 {
		o.DNSPort = 53
	}
	var px *Proxy
	if o.Proxy != "" {
		p, err := ParseProxy(o.Proxy)
		if err != nil {
			return st, err
		}
		px = &p
	}
	udp, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return st, err
	}
	defer udp.Close()
	var wg sync.WaitGroup
	k := 0
	if now := time.Now(); now.After(o.Epoch) {
		k = int(now.Sub(o.Epoch)/o.Interval) + 1
	}
	var lines []byte
loop:
	for ; ; k++ {
		next := o.Epoch.Add(time.Duration(k) * o.Interval)
		if !o.Until.IsZero() && next.After(o.Until) {
			break
		}
		if d := time.Until(next); d > 0 {
			select {
			case <-stop:
				break loop
			case <-time.After(d):
			}
		} else {
			select {
			case <-stop:
				break loop
			default:
			}
		}
		if behind := time.Since(next); behind > 5*o.Interval {
			// The machine stalled; skip ahead instead of sending a burst.
			k = int(time.Since(o.Epoch)/o.Interval) - 1
			continue
		}
		st.Ticks++
		lines = lines[:0]
		sent := func(kind, via string) {
			lines = append((lab.Event{T: time.Now(), Ev: lab.EvSent, Kind: kind, Via: via, Seq: k}).AppendJSON(lines), '\n')
			st.Sent++
		}
		if o.Direct {
			if ns, err := world.ReadResolv(o.Resolv); err == nil {
				sent(lab.DNS, lab.Direct)
				sendDNS(netip.AddrPortFrom(ns, o.DNSPort), wire.Probe{Kind: lab.DNS, Via: lab.Direct, Run: o.Run, Seq: k})
			}
			sent(lab.UDP, lab.Direct)
			udp.WriteToUDPAddrPort([]byte(wire.Probe{Kind: lab.UDP, Via: lab.Direct, Run: o.Run, Seq: k}.Tag()), netip.AddrPortFrom(o.Target, o.UDPPort))
			sent(lab.TCP, lab.Direct)
			wg.Add(1)
			go func(p wire.Probe) {
				defer wg.Done()
				c, err := net.DialTimeout("tcp4", netip.AddrPortFrom(o.Target, o.TCPPort).String(), o.Timeout)
				if err == nil {
					c.Write([]byte(p.Tag()))
					c.Close()
				}
			}(wire.Probe{Kind: lab.TCP, Via: lab.Direct, Run: o.Run, Seq: k})
		}
		if px != nil {
			for _, kind := range []string{lab.TCP, lab.DNS} {
				p := wire.Probe{Kind: kind, Via: lab.Proxy, Run: o.Run, Seq: k}
				host := o.Target.String()
				if kind == lab.DNS {
					host = p.Name()
				}
				sent(kind, lab.Proxy)
				wg.Add(1)
				go func() {
					defer wg.Done()
					if c, err := px.Connect(host, o.TCPPort, o.Timeout); err == nil {
						c.Write([]byte(p.Tag()))
						c.Close()
					}
				}()
			}
		}
		if _, err := log.Write(lines); err != nil {
			return st, err
		}
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
	return st, nil
}

// sendDNS sends one query and keeps the socket open a moment for the
// answer, so the resolver's reply doesn't bounce.
func sendDNS(ns netip.AddrPort, p wire.Probe) {
	q, err := wire.Query(uint16(p.Seq), p.Name())
	if err != nil {
		return
	}
	c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(ns))
	if err != nil {
		return
	}
	c.Write(q)
	time.AfterFunc(300*time.Millisecond, func() { c.Close() })
}

// Proxy is a SOCKS5 proxy, from a URL such as socks5h://user:pass@host:port.
type Proxy struct {
	Addr       string
	User, Pass string
}

// ParseProxy reads a socks5:// or socks5h:// URL.
func ParseProxy(raw string) (Proxy, error) {
	var p Proxy
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return p, fmt.Errorf("proxy %q: want a URL such as socks5h://127.0.0.1:1080", raw)
	}
	if u.Scheme != "socks5" && u.Scheme != "socks5h" {
		return p, fmt.Errorf("proxy %q: only socks5:// and socks5h:// are supported", raw)
	}
	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		return p, fmt.Errorf("proxy %q needs a port", raw)
	}
	p.Addr = u.Host
	if u.User != nil {
		p.User = u.User.Username()
		p.Pass, _ = u.User.Password()
		if len(p.User) > 255 || len(p.Pass) > 255 {
			return p, errors.New("proxy user name and password must be at most 255 bytes")
		}
	}
	return p, nil
}

// Connect opens a connection to host:port through the proxy. host is an
// IPv4 address or a name, which the proxy resolves.
func (p Proxy) Connect(host string, port uint16, timeout time.Duration) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", p.Addr, timeout)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(timeout))
	if err := p.handshake(c, host, port); err != nil {
		c.Close()
		return nil, err
	}
	c.SetDeadline(time.Time{})
	return c, nil
}

func (p Proxy) handshake(c net.Conn, host string, port uint16) error {
	method := byte(0)
	if p.User != "" {
		method = 2
	}
	if _, err := c.Write([]byte{5, 1, method}); err != nil {
		return err
	}
	var m [2]byte
	if _, err := io.ReadFull(c, m[:]); err != nil {
		return err
	}
	if m[0] != 5 || m[1] != method {
		return errors.New("the proxy refused the authentication method")
	}
	if method == 2 {
		req := append([]byte{1, byte(len(p.User))}, p.User...)
		req = append(append(req, byte(len(p.Pass))), p.Pass...)
		if _, err := c.Write(req); err != nil {
			return err
		}
		var a [2]byte
		if _, err := io.ReadFull(c, a[:]); err != nil {
			return err
		}
		if a[1] != 0 {
			return errors.New("the proxy refused the user name and password")
		}
	}
	req := []byte{5, 1, 0}
	if a, err := netip.ParseAddr(host); err == nil && a.Is4() {
		b := a.As4()
		req = append(append(req, 1), b[:]...)
	} else {
		if len(host) == 0 || len(host) > 255 {
			return fmt.Errorf("host %q: want 1 to 255 characters", host)
		}
		req = append(append(req, 3, byte(len(host))), host...)
	}
	req = binary.BigEndian.AppendUint16(req, port)
	if _, err := c.Write(req); err != nil {
		return err
	}
	var rep [4]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		return err
	}
	if rep[1] != 0 {
		return errors.New("the proxy refused the connection: reply " + strconv.Itoa(int(rep[1])))
	}
	skip := 0
	switch rep[3] {
	case 1:
		skip = 4 + 2
	case 4:
		skip = 16 + 2
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return err
		}
		skip = int(l[0]) + 2
	default:
		return errors.New("the proxy's reply has an unknown address type")
	}
	_, err := io.ReadFull(c, make([]byte, skip))
	return err
}
