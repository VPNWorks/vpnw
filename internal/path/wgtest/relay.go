// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package wgtest

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Relay sits between vpnw and a test peer, on the path WireGuard's UDP
// takes, and breaks it on demand: it can drop handshakes, go silent, add
// delay, or send everything to another peer. It is Lab's fault injector;
// it runs in tests only.
type Relay struct {
	Port int // its UDP port on 127.0.0.1; point the client's Endpoint here

	pc     net.PacketConn
	mu     sync.Mutex
	client net.Addr      // where the client's packets come from
	toPeer *net.UDPConn  // to the peer, from a port of the relay's own
	target atomic.Int64  // the peer's port
	silent atomic.Bool   // drop everything, both ways
	dropHS atomic.Int64  // drop this many more handshake initiations
	delay  atomic.Int64  // nanoseconds added each way
	seenHS atomic.Int64  // handshake initiations seen
	fwd    atomic.Int64  // packets forwarded, both ways
	done   chan struct{} //
}

// WireGuard message types, the first byte of every packet.
const (
	msgInitiation = 1
	msgResponse   = 2
)

// NewRelay relays to the test peer on 127.0.0.1:peerPort.
func NewRelay(peerPort int) (*Relay, error) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	up, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		pc.Close()
		return nil, err
	}
	r := &Relay{Port: pc.LocalAddr().(*net.UDPAddr).Port, pc: pc, toPeer: up, done: make(chan struct{})}
	r.target.Store(int64(peerPort))
	go r.fromClient()
	go r.fromPeer()
	return r, nil
}

// Silence drops every packet both ways until it is called with false: the
// peer seems to have vanished.
func (r *Relay) Silence(on bool) { r.silent.Store(on) }

// DropHandshakes drops the next n handshake initiations from the client.
func (r *Relay) DropHandshakes(n int) { r.dropHS.Store(int64(n)) }

// Delay adds d to every packet, each way.
func (r *Relay) Delay(d time.Duration) { r.delay.Store(int64(d)) }

// Redirect sends the client's packets to another peer from now on: a
// network that reroutes the tunnel to an impostor.
func (r *Relay) Redirect(port int) { r.target.Store(int64(port)) }

// Handshakes is how many handshake initiations the client has sent.
func (r *Relay) Handshakes() int64 { return r.seenHS.Load() }

// Forwarded is how many packets went through, both ways.
func (r *Relay) Forwarded() int64 { return r.fwd.Load() }

func (r *Relay) later(f func()) {
	if d := time.Duration(r.delay.Load()); d > 0 {
		time.AfterFunc(d, f)
		return
	}
	f()
}

func (r *Relay) fromClient() {
	buf := make([]byte, 65536)
	for {
		n, from, err := r.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		r.mu.Lock()
		r.client = from
		r.mu.Unlock()
		if n > 0 && buf[0] == msgInitiation {
			r.seenHS.Add(1)
			if r.dropHS.Load() > 0 {
				r.dropHS.Add(-1)
				continue
			}
		}
		if r.silent.Load() {
			continue
		}
		b := append([]byte(nil), buf[:n]...)
		to := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(r.target.Load())}
		r.later(func() {
			r.toPeer.WriteTo(b, to)
			r.fwd.Add(1)
		})
	}
}

func (r *Relay) fromPeer() {
	buf := make([]byte, 65536)
	for {
		n, _, err := r.toPeer.ReadFrom(buf)
		if err != nil {
			return
		}
		if r.silent.Load() {
			continue
		}
		r.mu.Lock()
		c := r.client
		r.mu.Unlock()
		if c == nil {
			continue
		}
		b := append([]byte(nil), buf[:n]...)
		r.later(func() {
			r.pc.WriteTo(b, c)
			r.fwd.Add(1)
		})
	}
}

// Close stops the relay.
func (r *Relay) Close() {
	r.pc.Close()
	r.toPeer.Close()
}

// ConfigVia is the client's wg-quick file with its Endpoint at the relay.
func (s *Server) ConfigVia(r *Relay) string {
	return s.configAt(s.client.priv, r.Port)
}

// FullConfigVia is ConfigVia for a full tunnel, AllowedIPs = 0.0.0.0/0, the
// way most VPN providers hand configs out.
func (s *Server) FullConfigVia(r *Relay) string {
	return s.configAllowed(s.client.priv, r.Port, "0.0.0.0/0")
}
