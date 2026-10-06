// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package server runs an exit: a TLS listener with HTTP CONNECT and SOCKS5
// behind it. Every request comes with a client's token and is decided with
// that client's policy before anything is dialed; allowed requests leave from
// the client's fixed source address, and every step goes into the exit's
// record with the client's run and connection IDs.
//
// It reuses the Agent's pieces: the policy engine through the request plan
// (exit.Client.Decide), the direct path for dialing, the resolver, and the
// event model for the record. The front ends are its own, because an exit
// serves many clients, each known by a token, where the Agent's broker
// serves one program.
package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vpnw.com/vpnw/internal/events"
	"vpnw.com/vpnw/internal/exit"
	"vpnw.com/vpnw/internal/path"
	"vpnw.com/vpnw/internal/policy"
)

// Limits on what a client may send before its request is decided.
const (
	HandshakeTime = 30 * time.Second
	MaxConns      = 4096
	DialTimeout   = 15 * time.Second
)

// Stats are the exit's totals since it started.
type Stats struct {
	Connections int64 `json:"connections"`
	Opened      int64 `json:"opened"`
	Denied      int64 `json:"denied"`
	Failed      int64 `json:"failed"`
	AuthDenied  int64 `json:"auth_denied"`
	TLSFailed   int64 `json:"tls_failed"`
	Health      int64 `json:"health_checks"`
	BytesUp     int64 `json:"bytes_up"`
	BytesDown   int64 `json:"bytes_down"`
}

// Server is one exit.
type Server struct {
	Config *exit.Config
	// TLS, if set, is the exit's certificate; Serve speaks TLS with every
	// client before anything else. Tests can leave it nil and hand plain
	// connections to Handle.
	TLS      *tls.Config
	Resolver path.Resolver
	Bus      *events.Bus
	// Dial connects to a destination from a source address. nil dials TCP
	// through the Agent's direct path, bound to the source address.
	Dial        func(ctx context.Context, src netip.Addr, dst net.IP, port int) (net.Conn, error)
	DialTimeout time.Duration
	Clock       func() time.Time

	seq                                          atomic.Uint64
	wg                                           sync.WaitGroup
	mu                                           sync.Mutex
	conns                                        map[net.Conn]struct{}
	closed                                       bool
	connections, opened, denied, failed          atomic.Int64
	authDenied, tlsFailed, health, up, downBytes atomic.Int64
}

// Stats returns the totals so far.
func (s *Server) Stats() Stats {
	return Stats{Connections: s.connections.Load(), Opened: s.opened.Load(), Denied: s.denied.Load(), Failed: s.failed.Load(),
		AuthDenied: s.authDenied.Load(), TLSFailed: s.tlsFailed.Load(), Health: s.health.Load(),
		BytesUp: s.up.Load(), BytesDown: s.downBytes.Load()}
}

func (s *Server) now() time.Time {
	if s.Clock != nil {
		return s.Clock()
	}
	return time.Now()
}

func (s *Server) emit(typ string, conn uint64, f map[string]any) {
	s.Bus.Emit(typ, 0, s.Config.Name, conn, f)
}

// Serve accepts connections until l is closed.
func (s *Server) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return err
		}
		if !s.track(c) {
			c.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.untrack(c)
			s.serveConn(c)
		}()
	}
}

func (s *Server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.conns) >= MaxConns {
		return false
	}
	if s.conns == nil {
		s.conns = map[net.Conn]struct{}{}
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

// Shutdown closes every connection and waits up to grace for their
// handlers to finish their records.
func (s *Server) Shutdown(grace time.Duration) {
	s.mu.Lock()
	s.closed = true
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(grace):
	}
}

func (s *Server) serveConn(c net.Conn) {
	defer c.Close()
	if s.TLS != nil {
		tc := tls.Server(c, s.TLS)
		ctx, cancel := context.WithTimeout(context.Background(), HandshakeTime)
		err := tc.HandshakeContext(ctx)
		cancel()
		if err != nil {
			s.tlsFailed.Add(1)
			return
		}
		c = tc
	}
	s.Handle(c)
}

// Handle serves one client connection after TLS: SOCKS5 if it starts with
// byte 5, otherwise HTTP.
func (s *Server) Handle(c net.Conn) {
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(HandshakeTime))
	br := bufio.NewReaderSize(c, 16<<10)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	peer := ""
	if a := c.RemoteAddr(); a != nil {
		peer = a.String()
	}
	if first[0] == 0x05 {
		s.socks(c, br, peer)
		return
	}
	s.http(c, br, peer)
}

// refusal is why a request was refused before any dial.
type refusal struct{ rule, reason string }

// outcome of trying to open a connection for a client.
type outcome struct {
	conn   net.Conn
	id     uint64
	start  time.Time
	denied *refusal
	err    error
	socks  byte
}

// open decides one request with the client's policy and, if it is allowed,
// dials it from the client's source address. Every step is recorded.
func (s *Server) open(cl *exit.Client, ids exit.IDs, rawHost string, port int, proto, peer string) outcome {
	id := s.seq.Add(1)
	start := s.now()
	s.connections.Add(1)
	host, ip, nerr := policy.NormalizeHost(rawHost)
	f := map[string]any{"port": port, "proto": proto, "client": cl.Name, "peer": peer}
	switch {
	case nerr != nil:
		f["host"] = sanitize(rawHost)
	case host != "":
		f["host"] = host
	default:
		f["ip"] = ip.String()
	}
	if ids.Run != "" {
		f["client_run"], f["client_conn"] = ids.Run, ids.Conn
	}
	s.emit(events.ConnectionAttempt, id, f)
	deny := func(rule, reason, text string) outcome {
		s.denied.Add(1)
		df := map[string]any{"rule": rule, "reason": reason}
		if text != "" {
			df["text"] = text
		}
		s.emit(events.PolicyDeny, id, df)
		return outcome{id: id, start: start, denied: &refusal{rule, reason}, socks: 0x02}
	}
	fail := func(err error, code byte) outcome {
		s.failed.Add(1)
		s.emit(events.ConnectionError, id, map[string]any{"error": err.Error()})
		return outcome{id: id, start: start, err: err, socks: code}
	}
	// The source address comes first: asking for an address that is not
	// the client's is refused before anything else happens.
	src, err := cl.SourceFor(ids.Source)
	if err != nil {
		return deny("source", err.Error(), "")
	}
	timeout := s.DialTimeout
	if timeout == 0 {
		timeout = DialTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// The decision is the Agent's request plan. Its DNS steps are recorded
	// in the order the Agent's broker records them: before the decision when
	// an address can change it, after it when the lookup is only to connect.
	type pending struct {
		typ string
		f   map[string]any
	}
	var dns []pending
	lookup := func(h string) ([]net.IP, error) {
		dns = append(dns, pending{events.DNSQuery, map[string]any{"host": h}})
		t0 := s.now()
		ips, err := s.Resolver.LookupIP(ctx, h)
		if err == nil && len(ips) == 0 {
			err = errors.New("no addresses")
		}
		if err != nil {
			dns = append(dns, pending{events.DNSResult, map[string]any{"host": h, "error": dnsErr(err)}})
			return nil, err
		}
		list := make([]string, len(ips))
		for i, a := range ips {
			list[i] = a.String()
		}
		dns = append(dns, pending{events.DNSResult, map[string]any{"host": h, "ips": list, "ms": s.now().Sub(t0).Milliseconds()}})
		return ips, nil
	}
	flush := func() {
		for _, p := range dns {
			s.emit(p.typ, id, p.f)
		}
		dns = nil
	}
	pl := cl.Decide(rawHost, port, lookup)
	if host != "" && cl.Policy.NeedsAddresses(policy.Target{Host: host, Port: port}) {
		flush()
	}
	allow := func() {
		af := map[string]any{"rule": pl.Rule, "reason": pl.Reason}
		if pl.Text != "" {
			af["text"] = pl.Text
		}
		s.emit(events.PolicyAllow, id, af)
		flush()
	}
	switch pl.Outcome {
	case "denied":
		return deny(pl.Rule, pl.Reason, pl.Text)
	case "failed":
		if pl.Rule != "" {
			allow() // allowed, then the lookup to connect failed
		}
		code := byte(0x01)
		if strings.HasPrefix(pl.Error, "dns: ") {
			code = 0x04
		}
		return fail(errors.New(pl.Error), code)
	}
	allow()
	var cands []net.IP
	if pl.IP != "" {
		cands = []net.IP{net.ParseIP(pl.IP)}
	} else {
		for _, a := range pl.Addrs {
			cands = append(cands, net.ParseIP(a))
		}
	}
	t0 := s.now()
	var lastErr error
	tried := 0
	for _, cand := range cands {
		if (cand.To4() != nil) != src.Is4() {
			continue // a source address of the other family cannot reach it
		}
		tried++
		conn, err := s.dial(ctx, src, cand, port)
		if err != nil {
			lastErr = err
			continue
		}
		of := map[string]any{"ip": cand.String(), "source": src.String(), "ms": s.now().Sub(t0).Milliseconds()}
		if host != "" {
			of["host"] = host
		}
		s.opened.Add(1)
		s.emit(events.ConnectionOpen, id, of)
		return outcome{conn: conn, id: id, start: start}
	}
	if tried == 0 {
		return fail(fmt.Errorf("no address of %s is reachable from source %s", target(host, ip, port), src), 0x08)
	}
	code := byte(0x05)
	if strings.Contains(lastErr.Error(), "unreachable") {
		code = 0x03
	}
	return fail(errors.New(dialErr(lastErr)), code)
}

func (s *Server) dial(ctx context.Context, src netip.Addr, dst net.IP, port int) (net.Conn, error) {
	if s.Dial != nil {
		return s.Dial(ctx, src, dst, port)
	}
	d := &path.Direct{Dialer: net.Dialer{LocalAddr: &net.TCPAddr{IP: src.AsSlice()}}}
	return d.Dial(ctx, "", dst, port)
}

func target(host string, ip net.IP, port int) string {
	if host == "" && ip != nil {
		host = ip.String()
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func dnsErr(err error) string {
	var de *net.DNSError
	if errors.As(err, &de) {
		switch {
		case de.IsNotFound:
			return "no such host"
		case de.IsTimeout:
			return "timed out"
		}
		return de.Err
	}
	return err.Error()
}

func dialErr(err error) string {
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		return op.Err.Error()
	}
	return err.Error()
}

// sanitize keeps a refused host printable and short in the record.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 128 {
			b.WriteString("...")
			break
		}
		if r < 0x20 || r == 0x7f {
			r = '?'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// refuseAuth records a client that came without a valid token.
func (s *Server) refuseAuth(peer, proto, host string, port int, reason string) {
	s.authDenied.Add(1)
	f := map[string]any{"peer": peer, "proto": proto, "reason": reason}
	if host != "" {
		f["host"], f["port"] = sanitize(host), port
	}
	s.emit(exit.AuthDeny, 0, f)
}

func tokenReason(token string) string {
	if token == "" {
		return "no token"
	}
	return "unknown token"
}

// relay carries bytes both ways until both sides are done, then records the
// close.
func (s *Server) relay(o outcome, client net.Conn, fromClient io.Reader) {
	defer o.conn.Close()
	client.SetDeadline(time.Time{})
	var up, down int64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, err := io.Copy(o.conn, fromClient)
		up = n
		if err != nil {
			o.conn.Close()
			client.Close()
			return
		}
		closeWrite(o.conn)
	}()
	go func() {
		defer wg.Done()
		n, err := io.Copy(client, o.conn)
		down = n
		if err != nil {
			o.conn.Close()
			client.Close()
			return
		}
		closeWrite(client)
	}()
	wg.Wait()
	s.recordClose(o, up, down)
}

func (s *Server) recordClose(o outcome, up, down int64) {
	s.up.Add(up)
	s.downBytes.Add(down)
	s.emit(events.ConnectionClose, o.id, map[string]any{"bytes_up": up, "bytes_down": down, "ms": s.now().Sub(o.start).Milliseconds()})
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}

// ---- SOCKS5 ----

func (s *Server) socks(c net.Conn, br *bufio.Reader, peer string) {
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil || len(methods) == 0 {
		return
	}
	// The token travels as the password of the user-and-password login,
	// which every request must use.
	if !bytes.Contains(methods, []byte{0x02}) {
		c.Write([]byte{0x05, 0xff})
		s.refuseAuth(peer, "socks5", "", 0, "no token (the client did not offer the user-and-password login)")
		return
	}
	c.Write([]byte{0x05, 0x02})
	var v [2]byte
	if _, err := io.ReadFull(br, v[:]); err != nil {
		return
	}
	user := make([]byte, v[1])
	if _, err := io.ReadFull(br, user); err != nil {
		return
	}
	var pl [1]byte
	if _, err := io.ReadFull(br, pl[:]); err != nil {
		return
	}
	pass := make([]byte, pl[0])
	if _, err := io.ReadFull(br, pass); err != nil {
		return
	}
	if v[0] != 0x01 {
		c.Write([]byte{0x01, 0x01})
		return
	}
	cl := s.Config.Lookup(string(pass))
	if cl == nil {
		c.Write([]byte{0x01, 0x01})
		s.refuseAuth(peer, "socks5", "", 0, tokenReason(string(pass)))
		return
	}
	ids, err := exit.ParseSOCKSUser(string(user))
	if err != nil {
		c.Write([]byte{0x01, 0x01})
		s.refuseAuth(peer, "socks5", "", 0, "client "+cl.Name+": bad IDs in the user name: "+err.Error())
		return
	}
	c.Write([]byte{0x01, 0x00})
	var req [4]byte
	if _, err := io.ReadFull(br, req[:]); err != nil {
		return // a health check logs in and leaves
	}
	if req[0] != 0x05 {
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		var a [4]byte
		if _, err := io.ReadFull(br, a[:]); err != nil {
			return
		}
		host = net.IP(a[:]).String()
	case 0x04:
		var a [16]byte
		if _, err := io.ReadFull(br, a[:]); err != nil {
			return
		}
		host = net.IP(a[:]).String()
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(br, l[:]); err != nil {
			return
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(br, name); err != nil {
			return
		}
		host = string(name)
	default:
		socksReply(c, 0x08, nil)
		return
	}
	var pb [2]byte
	if _, err := io.ReadFull(br, pb[:]); err != nil {
		return
	}
	port := int(pb[0])<<8 | int(pb[1])
	if req[1] != 0x01 {
		s.unsupported(cl, ids, host, port, req[1], peer)
		socksReply(c, 0x07, nil)
		return
	}
	o := s.open(cl, ids, host, port, "socks5", peer)
	if o.conn == nil {
		socksReply(c, o.socks, nil)
		return
	}
	if err := socksReply(c, 0x00, o.conn.LocalAddr()); err != nil {
		o.conn.Close()
		s.recordClose(o, 0, 0)
		return
	}
	s.relay(o, c, br)
}

// unsupported refuses SOCKS5 BIND and UDP ASSOCIATE, as the Agent does.
func (s *Server) unsupported(cl *exit.Client, ids exit.IDs, host string, port int, cmd byte, peer string) {
	id := s.seq.Add(1)
	s.connections.Add(1)
	s.denied.Add(1)
	proto, what := "socks5-bind", "incoming connections (SOCKS5 BIND)"
	if cmd == 0x03 {
		proto, what = "socks5-udp", "UDP (SOCKS5 UDP ASSOCIATE)"
	}
	f := map[string]any{"port": port, "proto": proto, "client": cl.Name, "peer": peer}
	if ip := net.ParseIP(host); ip != nil {
		f["ip"] = ip.String()
	} else {
		f["host"] = sanitize(host)
	}
	if ids.Run != "" {
		f["client_run"], f["client_conn"] = ids.Run, ids.Conn
	}
	s.emit(events.ConnectionAttempt, id, f)
	s.emit(events.PolicyDeny, id, map[string]any{"rule": "unsupported", "reason": what + " is not supported at the exit"})
}

// socksReply answers a SOCKS5 request. On success bound is where the exit's
// connection leaves from: the client's source address.
func socksReply(c net.Conn, code byte, bound net.Addr) error {
	rep := []byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if ta, ok := bound.(*net.TCPAddr); ok {
		if v4 := ta.IP.To4(); v4 != nil {
			copy(rep[4:8], v4)
			rep[8], rep[9] = byte(ta.Port>>8), byte(ta.Port)
		} else {
			rep = append([]byte{0x05, code, 0x00, 0x04}, ta.IP.To16()...)
			rep = append(rep, byte(ta.Port>>8), byte(ta.Port))
		}
	}
	_, err := c.Write(rep)
	return err
}
