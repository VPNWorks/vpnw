// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/VPNWorks/vpnw/internal/events"
	"github.com/VPNWorks/vpnw/internal/path"
	"github.com/VPNWorks/vpnw/internal/policy"
)

// Limits on what anyone on the internet can hold at an exit before showing
// a token. A connection gets ExitHandshakeTime for TLS and its request
// together. At most MaxPendingPerPeer connections from one address (one
// /64 for IPv6) may be waiting for that at once, and MaxPending in all;
// when all are taken, the oldest waiting connection of the address holding
// the most is closed to make room, so a flood from a few addresses can't
// keep clients with tokens out. A wrong token is answered after
// RefusedLoginDelay, which keeps guessing slow. Once logged in, a client
// may have MaxConnsPerClient connections open, so one token can't take
// every slot of the exit.
var (
	ExitHandshakeTime = 10 * time.Second
	MaxPending        = 1024
	MaxPendingPerPeer = 32
	RefusedLoginDelay = time.Second
	MaxConnsPerClient = 1024
)

// An exit records at most authDenyBurst auth.deny events in each
// authDenyWindow. It counts the rest, and the next one it records says how
// many it left out, in "unrecorded".
const (
	authDenyBurst  = 20
	authDenyWindow = 10 * time.Second
)

// Exit makes a broker the front of an exit, the server end of a path (vpnw
// exit). An exit takes HTTP CONNECT and SOCKS5 requests, inside TLS, from
// many clients. Each request has to carry a client's token as its proxy
// password, and is decided and sent by the same code as a run's requests,
// with that client's policy and from that client's path. So a client that
// skipped its own policy, or a stolen token, gets nothing that policy
// refuses.
//
// The conventions on the wire, which internal/path speaks from the other
// end:
//
//	                   HTTP CONNECT                   SOCKS5
//	token              Proxy-Authorization: Basic,    the password of the
//	                   the token as the password      user-and-password login
//	run and conn IDs   VPNW-Run: r-3f9a1c             the user name,
//	                   VPNW-Conn: 17                  r-3f9a1c/17
//	refused            403, VPNW-Rule and VPNW-Reason reply 2
//	wrong token        407                            login refused
//	health check       GET /health: 200 and the       a login, then nothing
//	                   exit's name, or 407
//
// A request that gives the token or an ID header twice is refused, so the
// exit never chooses between two. The IDs are optional: a client without
// vpnw sends none, and is decided and recorded like any other.
type Exit struct {
	// Name is the exit's name, the answer to a health check.
	Name    string
	Clients Clients
}

// Client is one client of an exit: the policy its requests are decided
// with, and the path they leave by (direct, from its fixed address).
type Client struct {
	Name   string
	Policy *policy.Policy
	Path   path.Path
	// Source is the address its connections leave from, for the record.
	Source string
}

// Clients finds the client a token belongs to, or nil. Login must take the
// same time whichever client the token comes closest to.
type Clients interface {
	Login(token string) *Client
}

// fields adds who asked to a connection's first event, at an exit: the
// client, the address it leaves from, where the request came from, and the
// client's own run and connection IDs, so its record and the exit's line up.
func (o origin) fields(f map[string]any) {
	if o.client == nil {
		return
	}
	f["client"] = o.client.Name
	if o.client.Source != "" {
		f["source"] = o.client.Source
	}
	if o.peer != "" {
		f["peer"] = o.peer
	}
	if o.run != "" {
		f["client_run"] = o.run
		f["client_conn"] = o.conn
	}
}

// parseRun checks a run ID a client sent: 1 to 64 letters, digits, dots,
// dashes and underscores, the same rule vpnw uses when it sends one.
func parseRun(s string) error {
	if s == "" || len(s) > 64 {
		return errors.New("a run ID has 1 to 64 characters")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return errors.New("a run ID has letters, digits, dots, dashes and underscores only")
		}
	}
	return nil
}

// parseConn checks a connection ID: a whole number from 1 up, in decimal,
// with no sign and no leading zero.
func parseConn(s string) (uint64, error) {
	if s == "" || len(s) > 20 || s[0] == '0' {
		return 0, errors.New("a connection ID is a whole number from 1 up")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errors.New("a connection ID is a whole number from 1 up")
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, errors.New("the connection ID is too large")
	}
	return n, nil
}

// idsFromHeaders reads the run and connection IDs from VPNW-Run and
// VPNW-Conn. Both or neither.
func idsFromHeaders(run, conn string) (string, uint64, error) {
	if run == "" && conn == "" {
		return "", 0, nil
	}
	if run == "" || conn == "" {
		return "", 0, errors.New("VPNW-Run and VPNW-Conn go together")
	}
	if err := parseRun(run); err != nil {
		return "", 0, fmt.Errorf("VPNW-Run: %v", err)
	}
	n, err := parseConn(conn)
	if err != nil {
		return "", 0, fmt.Errorf("VPNW-Conn: %v", err)
	}
	return run, n, nil
}

// idsFromUser reads the IDs from a SOCKS5 user name, RUN/CONN. A user name
// without a slash carries none.
func idsFromUser(u string) (string, uint64, error) {
	run, conn, ok := strings.Cut(u, "/")
	if !ok {
		return "", 0, nil
	}
	if strings.Contains(conn, "/") {
		return "", 0, errors.New("the user name holds RUN/CONN")
	}
	if err := parseRun(run); err != nil {
		return "", 0, err
	}
	n, err := parseConn(conn)
	if err != nil {
		return "", 0, err
	}
	return run, n, nil
}

// count returns how many times a header is given.
func (h *head) count(name string) int {
	n := 0
	for _, x := range h.headers {
		if strings.EqualFold(x.name, name) {
			n++
		}
	}
	return n
}

// waiter is a connection to an exit that hasn't logged in yet.
type waiter struct {
	key   string // the address it came from; for IPv6, its /64
	c     net.Conn
	since time.Time
	gone  bool
}

// peerKey is what the limit per address counts by: the address, or the /64
// of an IPv6 one, since anyone with one IPv6 address usually has its /64.
func peerKey(ip string) string {
	if a, err := netip.ParseAddr(ip); err == nil && a.Is6() && !a.Is4In6() {
		if p, err := a.Prefix(64); err == nil {
			return p.String()
		}
	}
	return ip
}

// waiting gives a connection that hasn't logged in yet a slot, closing
// another to make room when all are taken. It returns nil when the address
// it came from holds its share already.
func (b *Broker) waiting(key string, c net.Conn) *waiter {
	b.mu.Lock()
	if b.pending[key] >= MaxPendingPerPeer {
		b.mu.Unlock()
		return nil
	}
	var victim *waiter
	if len(b.waiters) >= MaxPending {
		most := 0
		for w := range b.waiters {
			if n := b.pending[w.key]; victim == nil || n > most || (n == most && w.since.Before(victim.since)) {
				victim, most = w, n
			}
		}
		if victim != nil {
			b.forget(victim)
		}
	}
	if b.waiters == nil {
		b.waiters, b.pending = map[*waiter]struct{}{}, map[string]int{}
	}
	w := &waiter{key: key, c: c, since: time.Now()}
	b.waiters[w] = struct{}{}
	b.pending[key]++
	b.mu.Unlock()
	if victim != nil {
		victim.c.Close()
	}
	return w
}

// forget lets a waiting connection's slot go; b.mu is held.
func (b *Broker) forget(w *waiter) {
	if w.gone {
		return
	}
	w.gone = true
	delete(b.waiters, w)
	if b.pending[w.key]--; b.pending[w.key] <= 0 {
		delete(b.pending, w.key)
	}
}

// doneWaiting lets a waiting connection's slot go. It reports whether the
// connection still had it: one closed to make room for another has not.
func (b *Broker) doneWaiting(w *waiter) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	had := !w.gone
	b.forget(w)
	return had
}

// clientIn counts a connection of a client that has logged in, if it has
// fewer than MaxConnsPerClient open.
func (b *Broker) clientIn(name string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.clientConns[name] >= MaxConnsPerClient {
		b.overLimit.Add(1)
		return false
	}
	if b.clientConns == nil {
		b.clientConns = map[string]int{}
	}
	b.clientConns[name]++
	return true
}

func (b *Broker) clientOut(name string) {
	b.mu.Lock()
	if b.clientConns[name]--; b.clientConns[name] <= 0 {
		delete(b.clientConns, name)
	}
	b.mu.Unlock()
}

// exitHandle serves one connection to an exit: TLS first, when the
// listener speaks it, then SOCKS5 if it starts with byte 5, otherwise HTTP.
func (b *Broker) exitHandle(c net.Conn) {
	peer, ip := "", ""
	if a := c.RemoteAddr(); a != nil {
		peer = a.String()
		ip = peer
		if h, _, err := net.SplitHostPort(peer); err == nil {
			ip = h
		}
	}
	w := b.waiting(peerKey(ip), c)
	if w == nil {
		return
	}
	defer b.doneWaiting(w)
	// Once a client has shown its token, its connection counts against the
	// client's share, MaxConnsPerClient, instead of the waiting ones', and
	// it gets the time a run's program gets. loggedIn reports false, and the
	// caller stops, when the connection was closed to make room before it
	// got this far, or when the client has its share open already.
	var counted string
	defer func() {
		if counted != "" {
			b.clientOut(counted)
		}
	}()
	loggedIn := func(name string) bool {
		if !b.doneWaiting(w) || !b.clientIn(name) {
			return false
		}
		counted = name
		c.SetWriteDeadline(time.Time{})
		c.SetReadDeadline(time.Now().Add(HandshakeTime))
		return true
	}
	c.SetDeadline(time.Now().Add(ExitHandshakeTime))
	if tc, ok := c.(*tls.Conn); ok {
		if err := tc.Handshake(); err != nil {
			b.tlsFailed.Add(1)
			return
		}
	}
	br := bufio.NewReaderSize(c, 16<<10)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	switch first[0] {
	case 0x05:
		b.exitSOCKS(c, br, peer, loggedIn)
	case 0x04:
		c.Write([]byte{0x00, 0x5b, 0, 0, 0, 0, 0, 0})
	default:
		b.exitHTTP(c, br, peer, loggedIn)
	}
}

// login finds the client whose token is the password in a Proxy-Authorization
// header. It returns nil and why when there is none.
func (b *Broker) login(v string) (*Client, string) {
	if v == "" {
		return nil, "no token; send it as the proxy password"
	}
	scheme, cred, ok := strings.Cut(v, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return nil, "the proxy credentials are not Basic"
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cred))
	if err != nil {
		return nil, "the proxy credentials are not valid base64"
	}
	_, token, ok := strings.Cut(string(raw), ":")
	if !ok || token == "" {
		return nil, "no token; send it as the proxy password"
	}
	if cl := b.Exit.Clients.Login(token); cl != nil {
		return cl, ""
	}
	return nil, "the token is not known here"
}

// refuseLogin records a request without a valid token, then waits
// RefusedLoginDelay before the caller answers it. The token itself is never
// recorded. Past authDenyBurst in a window, the event is only counted.
func (b *Broker) refuseLogin(peer, proto, why, host string, port int) {
	b.authDenied.Add(1)
	defer func() {
		select {
		case <-time.After(RefusedLoginDelay):
		case <-b.baseCtx().Done():
		}
	}()
	b.mu.Lock()
	now := b.now()
	if now.Sub(b.denyWindow) >= authDenyWindow {
		b.denyWindow, b.denyInWindow = now, 0
	}
	if b.denyInWindow >= authDenyBurst {
		b.denyUnrecorded++
		b.mu.Unlock()
		return
	}
	b.denyInWindow++
	left := b.denyUnrecorded
	b.denyUnrecorded = 0
	b.mu.Unlock()
	f := map[string]any{"proto": proto, "reason": why}
	if left > 0 {
		f["unrecorded"] = left
	}
	if peer != "" {
		f["peer"] = peer
	}
	if host != "" {
		if ip := net.ParseIP(host); ip != nil {
			f["ip"] = ip.String()
		} else {
			f["host"] = sanitize(host)
		}
		f["port"] = port
	}
	b.Bus.Emit(events.AuthDeny, 0, "", 0, f)
}

// headerSafe keeps a header value on one printable line.
func headerSafe(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s) && sb.Len() < 300; i++ {
		c := s[i]
		if c < 0x20 || c >= 0x7f {
			c = '?'
		}
		sb.WriteByte(c)
	}
	return sb.String()
}

// toClient is the reason for a refusal as the client is told it. When the
// client asked for a name, a reason that comes from an address the exit
// looked up stays in the exit's record, and the client hears only the
// rule, so a token can't be used to read the exit's DNS answers.
func toClient(d *policy.Decision, host string) string {
	if host != "" && (strings.Contains(d.Reason, " resolved to ") || d.Rule == "exit") {
		return fmt.Sprintf("an address %s resolves to at the exit is refused by %s", host, d.Rule)
	}
	return d.Reason
}

func (b *Broker) exitHTTP(c net.Conn, br *bufio.Reader, peer string, loggedIn func(string) bool) {
	h, err := readHead(br)
	if err != nil {
		if errors.Is(err, errHeadTooLarge) {
			httpReply(c, "431 Request Header Fields Too Large", "", "vpnw exit: request head too large\n")
		} else if err != io.EOF {
			httpReply(c, "400 Bad Request", "", "vpnw exit: "+err.Error()+"\n")
		}
		return
	}
	for _, name := range []string{"Proxy-Authorization", "VPNW-Run", "VPNW-Conn"} {
		if h.count(name) > 1 {
			httpReply(c, "400 Bad Request", "", "vpnw exit: "+name+" is given more than once\n")
			return
		}
	}
	health := h.method == "GET" && h.target == "/health"
	if h.method != "CONNECT" && !health {
		httpReply(c, "400 Bad Request", "", "vpnw exit: an exit takes CONNECT host:port, or SOCKS5\n")
		return
	}
	proto := "health"
	var host string
	var port int
	if !health {
		proto = "http-connect"
		if host, port, err = splitTarget(h.target); err != nil {
			httpReply(c, "400 Bad Request", "", "vpnw exit: "+err.Error()+"\n")
			return
		}
	}
	cl, why := b.login(h.get("Proxy-Authorization"))
	if cl == nil {
		b.refuseLogin(peer, proto, why, host, port)
		httpReply(c, "407 Proxy Authentication Required", "Proxy-Authenticate: Basic realm=\"vpnw exit\"\r\n", "vpnw exit: "+why+"\n")
		return
	}
	if !loggedIn(cl.Name) {
		httpReply(c, "429 Too Many Requests", "", fmt.Sprintf("vpnw exit: client %s has %d connections open here already\n", cl.Name, MaxConnsPerClient))
		return
	}
	if health {
		b.healthChecks.Add(1)
		httpReply(c, "200 OK", "", b.Exit.Name+"\n")
		return
	}
	run, conn, err := idsFromHeaders(h.get("VPNW-Run"), h.get("VPNW-Conn"))
	if err != nil {
		httpReply(c, "400 Bad Request", "", "vpnw exit: "+err.Error()+"\n")
		return
	}
	o := b.open(origin{client: cl, run: run, conn: conn, peer: peer}, host, port, proto)
	target := net.JoinHostPort(host, strconv.Itoa(port))
	switch {
	case o.denied != nil:
		why := toClient(o.denied, host)
		httpReply(c, "403 Forbidden", "VPNW-Rule: "+headerSafe(o.denied.Rule)+"\r\nVPNW-Reason: "+headerSafe(why)+"\r\n",
			fmt.Sprintf("vpnw exit: blocked %s (%s: %s)\n", target, o.denied.Rule, headerSafe(why)))
		return
	case o.err != nil:
		// The addresses the exit looked up stay at the exit.
		msg := o.err.Error()
		for _, x := range o.addrs {
			msg = strings.ReplaceAll(msg, x, "an address of "+host)
		}
		why := fmt.Sprintf("cannot reach %s: %s", target, msg)
		httpReply(c, "502 Bad Gateway", "VPNW-Reason: "+headerSafe(why)+"\r\n", "vpnw exit: "+why+"\n")
		return
	}
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		o.conn.Close()
		b.emitPath(o.path, events.ConnectionClose, o.id, map[string]any{"bytes_up": 0, "bytes_down": 0, "ms": b.now().Sub(o.start).Milliseconds()})
		return
	}
	b.finish(o, c, br, 0, 0, nil)
}

func (b *Broker) exitSOCKS(c net.Conn, br *bufio.Reader, peer string, loggedIn func(string) bool) {
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil || len(methods) == 0 {
		return
	}
	if bytes.IndexByte(methods, 0x02) < 0 {
		b.refuseLogin(peer, "socks5", "no token; an exit needs the user-and-password login, with the token as the password", "", 0)
		c.Write([]byte{0x05, 0xff})
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
		b.refuseLogin(peer, "socks5", "the login is not SOCKS5 user-and-password", "", 0)
		c.Write([]byte{0x01, 0x01})
		return
	}
	var cl *Client
	if len(pass) > 0 {
		cl = b.Exit.Clients.Login(string(pass))
	}
	if cl == nil {
		why := "the token is not known here"
		if len(pass) == 0 {
			why = "no token; send it as the password"
		}
		b.refuseLogin(peer, "socks5", why, "", 0)
		c.Write([]byte{0x01, 0x01})
		return
	}
	run, conn, err := idsFromUser(string(user))
	if err != nil {
		b.refuseLogin(peer, "socks5", "the user name should be RUN/CONN: "+err.Error(), "", 0)
		c.Write([]byte{0x01, 0x01})
		return
	}
	if !loggedIn(cl.Name) {
		// SOCKS5 has no word for busy: the login is refused.
		c.Write([]byte{0x01, 0x01})
		return
	}
	c.Write([]byte{0x01, 0x00})
	cmd, host, port, ok := socksRequest(c, br)
	if !ok {
		return
	}
	from := origin{client: cl, run: run, conn: conn, peer: peer}
	if cmd != 0x01 {
		b.unsupported(from, c, host, port, cmd)
		return
	}
	o := b.open(from, host, port, "socks5")
	if o.conn == nil {
		socksReply(c, o.socks)
		return
	}
	if err := socksReply(c, 0x00); err != nil {
		o.conn.Close()
		b.emitPath(o.path, events.ConnectionClose, o.id, map[string]any{"bytes_up": 0, "bytes_down": 0, "ms": b.now().Sub(o.start).Milliseconds()})
		return
	}
	b.finish(o, c, br, 0, 0, nil)
}
