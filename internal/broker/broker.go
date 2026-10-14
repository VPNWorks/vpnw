// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package broker is where a workload's connections are decided. It accepts
// HTTP proxy (CONNECT and plain HTTP) and SOCKS5 requests, asks the policy,
// dials through the chosen path, relays bytes and reports every step as an
// event. The sealed backend makes it the only way out of the workload's
// network namespace; the broker itself does not know or care how it was
// reached.
package broker

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/VPNWorks/vpnw/internal/events"
	"github.com/VPNWorks/vpnw/internal/path"
	"github.com/VPNWorks/vpnw/internal/policy"
)

// Limits on what a client may send before its connection is decided.
const (
	MaxHeadBytes   = 64 << 10
	MaxHeaderLines = 100
	HandshakeTime  = 30 * time.Second
	MaxConns       = 4096
)

// Stats are the run's totals.
type Stats struct {
	Connections int64 `json:"connections"`
	Opened      int64 `json:"opened"`  // reached the destination
	Allowed     int64 `json:"allowed"` // passed the policy, or no policy; may still fail to connect
	Denied      int64 `json:"denied"`
	Failed      int64 `json:"failed"`
	BytesUp     int64 `json:"bytes_up"`
	BytesDown   int64 `json:"bytes_down"`
	// At an exit: logins refused, health checks answered, and connections
	// that never finished TLS.
	AuthDenied   int64 `json:"auth_denied,omitempty"`
	HealthChecks int64 `json:"health_checks,omitempty"`
	TLSFailed    int64 `json:"tls_failed,omitempty"`
}

// Guard is a further check on a connection the policy allowed, such as a
// Guard plugin. A Guard can only refuse; an error is a refusal.
type Guard interface {
	Name() string
	Check(ctx context.Context, r GuardRequest) (deny bool, reason string, err error)
}

// GuardRequest is what a Guard is told about one connection.
type GuardRequest struct {
	Run   string `json:"run"`
	Conn  uint64 `json:"conn"`
	PID   int    `json:"pid,omitempty"`
	Path  string `json:"path"`
	Host  string `json:"host,omitempty"`
	IP    string `json:"ip,omitempty"`
	Port  int    `json:"port"`
	Proto string `json:"proto"`
	// Client is the exit's client the connection came from, at an exit.
	Client string `json:"client,omitempty"`
}

// Broker decides and carries connections for one run.
type Broker struct {
	Policy *policy.Policy // nil: no policy, every valid destination is allowed
	// Guards are asked, in order, about every connection the policy
	// allowed. Any of them can refuse it; one that fails refuses it too.
	Guards   []Guard
	Path     path.Path
	Resolver path.Resolver
	Bus      *events.Bus
	Clock    func() time.Time
	// Token, if set, must be presented as proxy credentials (user "vpnw").
	Token       string
	DialTimeout time.Duration
	// Exit, if set, makes the broker the front of an exit (vpnw exit): it
	// takes HTTP CONNECT and SOCKS5 from many clients, each known by a token,
	// and decides and sends each request with that client's policy and path.
	// Policy, Path and Token are then not used. See exit.go.
	Exit *Exit

	pid                                          atomic.Int64
	seq                                          atomic.Uint64
	active                                       atomic.Int64
	wg                                           sync.WaitGroup
	mu                                           sync.Mutex
	conns                                        map[net.Conn]struct{}
	ups                                          map[net.Conn]struct{} // open connections out, through the path
	closed                                       bool
	baseOnce                                     sync.Once
	base                                         context.Context // cancelled by Shutdown
	stop                                         context.CancelFunc
	connections, opened, allowed, denied, failed atomic.Int64
	bytesUp, bytesDown                           atomic.Int64
	authDenied, healthChecks, tlsFailed          atomic.Int64
	// At an exit, under mu: connections not yet logged in, by the address
	// they came from and in all, and the auth.deny events of this window.
	pending        map[string]int
	pendingAll     int
	denyWindow     time.Time
	denyInWindow   int
	denyUnrecorded int64
}

// baseCtx is the context every connection's lookups and dials run under;
// Shutdown cancels it, so none is left waiting when the run ends.
func (b *Broker) baseCtx() context.Context {
	b.baseOnce.Do(func() { b.base, b.stop = context.WithCancel(context.Background()) })
	return b.base
}

// errRunEnded is a connection's outcome when the run ended while it was
// still being looked up or dialled.
var errRunEnded = errors.New("the run ended before the connection opened")

// SetPID records the workload's process id for events.
func (b *Broker) SetPID(pid int) { b.pid.Store(int64(pid)) }

func (b *Broker) now() time.Time {
	if b.Clock != nil {
		return b.Clock()
	}
	return time.Now()
}

// emitPath emits an event of a connection that went by the path pathID; at
// an exit, each client has a path of its own.
func (b *Broker) emitPath(pathID, typ string, conn uint64, f map[string]any) {
	b.Bus.Emit(typ, int(b.pid.Load()), pathID, conn, f)
}

func (b *Broker) runID() string {
	if b.Bus == nil {
		return ""
	}
	return b.Bus.Run()
}

// Stats returns the totals so far.
func (b *Broker) Stats() Stats {
	return Stats{
		Connections: b.connections.Load(), Opened: b.opened.Load(), Allowed: b.allowed.Load(), Denied: b.denied.Load(),
		Failed: b.failed.Load(), BytesUp: b.bytesUp.Load(), BytesDown: b.bytesDown.Load(),
		AuthDenied: b.authDenied.Load(), HealthChecks: b.healthChecks.Load(), TLSFailed: b.tlsFailed.Load(),
	}
}

// Serve accepts connections until l is closed. Any other error from Accept,
// such as running out of file descriptors under a flood of connections, is
// waited out, so a burst can't stop the broker.
func (b *Broker) Serve(l net.Listener) error {
	wait := 5 * time.Millisecond
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			time.Sleep(wait)
			if wait *= 2; wait > time.Second {
				wait = time.Second
			}
			continue
		}
		wait = 5 * time.Millisecond
		if !b.track(c) {
			c.Close()
			continue
		}
		go func() {
			defer b.wg.Done()
			defer b.untrack(c)
			b.Handle(c)
		}()
	}
}

// track registers a connection from a client and counts its handler in
// the wait group, both under the lock that Shutdown takes, so no handler
// starts once Shutdown has begun waiting.
func (b *Broker) track(c net.Conn) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || len(b.conns) >= MaxConns {
		return false
	}
	if b.conns == nil {
		b.conns = map[net.Conn]struct{}{}
	}
	b.conns[c] = struct{}{}
	b.wg.Add(1)
	return true
}

// trackUp registers a connection out through the path, so Shutdown can
// close it; a run already ending closes it at once.
func (b *Broker) trackUp(c net.Conn) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		c.Close()
		return
	}
	if b.ups == nil {
		b.ups = map[net.Conn]struct{}{}
	}
	b.ups[c] = struct{}{}
}

func (b *Broker) untrackUp(c net.Conn) {
	b.mu.Lock()
	delete(b.ups, c)
	b.mu.Unlock()
}

func (b *Broker) untrack(c net.Conn) {
	b.mu.Lock()
	delete(b.conns, c)
	b.mu.Unlock()
}

// Shutdown closes every open connection and waits up to grace for their
// handlers to finish writing their events.
func (b *Broker) Shutdown(grace time.Duration) {
	b.mu.Lock()
	b.closed = true
	for c := range b.conns {
		c.Close()
	}
	// The other side too: a connection whose path has gone silent would
	// otherwise wait on it for ever, and never be closed in the record.
	for c := range b.ups {
		c.Close()
	}
	b.mu.Unlock()
	// Connections still being looked up or dialled stop now, and each is
	// recorded with errRunEnded, so none is left without an outcome.
	b.baseCtx()
	b.stop()
	done := make(chan struct{})
	go func() { b.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(grace):
	}
}

// Handle serves one client connection: SOCKS5 if it starts with byte 5,
// otherwise HTTP.
func (b *Broker) Handle(c net.Conn) {
	defer c.Close()
	if b.Exit != nil {
		b.exitHandle(c)
		return
	}
	c.SetReadDeadline(time.Now().Add(HandshakeTime))
	br := bufio.NewReaderSize(c, 16<<10)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	switch first[0] {
	case 0x05:
		b.socks(c, br)
	case 0x04:
		// SOCKS4 carries no host names and no way to explain a refusal.
		c.Write([]byte{0x00, 0x5b, 0, 0, 0, 0, 0, 0})
	default:
		b.http(c, br)
	}
}

// outcome of trying to open a connection.
type outcome struct {
	conn   net.Conn
	id     uint64
	start  time.Time
	denied *policy.Decision
	err    error
	socks  byte   // SOCKS5 reply code on failure
	path   string // the ID of the path it went by, for its later events
}

// origin is who asked for a connection. The zero origin is the broker's own
// program; at an exit it is a client, with the run and connection IDs it
// sent, if any, and the address it came from.
type origin struct {
	client *Client
	run    string
	conn   uint64
	peer   string
}

// open decides and dials one destination, emitting events for each step:
// with the broker's own policy and path, or, at an exit, with the client's.
func (b *Broker) open(from origin, rawHost string, port int, proto string) outcome {
	pol, p := b.Policy, b.Path
	if from.client != nil {
		pol, p = from.client.Policy, from.client.Path
	}
	o := b.decide(from, pol, p, rawHost, port, proto)
	o.path = p.ID()
	return o
}

// decide is open's work, with the policy and path chosen.
func (b *Broker) decide(from origin, pol *policy.Policy, p path.Path, rawHost string, port int, proto string) outcome {
	id := b.seq.Add(1)
	start := b.now()
	b.connections.Add(1)
	pathID := p.ID()
	emit := func(typ string, f map[string]any) { b.emitPath(pathID, typ, id, f) }
	host, ip, nerr := policy.NormalizeHost(rawHost)
	f := map[string]any{"port": port, "proto": proto}
	switch {
	case nerr != nil:
		f["host"] = sanitize(rawHost)
	case host != "":
		f["host"] = host
	default:
		f["ip"] = ip.String()
	}
	from.fields(f)
	emit(events.ConnectionAttempt, f)
	if from.client != nil && pol == nil {
		// An exit never treats a client without a policy as allowed.
		d := policy.Decision{Allow: false, Rule: "no-policy", Reason: "the exit has no policy for client " + from.client.Name}
		b.denied.Add(1)
		emit(events.PolicyDeny, map[string]any{"rule": d.Rule, "reason": d.Reason})
		return outcome{id: id, start: start, denied: &d, socks: 0x02}
	}
	if nerr != nil {
		reason := strings.TrimPrefix(nerr.Error(), policy.ErrInvalid.Error()+": ")
		if pol != nil {
			d := policy.Decision{Allow: false, Rule: "invalid", Reason: reason}
			b.denied.Add(1)
			emit(events.PolicyDeny, map[string]any{"rule": d.Rule, "reason": d.Reason})
			return outcome{id: id, start: start, denied: &d, socks: 0x02}
		}
		b.failed.Add(1)
		emit(events.ConnectionError, map[string]any{"error": reason})
		return outcome{id: id, start: start, err: errors.New(reason), socks: 0x04}
	}
	if port < 1 || port > 65535 {
		b.failed.Add(1)
		emit(events.ConnectionError, map[string]any{"error": "port out of range"})
		return outcome{id: id, start: start, err: errors.New("port out of range"), socks: 0x01}
	}
	t := policy.Target{Host: host, IP: ip, Port: port, RemoteDNS: p.RemoteDNS()}
	timeout := b.DialTimeout
	if timeout == 0 {
		timeout = path.DialTimeout
	}
	ctx, cancel := context.WithTimeout(b.baseCtx(), timeout)
	defer cancel()
	// The path sends the run and connection IDs to an exit, and says which
	// exit answered and when a list of exits moved on.
	ci := &path.Conn{Run: b.runID(), ID: id, Switched: func(from, to, reason string, ms int64) {
		emit(events.PathSwitch, map[string]any{"from": from, "to": to, "error": reason, "ms": ms})
	}}
	ctx = path.WithConn(ctx, ci)

	var addrs []net.IP
	resolve := func() error {
		emit(events.DNSQuery, map[string]any{"host": host})
		t0 := b.now()
		ips, err := b.Resolver.LookupIP(ctx, host)
		if err == nil && len(ips) == 0 {
			err = errors.New("no addresses")
		}
		if err != nil {
			msg := dnsErr(err)
			emit(events.DNSResult, map[string]any{"host": host, "error": msg})
			return errors.New("dns: " + msg)
		}
		list := make([]string, len(ips))
		for i, a := range ips {
			list[i] = a.String()
		}
		emit(events.DNSResult, map[string]any{"host": host, "ips": list, "ms": b.now().Sub(t0).Milliseconds()})
		addrs = ips
		return nil
	}
	fail := func(err error, code byte) outcome {
		// A lookup or dial cut off by the end of the run says so; any
		// other failure keeps its own reason, even if it raced the end.
		if b.baseCtx().Err() != nil && (errors.Is(err, context.Canceled) || strings.Contains(err.Error(), context.Canceled.Error())) {
			err = errRunEnded
		}
		b.failed.Add(1)
		ef := map[string]any{"error": err.Error()}
		if ci.Exit != "" {
			ef["exit"] = ci.Exit
		}
		emit(events.ConnectionError, ef)
		return outcome{id: id, start: start, err: err, socks: code}
	}

	if pol != nil {
		var d policy.Decision
		if pol.NeedsAddresses(t) {
			if err := resolve(); err != nil {
				return fail(err, 0x04)
			}
			d = pol.Decide(t, addrs)
		} else {
			d = pol.Decide(t, nil)
		}
		df := map[string]any{"rule": d.Rule, "reason": d.Reason}
		if d.Text != "" {
			df["text"] = d.Text
		}
		if !d.Allow {
			b.denied.Add(1)
			emit(events.PolicyDeny, df)
			return outcome{id: id, start: start, denied: &d, socks: 0x02}
		}
		emit(events.PolicyAllow, df)
	}
	if len(b.Guards) > 0 {
		req := GuardRequest{Run: b.runID(), Conn: id, PID: int(b.pid.Load()), Path: pathID, Host: host, Port: port, Proto: proto}
		if host == "" {
			req.IP = ip.String()
		}
		if from.client != nil {
			req.Client = from.client.Name
		}
		for _, g := range b.Guards {
			deny, reason, err := g.Check(ctx, req)
			if err == nil && !deny {
				continue
			}
			if err != nil {
				reason = "guard plugin failed, so the connection is refused: " + err.Error()
			} else if reason == "" {
				reason = "refused by guard plugin " + g.Name()
			}
			d := policy.Decision{Allow: false, Rule: "plugin:" + g.Name(), Reason: reason}
			b.denied.Add(1)
			emit(events.PolicyDeny, map[string]any{"rule": d.Rule, "reason": d.Reason})
			return outcome{id: id, start: start, denied: &d, socks: 0x02}
		}
	}
	b.allowed.Add(1)

	var cands []net.IP
	switch {
	case host == "":
		cands = []net.IP{ip}
	case t.RemoteDNS:
		cands = []net.IP{nil}
	default:
		if addrs == nil {
			if err := resolve(); err != nil {
				return fail(err, 0x04)
			}
		}
		cands = addrs
	}
	t0 := b.now()
	var lastErr error
	for _, cand := range cands {
		conn, err := p.Dial(ctx, host, cand, port)
		if err != nil {
			lastErr = err
			continue
		}
		of := map[string]any{"ms": b.now().Sub(t0).Milliseconds()}
		if cand != nil {
			of["ip"] = cand.String()
		}
		if host != "" {
			of["host"] = host
		}
		if ci.Exit != "" {
			of["exit"] = ci.Exit
		}
		if from.client != nil {
			// At an exit: the address the connection really left from.
			if ta, ok := conn.LocalAddr().(*net.TCPAddr); ok {
				of["source"] = ta.IP.String()
			}
		}
		b.opened.Add(1)
		emit(events.ConnectionOpen, of)
		return outcome{conn: conn, id: id, start: start}
	}
	code := byte(0x05)
	if lastErr != nil && strings.Contains(lastErr.Error(), "unreachable") {
		code = 0x03
	}
	return fail(errors.New(dialErr(lastErr)), code)
}

func dnsErr(err error) string {
	var de *net.DNSError
	if errors.As(err, &de) {
		if de.IsNotFound {
			return "no such host"
		}
		if de.IsTimeout {
			return "timed out"
		}
		return de.Err
	}
	return err.Error()
}

func dialErr(err error) string {
	if err == nil {
		return "no address to dial"
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		return op.Err.Error()
	}
	return err.Error()
}

// sanitize keeps a rejected host printable and short in events.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 128 {
			b.WriteString("…")
			break
		}
		if r < 0x20 || r == 0x7f {
			b.WriteString("?")
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// QuietAfterClose is how long a connection out may stay silent after the
// program has stopped sending on it. A program that gave up (a timeout,
// say) closes its side; without this limit, a path that had gone silent
// would hold the other side open until the run ended. The limit is counted
// in whole windows: a connection is closed once a full window passes with
// nothing arriving, so between one and two windows of silence in all.
var QuietAfterClose = 2 * time.Minute

// quietReader reads from a connection out; once the program has stopped
// sending, each read must bring something within QuietAfterClose. Only the
// rewriting path uses it; the plain copy keeps the kernel's fast path and
// renews the deadline window by window instead.
type quietReader struct {
	c    net.Conn
	done *atomic.Bool
}

func (q quietReader) Read(p []byte) (int, error) {
	if q.done.Load() {
		q.c.SetReadDeadline(time.Now().Add(QuietAfterClose))
	}
	return q.c.Read(p)
}

// isTimeout reports a read deadline that ran out. Kernel sockets say
// os.ErrDeadlineExceeded; the WireGuard path's netstack has its own error,
// so ask the net.Error.
func isTimeout(err error) bool {
	var ne net.Error
	return err != nil && (errors.Is(err, os.ErrDeadlineExceeded) || errors.As(err, &ne) && ne.Timeout())
}

// finish relays until both sides are done, then records the close.
func (b *Broker) finish(o outcome, client net.Conn, fromClient io.Reader, extraUp, extraDown int64, rewrite func(io.Reader, io.Writer) (int64, error)) {
	defer o.conn.Close()
	b.trackUp(o.conn)
	defer b.untrackUp(o.conn)
	client.SetDeadline(time.Time{})
	b.active.Add(1)
	defer b.active.Add(-1)
	var up, down int64
	var wg sync.WaitGroup
	var clientDone atomic.Bool
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
		clientDone.Store(true)
		o.conn.SetReadDeadline(time.Now().Add(QuietAfterClose))
	}()
	go func() {
		defer wg.Done()
		var err error
		if rewrite != nil {
			down, err = rewrite(quietReader{o.conn, &clientDone}, client)
		} else {
			for {
				var n int64
				n, err = io.Copy(client, o.conn)
				down += n
				// The quiet limit ended this copy. Something arrived in
				// the window, so the connection is alive: renew it.
				if isTimeout(err) && clientDone.Load() && n > 0 {
					o.conn.SetReadDeadline(time.Now().Add(QuietAfterClose))
					continue
				}
				break
			}
		}
		if err != nil {
			o.conn.Close()
			client.Close()
			return
		}
		closeWrite(client)
	}()
	wg.Wait()
	up += extraUp
	down += extraDown
	b.bytesUp.Add(up)
	b.bytesDown.Add(down)
	b.emitPath(o.path, events.ConnectionClose, o.id, map[string]any{"bytes_up": up, "bytes_down": down, "ms": b.now().Sub(o.start).Milliseconds()})
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}

// ---- HTTP ----

type header struct{ name, value string }

type head struct {
	method, target, proto string
	headers               []header
	size                  int
}

func (h *head) get(name string) string {
	for _, x := range h.headers {
		if strings.EqualFold(x.name, name) {
			return x.value
		}
	}
	return ""
}

var errHeadTooLarge = errors.New("request head too large")

// ReadRequestHead reads an HTTP/1.x request line and headers.
func readHead(br *bufio.Reader) (*head, error) {
	h := &head{}
	line, err := readLine(br, &h.size)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(line, " ")
	if len(parts) != 3 {
		return nil, errors.New("malformed request line")
	}
	h.method, h.target, h.proto = parts[0], parts[1], parts[2]
	if h.proto != "HTTP/1.1" && h.proto != "HTTP/1.0" {
		return nil, errors.New("unsupported protocol version")
	}
	if !token(h.method) || h.target == "" {
		return nil, errors.New("malformed request line")
	}
	for {
		l, err := readLine(br, &h.size)
		if err != nil {
			return nil, err
		}
		if l == "" {
			return h, nil
		}
		if len(h.headers) >= MaxHeaderLines {
			return nil, errHeadTooLarge
		}
		i := strings.IndexByte(l, ':')
		if i <= 0 || !token(l[:i]) {
			return nil, errors.New("malformed header")
		}
		h.headers = append(h.headers, header{l[:i], strings.TrimSpace(l[i+1:])})
	}
}

func readLine(br *bufio.Reader, total *int) (string, error) {
	var sb strings.Builder
	for {
		frag, err := br.ReadSlice('\n')
		*total += len(frag)
		if *total > MaxHeadBytes {
			return "", errHeadTooLarge
		}
		sb.Write(frag)
		if err == nil {
			break
		}
		if err != bufio.ErrBufferFull {
			return "", err
		}
	}
	s := strings.TrimSuffix(sb.String(), "\n")
	s = strings.TrimSuffix(s, "\r")
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 0x20 && c != '\t') || c == 0x7f {
			return "", errors.New("control character in request head")
		}
	}
	return s, nil
}

func token(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c >= 0x7f || strings.IndexByte("()<>@,;:\\\"/[]?={}", c) >= 0 {
			return false
		}
	}
	return true
}

func httpReply(c net.Conn, status, extra, body string) {
	msg := fmt.Sprintf("HTTP/1.1 %s\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n%sContent-Length: %d\r\n\r\n%s",
		status, extra, len(body), body)
	c.Write([]byte(msg))
}

func (b *Broker) authorized(h *head) bool {
	if b.Token == "" {
		return true
	}
	v := h.get("Proxy-Authorization")
	const pfx = "Basic "
	if !strings.HasPrefix(v, pfx) {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v[len(pfx):]))
	if err != nil {
		return false
	}
	return string(raw) == "vpnw:"+b.Token
}

func (b *Broker) http(c net.Conn, br *bufio.Reader) {
	h, err := readHead(br)
	if err != nil {
		if errors.Is(err, errHeadTooLarge) {
			httpReply(c, "431 Request Header Fields Too Large", "", "vpnw: request head too large\n")
		} else if err != io.EOF {
			httpReply(c, "400 Bad Request", "", "vpnw: "+err.Error()+"\n")
		}
		return
	}
	if !b.authorized(h) {
		httpReply(c, "407 Proxy Authentication Required", "Proxy-Authenticate: Basic realm=\"vpnw\"\r\n", "vpnw: proxy credentials required\n")
		return
	}
	if h.method == "CONNECT" {
		host, port, err := splitTarget(h.target)
		if err != nil {
			httpReply(c, "400 Bad Request", "", "vpnw: "+err.Error()+"\n")
			return
		}
		o := b.open(origin{}, host, port, "http-connect")
		if !b.replyFailure(c, o, host, port) {
			return
		}
		if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
			o.conn.Close()
			b.emitPath(o.path, events.ConnectionClose, o.id, map[string]any{"bytes_up": 0, "bytes_down": 0, "ms": b.now().Sub(o.start).Milliseconds()})
			return
		}
		b.finish(o, c, br, 0, 0, nil)
		return
	}
	u, err := url.Parse(h.target)
	if err != nil || !u.IsAbs() || u.Host == "" {
		httpReply(c, "400 Bad Request", "", "vpnw: this is a proxy; send CONNECT host:port or an absolute http:// URL\n")
		return
	}
	if u.Scheme != "http" {
		httpReply(c, "400 Bad Request", "", "vpnw: use CONNECT for "+u.Scheme+" URLs\n")
		return
	}
	host, port := u.Hostname(), 80
	if p := u.Port(); p != "" {
		n, err := policy.ParsePort(p)
		if err != nil {
			httpReply(c, "400 Bad Request", "", "vpnw: bad port\n")
			return
		}
		port = n
	}
	o := b.open(origin{}, host, port, "http")
	if !b.replyFailure(c, o, host, port) {
		return
	}
	// Forward one request on its own connection. Proxy headers stay here;
	// Connection: close on both sides keeps one proxy connection to one
	// origin, so a client cannot reuse it for a different host.
	var sb strings.Builder
	sb.WriteString(h.method + " " + u.RequestURI() + " " + h.proto + "\r\n")
	sb.WriteString("Host: " + u.Host + "\r\n")
	for _, x := range h.headers {
		switch strings.ToLower(x.name) {
		case "host", "proxy-connection", "proxy-authorization", "connection", "keep-alive":
			continue
		}
		sb.WriteString(x.name + ": " + x.value + "\r\n")
	}
	sb.WriteString("Connection: close\r\n\r\n")
	n, err := io.WriteString(o.conn, sb.String())
	if err != nil {
		o.conn.Close()
		b.emitPath(o.path, events.ConnectionClose, o.id, map[string]any{"bytes_up": n, "bytes_down": 0, "ms": b.now().Sub(o.start).Milliseconds()})
		return
	}
	b.finish(o, c, br, int64(n), 0, rewriteResponse)
}

// replyFailure answers a denied or failed request. It returns true when the
// connection is open and the caller should carry on.
func (b *Broker) replyFailure(c net.Conn, o outcome, host string, port int) bool {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	if o.denied != nil {
		httpReply(c, "403 Forbidden", "X-VPNW-Rule: "+o.denied.Rule+"\r\n",
			fmt.Sprintf("vpnw: blocked %s (%s: %s)\n", target, o.denied.Rule, o.denied.Reason))
		return false
	}
	if o.err != nil {
		httpReply(c, "502 Bad Gateway", "", fmt.Sprintf("vpnw: cannot reach %s: %v\n", target, o.err))
		return false
	}
	return true
}

// rewriteResponse copies an origin response, replacing its connection
// headers with Connection: close.
func rewriteResponse(from io.Reader, to io.Writer) (int64, error) {
	br := bufio.NewReaderSize(from, 16<<10)
	var total int
	var out strings.Builder
	first := true
	for {
		l, err := readLine(br, &total)
		if err != nil {
			if out.Len() > 0 {
				n, _ := io.WriteString(to, out.String())
				return int64(n), err
			}
			return 0, err
		}
		if l == "" {
			break
		}
		if !first {
			name := l
			if i := strings.IndexByte(l, ':'); i >= 0 {
				name = l[:i]
			}
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "connection", "keep-alive", "proxy-connection":
				continue
			}
		}
		first = false
		out.WriteString(l + "\r\n")
	}
	out.WriteString("Connection: close\r\n\r\n")
	n, err := io.WriteString(to, out.String())
	if err != nil {
		return int64(n), err
	}
	m, err := io.Copy(to, br)
	return int64(n) + m, err
}

// splitTarget reads host:port from a CONNECT target.
func splitTarget(t string) (string, int, error) {
	host, ps, err := net.SplitHostPort(t)
	if err != nil {
		return "", 0, errors.New("CONNECT needs host:port")
	}
	if strings.ContainsAny(host, "%/") {
		return "", 0, errors.New("bad host in CONNECT")
	}
	port, err := policy.ParsePort(ps)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

// ---- SOCKS5 ----

func (b *Broker) socks(c net.Conn, br *bufio.Reader) {
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil || len(methods) == 0 {
		return
	}
	want := byte(0x00)
	if b.Token != "" {
		want = 0x02
	}
	ok := false
	for _, m := range methods {
		if m == want {
			ok = true
		}
	}
	if !ok {
		c.Write([]byte{0x05, 0xff})
		return
	}
	c.Write([]byte{0x05, want})
	if want == 0x02 {
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
		if v[0] != 0x01 || string(user) != "vpnw" || string(pass) != b.Token {
			c.Write([]byte{0x01, 0x01})
			return
		}
		c.Write([]byte{0x01, 0x00})
	}
	cmd, host, port, ok := socksRequest(c, br)
	if !ok {
		return
	}
	if cmd != 0x01 {
		b.unsupported(origin{}, c, host, port, cmd)
		return
	}
	o := b.open(origin{}, host, port, "socks5")
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

// unsupported refuses SOCKS5 BIND and UDP ASSOCIATE, with an event saying so.
func (b *Broker) unsupported(from origin, c net.Conn, host string, port int, cmd byte) {
	pol, p := b.Policy, b.Path
	if from.client != nil {
		pol, p = from.client.Policy, from.client.Path
	}
	id := b.seq.Add(1)
	b.connections.Add(1)
	proto := "socks5-bind"
	what := "incoming connections (SOCKS5 BIND)"
	if cmd == 0x03 {
		proto, what = "socks5-udp", "UDP (SOCKS5 UDP ASSOCIATE)"
	}
	f := map[string]any{"port": port, "proto": proto}
	if ip := net.ParseIP(host); ip != nil {
		f["ip"] = ip.String()
	} else {
		f["host"] = sanitize(host)
	}
	from.fields(f)
	b.emitPath(p.ID(), events.ConnectionAttempt, id, f)
	msg := what + " is not supported by vpnw yet"
	if pol != nil {
		b.denied.Add(1)
		b.emitPath(p.ID(), events.PolicyDeny, id, map[string]any{"rule": "unsupported", "reason": msg})
	} else {
		b.failed.Add(1)
		b.emitPath(p.ID(), events.ConnectionError, id, map[string]any{"error": msg})
	}
	socksReply(c, 0x07)
}

func socksReply(c net.Conn, code byte) error {
	_, err := c.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

// socksRequest reads a SOCKS5 request, after the login: the command, and the
// host and port. ok is false when the client went away or sent something
// other than SOCKS5, or used an address type it was told is not supported.
func socksRequest(c net.Conn, br *bufio.Reader) (cmd byte, host string, port int, ok bool) {
	var req [4]byte
	if _, err := io.ReadFull(br, req[:]); err != nil {
		return 0, "", 0, false
	}
	if req[0] != 0x05 {
		return 0, "", 0, false
	}
	switch req[3] {
	case 0x01:
		var a [4]byte
		if _, err := io.ReadFull(br, a[:]); err != nil {
			return 0, "", 0, false
		}
		host = net.IP(a[:]).String()
	case 0x04:
		var a [16]byte
		if _, err := io.ReadFull(br, a[:]); err != nil {
			return 0, "", 0, false
		}
		host = net.IP(a[:]).String()
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(br, l[:]); err != nil {
			return 0, "", 0, false
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(br, name); err != nil {
			return 0, "", 0, false
		}
		host = string(name)
	default:
		socksReply(c, 0x08)
		return 0, "", 0, false
	}
	var pb [2]byte
	if _, err := io.ReadFull(br, pb[:]); err != nil {
		return 0, "", 0, false
	}
	return req[1], host, int(pb[0])<<8 | int(pb[1]), true
}
