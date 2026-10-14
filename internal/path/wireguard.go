// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package path

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// WireGuard is a path through a WireGuard tunnel that vpnw runs itself, in
// user space: the WireGuard protocol from wireguard-go and a TCP/IP stack
// from gVisor, both inside the vpnw process. It needs no root, no kernel
// module and no network interface on the machine; the only thing that
// leaves the machine is WireGuard's encrypted UDP to the peer.
//
// Names are looked up through the tunnel, at the DNS servers in the
// config, so lookups don't leak outside it, and the broker still checks
// every address against the policy before dialing (RemoteDNS is false).
type WireGuard struct {
	Name string
	Conf *WGConf
	// DNS is "tunnel" (the config's DNS servers, through the tunnel) or
	// "local" (this machine's resolver, outside the tunnel).
	DNS string

	once  sync.Once
	err   error
	dev   *device.Device
	tnet  *netstack.Net
	live  *liveness
	peers []string // each peer's endpoint, resolved, in config order
}

// NewWireGuard builds a WireGuard path from a wg-quick config. dns is
// "tunnel", "local" or "" (tunnel when the config names DNS servers).
func NewWireGuard(name string, c *WGConf, dns string) (*WireGuard, error) {
	switch dns {
	case "", "tunnel":
		if len(c.DNS) == 0 {
			// Never a quiet fallback that would send lookups outside the
			// tunnel.
			return nil, fmt.Errorf("the WireGuard config names no DNS server, so names could only be looked up outside the tunnel; add DNS = <server> to its [Interface], or ask for that with dns = \"local\" (--dns local)")
		}
		dns = "tunnel"
		for _, d := range c.DNS {
			if _, ok := c.Covers(d); !ok {
				return nil, fmt.Errorf("the WireGuard config's DNS server %s is outside every peer's AllowedIPs, so the tunnel would drop every lookup; add it to AllowedIPs, or use dns = \"local\"", d)
			}
		}
	case "local":
	default:
		return nil, fmt.Errorf("dns for a WireGuard path is \"tunnel\" or \"local\"")
	}
	if name == "" || name == "network" {
		name = "wireguard"
	}
	return &WireGuard{Name: name, Conf: c, DNS: dns}, nil
}

func (w *WireGuard) ID() string      { return w.Name }
func (w *WireGuard) Kind() string    { return "wireguard" }
func (w *WireGuard) RemoteDNS() bool { return false }

// Describe names the peer and the tunnel addresses. Keys are public keys,
// shortened; the private key never appears.
func (w *WireGuard) Describe() string {
	p := w.Conf.Peers[0]
	pub := base64.StdEncoding.EncodeToString(p.PublicKey[:])
	var addrs []string
	for _, a := range w.Conf.Addresses {
		addrs = append(addrs, a.String())
	}
	s := fmt.Sprintf("wireguard peer %s… at %s, tunnel address %s", pub[:8], p.Endpoint, strings.Join(addrs, ", "))
	if n := len(w.Conf.Peers); n > 1 {
		s += fmt.Sprintf(", %d peers", n)
	}
	if w.DNS == "tunnel" {
		var d []string
		for _, a := range w.Conf.DNS {
			d = append(d, a.String())
		}
		s += ", dns " + strings.Join(d, ", ") + " through the tunnel"
	} else {
		s += ", dns on this machine"
	}
	return s
}

// start brings the tunnel up once. The peers' endpoints are looked up on
// this machine, the one lookup that can't go through the tunnel.
func (w *WireGuard) start(ctx context.Context) error {
	w.once.Do(func() { w.err = w.up(ctx) })
	return w.err
}

func (w *WireGuard) up(ctx context.Context) error {
	c := w.Conf
	var local []netip.Addr
	for _, a := range c.Addresses {
		local = append(local, a.Addr())
	}
	dns := c.DNS
	if w.DNS != "tunnel" {
		dns = nil
	}
	tdev, tnet, err := netstack.CreateNetTUN(local, dns, c.MTU)
	if err != nil {
		return fmt.Errorf("wireguard: %v", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hexKey(c.PrivateKey))
	if c.ListenPort != 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", c.ListenPort)
	}
	b.WriteString("replace_peers=true\n")
	for _, p := range c.Peers {
		ep, err := resolveEndpoint(ctx, p.Endpoint)
		if err != nil {
			tdev.Close()
			return err
		}
		w.peers = append(w.peers, ep)
		fmt.Fprintf(&b, "public_key=%s\n", hexKey(p.PublicKey))
		if p.PresharedKey != nil {
			fmt.Fprintf(&b, "preshared_key=%s\n", hexKey(*p.PresharedKey))
		}
		fmt.Fprintf(&b, "endpoint=%s\n", ep)
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.Keepalive)
		b.WriteString("replace_allowed_ips=true\n")
		for _, a := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", a)
		}
	}
	live := &liveness{}
	dev := device.NewDevice(&watchedTUN{Device: tdev, live: live}, &watchedBind{Bind: conn.NewDefaultBind(), live: live},
		device.NewLogger(device.LogLevelSilent, ""))
	if err := dev.IpcSet(b.String()); err != nil {
		dev.Close()
		return fmt.Errorf("wireguard: %v", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("wireguard: %v", err)
	}
	w.dev, w.tnet, w.live = dev, tnet, live
	return nil
}

// liveness is what a tunnel knows of its peers being there: when it last
// heard from one, and when the first packet went out after that, both in
// nanoseconds on a monotonic clock, or 0.
//
// Heard means a packet WireGuard accepted: a handshake that checked out, or
// a transport packet that decrypted, keepalives included. The tunnel's
// socket notes when each packet shaped like a WireGuard message came in
// (arrived), but anyone can send a packet of that shape, so it counts as
// heard only once WireGuard's own count of bytes received from its peers
// has grown (confirm).
type liveness struct {
	heard, waiting, arrived atomic.Int64

	mu sync.Mutex
	rx uint64 // bytes WireGuard had accepted from the peers at the last confirm
}

// begin starts counting after the handshakes that bring a tunnel up: rx is
// the bytes WireGuard has accepted so far, and the peers were heard now.
// What came in before doesn't count again later.
func (l *liveness) begin(rx uint64) {
	l.mu.Lock()
	l.rx = rx
	l.mu.Unlock()
	l.heard.Store(monotonic())
}

// confirm takes rx, the bytes WireGuard has accepted from the peers so far.
// If that grew since the last time, what arrived came from a peer: the
// last packet that arrived counts as heard.
func (l *liveness) confirm(rx uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if rx == l.rx {
		return
	}
	l.rx = rx
	a := l.arrived.Load()
	if a == 0 {
		a = monotonic()
	}
	if a > l.heard.Load() {
		l.heard.Store(a)
	}
}

var clockStart = time.Now()

func monotonic() int64 { return int64(time.Since(clockStart)) + 1 }

// sent notes data going out: the first after the last packet heard starts
// the wait for an answer.
func (l *liveness) sent() {
	now := monotonic()
	for {
		w, h := l.waiting.Load(), l.heard.Load()
		if w != 0 && w > h {
			return
		}
		if l.waiting.CompareAndSwap(w, now) {
			return
		}
	}
}

// silentFor is how long the first packet that went out after the last one
// heard has gone unanswered, or 0.
func (l *liveness) silentFor() time.Duration {
	w, h := l.waiting.Load(), l.heard.Load()
	if w == 0 || w <= h {
		return 0
	}
	return time.Duration(monotonic() - w)
}

// watchedTUN is the tunnel's end of vpnw's TCP/IP stack. It notes each
// packet the stack sends out to a peer.
type watchedTUN struct {
	tun.Device
	live *liveness
}

// Read hands WireGuard the packets the stack sends out through the tunnel.
func (t *watchedTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.Device.Read(bufs, sizes, offset)
	for i := 0; i < n && i < len(bufs) && i < len(sizes); i++ {
		if end := offset + sizes[i]; end <= len(bufs[i]) && unicastData(bufs[i][offset:end]) {
			t.live.sent()
			break
		}
	}
	return n, err
}

// watchedBind is the tunnel's UDP socket. It notes when each packet shaped
// like a WireGuard message comes in: data, a keepalive or a handshake. Once
// WireGuard has accepted it, it says the peer is there (see liveness).
type watchedBind struct {
	conn.Bind
	live *liveness
}

func (b *watchedBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	for i, fn := range fns {
		fns[i] = func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, err := fn(packets, sizes, eps)
			for j := 0; j < n && j < len(packets) && j < len(sizes); j++ {
				if sizes[j] <= len(packets[j]) && wgMessage(packets[j][:sizes[j]]) {
					b.live.arrived.Store(monotonic())
					break
				}
			}
			return n, err
		}
	}
	return fns, actual, err
}

// wgMessage reports a packet shaped like a WireGuard message: a handshake
// initiation or response, a cookie reply, or a transport packet.
func wgMessage(p []byte) bool {
	if len(p) < 32 || p[1] != 0 || p[2] != 0 || p[3] != 0 {
		return false
	}
	switch p[0] {
	case 1:
		return len(p) == 148
	case 2:
		return len(p) == 92
	case 3:
		return len(p) == 64
	case 4:
		return true
	}
	return false
}

// unicastData reports a TCP or UDP packet to a unicast address: one a live
// peer receives and answers. Anything else the stack might send (multicast,
// neighbour discovery) can go unanswered without the peer being gone.
func unicastData(p []byte) bool {
	var proto byte
	var dst netip.Addr
	switch {
	case len(p) >= 20 && p[0]>>4 == 4:
		proto, dst = p[9], netip.AddrFrom4([4]byte(p[16:20]))
	case len(p) >= 40 && p[0]>>4 == 6:
		proto, dst = p[6], netip.AddrFrom16([16]byte(p[24:40]))
	default:
		return false
	}
	return (proto == 6 || proto == 17) && !dst.IsMulticast() && !dst.IsUnspecified()
}

// Silent reports a tunnel that has stopped answering: data went out through
// it more than d ago, and nothing has come back from any peer since, not
// even a keepalive. A live WireGuard peer answers data within 10 seconds,
// with a keepalive when it has nothing else to send, so it is never silent
// for long. Only what WireGuard accepted counts: packets forged to look
// like a peer's don't hide a peer that is gone.
func (w *WireGuard) Silent(d time.Duration) bool {
	if w.live == nil {
		return false
	}
	if rx, ok := w.received(); ok {
		w.live.confirm(rx)
	}
	return w.live.silentFor() > d
}

// received is how many bytes WireGuard has accepted from the peers: only
// handshakes that checked out and packets that decrypted count.
func (w *WireGuard) received() (uint64, bool) {
	st, err := w.dev.IpcGet()
	if err != nil {
		return 0, false
	}
	var n uint64
	for _, l := range strings.Split(st, "\n") {
		if v, ok := strings.CutPrefix(l, "rx_bytes="); ok {
			b, _ := strconv.ParseUint(v, 10, 64)
			n += b
		}
	}
	return n, true
}

// quietAgain makes Silent count again from the next packet that goes out.
func (w *WireGuard) quietAgain() {
	if w.live != nil {
		w.live.waiting.Store(0)
	}
}

// Endpoint is the first peer's endpoint, as resolved when the tunnel came up.
func (w *WireGuard) Endpoint() string {
	if len(w.peers) == 0 {
		return ""
	}
	return w.peers[0]
}

// LookupError is a peer's endpoint whose name couldn't be looked up on
// this machine.
type LookupError struct {
	Endpoint string // as the config has it
	Err      error
}

func (e *LookupError) Error() string {
	return fmt.Sprintf("wireguard endpoint %s: cannot look up its name: %v", e.Endpoint, e.Err)
}

func (e *LookupError) Unwrap() error { return e.Err }

// HandshakeError is peers that didn't complete a WireGuard handshake in
// time.
type HandshakeError struct {
	Endpoints []string // as the config has them
	Addrs     []string // where the handshakes went: the endpoints, looked up
	Timeout   time.Duration
}

func (e *HandshakeError) Error() string {
	return fmt.Sprintf("no WireGuard handshake from %s within %v: check the endpoint and the keys, and that UDP to it gets through", strings.Join(e.Addrs, ", "), e.Timeout)
}

func resolveEndpoint(ctx context.Context, ep string) (string, error) {
	host, port, err := net.SplitHostPort(ep)
	if err != nil {
		return "", fmt.Errorf("wireguard endpoint %s: %v", ep, err)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(ip, mustPort(port)).String(), nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err == nil && len(ips) == 0 {
		err = errors.New("no addresses")
	}
	if err != nil {
		return "", &LookupError{Endpoint: ep, Err: err}
	}
	return netip.AddrPortFrom(ips[0].Unmap(), mustPort(port)).String(), nil
}

func mustPort(s string) uint16 {
	n, _ := strconv.Atoi(s)
	return uint16(n)
}

// HandshakeTimeout bounds how long Health waits for every peer to answer.
// WireGuard sends a handshake again after 5 seconds without a reply, so 12
// seconds leaves room for one lost packet and its retry. A variable so
// tests can shorten it.
var HandshakeTimeout = 12 * time.Second

// Health brings the tunnel up and waits until every peer has completed a
// WireGuard handshake: until then nothing is known to work, since
// WireGuard is silent towards anyone without the right keys.
func (w *WireGuard) Health(ctx context.Context) error {
	if err := w.start(ctx); err != nil {
		return err
	}
	// A handshake starts when there is something to send. A keepalive
	// gives it something, then the peer's own setting is put back.
	var b strings.Builder
	for _, p := range w.Conf.Peers {
		fmt.Fprintf(&b, "public_key=%s\nupdate_only=true\npersistent_keepalive_interval=1\n", hexKey(p.PublicKey))
	}
	if err := w.dev.IpcSet(b.String()); err != nil {
		return fmt.Errorf("wireguard: %v", err)
	}
	defer func() {
		var r strings.Builder
		for _, p := range w.Conf.Peers {
			fmt.Fprintf(&r, "public_key=%s\nupdate_only=true\npersistent_keepalive_interval=%d\n", hexKey(p.PublicKey), p.Keepalive)
		}
		w.dev.IpcSet(r.String())
	}()
	ctx, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	defer cancel()
	for {
		missing := w.withoutHandshake()
		if len(missing) == 0 {
			if rx, ok := w.received(); ok {
				w.live.begin(rx)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			e := &HandshakeError{Timeout: HandshakeTimeout}
			for _, i := range missing {
				e.Endpoints = append(e.Endpoints, w.Conf.Peers[i].Endpoint)
				e.Addrs = append(e.Addrs, w.peers[i])
			}
			return e
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// withoutHandshake lists the peers, by their place in the config, that have
// not completed a handshake yet.
func (w *WireGuard) withoutHandshake() []int {
	st, err := w.dev.IpcGet()
	if err != nil {
		all := make([]int, len(w.Conf.Peers))
		for i := range all {
			all[i] = i
		}
		return all
	}
	done := map[string]bool{}
	cur := ""
	for _, l := range strings.Split(st, "\n") {
		k, v, _ := strings.Cut(l, "=")
		switch k {
		case "public_key":
			cur = v
		case "last_handshake_time_sec":
			if v != "0" {
				done[cur] = true
			}
		}
	}
	var out []int
	for i, p := range w.Conf.Peers {
		if !done[hexKey(p.PublicKey)] {
			out = append(out, i)
		}
	}
	return out
}

// Dial opens a TCP connection through the tunnel to an address the broker
// has already checked. An address outside every peer's AllowedIPs is
// refused here: the tunnel would drop it without a word.
func (w *WireGuard) Dial(ctx context.Context, host string, ip net.IP, port int) (net.Conn, error) {
	if err := w.start(ctx); err != nil {
		return nil, err
	}
	if ip == nil {
		ips, err := w.Resolver().LookupIP(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, errors.New("no addresses")
		}
		ip = ips[0]
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return nil, fmt.Errorf("bad address %v", ip)
	}
	addr = addr.Unmap()
	// These never lead anywhere through a tunnel: loopback is this
	// machine, and link-local is the peer's own network segment, where
	// its cloud metadata service lives. A DNS answer from the tunnel that
	// points at one is refused, whatever AllowedIPs says.
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() || addr.IsMulticast() {
		return nil, fmt.Errorf("%s can't be reached through a tunnel: it's a loopback, link-local or multicast address", addr)
	}
	peer, ok := w.Conf.Covers(addr)
	if !ok {
		return nil, fmt.Errorf("%s is outside the tunnel: no peer's AllowedIPs include it", addr)
	}
	if ci := ConnOf(ctx); ci != nil {
		ci.Exit = peer.Endpoint
	}
	c, err := w.tnet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(addr, uint16(port)))
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Resolver looks names up the way this path says: through the tunnel, or
// on this machine.
func (w *WireGuard) Resolver() Resolver {
	if w.DNS != "tunnel" {
		return SystemResolver{}
	}
	return tunnelResolver{w}
}

type tunnelResolver struct{ w *WireGuard }

func (r tunnelResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	if err := r.w.start(ctx); err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	// The tunnel's resolver doesn't always stop when ctx does (a silent
	// peer leaves it waiting out its own timeouts), so wait on both. A
	// lookup given up on this way keeps its goroutine and UDP socket until
	// the resolver's own timeouts end it, about 10 s at most; the channel
	// is buffered so it never blocks.
	type answer struct {
		addrs []string
		err   error
	}
	ch := make(chan answer, 1)
	go func() {
		a, err := r.w.tnet.LookupContextHost(ctx, host)
		ch <- answer{a, err}
	}()
	var addrs []string
	var err error
	select {
	case a := <-ch:
		addrs, err = a.addrs, a.err
	case <-ctx.Done():
		return nil, &net.DNSError{Err: ctx.Err().Error(), Name: host, IsTimeout: ctx.Err() == context.DeadlineExceeded}
	}
	if err != nil {
		var de *net.DNSError
		if errors.As(err, &de) {
			return nil, de
		}
		return nil, &net.DNSError{Err: err.Error(), Name: host}
	}
	var out []net.IP
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil {
			out = append(out, ip)
		}
	}
	return out, nil
}

// Close takes the tunnel down.
func (w *WireGuard) Close() error {
	if w.dev != nil {
		w.dev.Close()
	}
	return nil
}

// PathResolver is a path that looks names up its own way. The broker uses
// it in place of this machine's resolver.
type PathResolver interface {
	Resolver() Resolver
}
