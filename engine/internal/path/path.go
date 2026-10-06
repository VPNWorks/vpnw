// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package path implements NetworkPath: how a workload's connections leave
// the machine. The Alpha has two kinds, direct and proxy (SOCKS5 or HTTP
// CONNECT), behind one interface, so a WireGuard path can join later without
// touching the broker, the policy or the events. 0.2.0 adds proxies reached
// over TLS (tls.go) and lists of exits with failover (exits.go).
package path

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"vpnw.com/vpnw/internal/config"
)

// Path is one way out.
type Path interface {
	// ID is the stable name stamped on events: "direct", "office", ...
	ID() string
	// Kind is "direct", "socks5" or "http".
	Kind() string
	// RemoteDNS reports whether names are resolved at the exit.
	RemoteDNS() bool
	// Describe is a one-line description with any password removed.
	Describe() string
	// Dial opens a TCP connection. For a remote-DNS path host is sent to the
	// exit and ip is nil; otherwise ip is the address already checked.
	Dial(ctx context.Context, host string, ip net.IP, port int) (net.Conn, error)
	// Health checks that the path can be used at all.
	Health(ctx context.Context) error
}

// Resolver looks up addresses. The broker uses it for local-DNS paths.
type Resolver interface {
	LookupIP(ctx context.Context, host string) ([]net.IP, error)
}

// SystemResolver uses Go's resolver.
type SystemResolver struct{}

// LookupIP resolves host to IPv4 and IPv6 addresses.
func (SystemResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	return out, nil
}

// DialTimeout bounds how long one connection may take to open.
const DialTimeout = 15 * time.Second

// Direct connects from this machine.
type Direct struct{ Dialer net.Dialer }

func (*Direct) ID() string       { return "direct" }
func (*Direct) Kind() string     { return "direct" }
func (*Direct) RemoteDNS() bool  { return false }
func (*Direct) Describe() string { return "direct from this machine" }

func (d *Direct) Dial(ctx context.Context, host string, ip net.IP, port int) (net.Conn, error) {
	if ip == nil {
		return nil, errors.New("direct path needs a resolved address")
	}
	return d.Dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
}

func (*Direct) Health(context.Context) error { return nil }

// Proxy sends connections through a SOCKS5 or HTTP CONNECT proxy.
type Proxy struct {
	Name   string
	Scheme string // "socks5" or "http"
	Addr   string // host:port of the proxy
	User   string
	Pass   string
	Remote bool
	Dialer net.Dialer
	// TLS, when set, wraps the connection to the proxy in TLS before the
	// proxy's own handshake (https:// and socks5+tls://), with the
	// certificate always checked, and follows VPN Works exit conventions:
	// the run and connection IDs go with each request.
	TLS *tls.Config
}

func (p *Proxy) ID() string      { return p.Name }
func (p *Proxy) RemoteDNS() bool { return p.Remote }
func (p *Proxy) Kind() string {
	if p.Scheme == "http" {
		if p.TLS != nil {
			return "https"
		}
		return "http"
	}
	if p.TLS != nil {
		return "socks5+tls"
	}
	return "socks5"
}

func (p *Proxy) Describe() string {
	u := p.Kind() + "://"
	if p.User != "" {
		u += "***@"
	}
	dns := "local DNS"
	if p.Remote {
		dns = "DNS at the exit"
	}
	return fmt.Sprintf("%s%s, %s", u, p.Addr, dns)
}

// Health opens and closes a TCP connection to the proxy. A proxy reached
// over TLS also has its certificate checked and its token tried (tls.go).
func (p *Proxy) Health(ctx context.Context) error {
	if p.TLS != nil {
		return p.tlsHealth(ctx)
	}
	c, err := p.Dialer.DialContext(ctx, "tcp", p.Addr)
	if err != nil {
		return fmt.Errorf("proxy %s is not reachable: %v", p.Addr, shortErr(err))
	}
	return c.Close()
}

// Dial connects through the proxy.
func (p *Proxy) Dial(ctx context.Context, host string, ip net.IP, port int) (net.Conn, error) {
	return p.dial(ctx, host, ip, port, 0)
}

// dial connects through the proxy. limit, if set, bounds how long the proxy
// may take to accept the connection and finish TLS; a list of exits uses it
// to move on from an exit that stopped answering. Errors that mean the proxy
// never answered are a *downError.
func (p *Proxy) dial(ctx context.Context, host string, ip net.IP, port int, limit time.Duration) (net.Conn, error) {
	c, err := p.connect(ctx, limit)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	dest := host
	if !p.Remote || host == "" {
		if ip == nil {
			c.Close()
			return nil, errors.New("no address to send to a local-DNS proxy")
		}
		dest = ip.String()
	}
	info := ConnOf(ctx)
	var ex *exitIDs
	if p.TLS != nil {
		ex = &exitIDs{conn: info}
	}
	var out net.Conn
	if p.Scheme == "http" {
		out, err = httpConnect(c, dest, port, p.User, p.Pass, ex)
	} else {
		out, err = socks5Connect(c, dest, port, ex.socksUser(p.User, p.Pass), p.Pass)
	}
	if ex != nil && info != nil && !isDown(err) {
		info.Exit = p.Addr
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	c.SetDeadline(time.Time{})
	return out, nil
}

// connect opens the connection to the proxy itself: TCP, then TLS for a
// proxy reached over TLS. limit, if set, bounds both.
func (p *Proxy) connect(ctx context.Context, limit time.Duration) (net.Conn, error) {
	dctx := ctx
	if limit > 0 {
		var cancel context.CancelFunc
		dctx, cancel = context.WithTimeout(ctx, limit)
		defer cancel()
	}
	c, err := p.Dialer.DialContext(dctx, "tcp", p.Addr)
	if err != nil {
		return nil, &downError{fmt.Errorf("proxy %s: %v", p.Addr, shortErr(err))}
	}
	if p.TLS == nil {
		return c, nil
	}
	tc := tls.Client(c, p.TLS)
	if err := tc.HandshakeContext(dctx); err != nil {
		c.Close()
		return nil, &downError{fmt.Errorf("TLS with %s: %v", p.Addr, tlsReason(err))}
	}
	return tc, nil
}

func shortErr(err error) string {
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		return op.Err.Error()
	}
	return err.Error()
}

// FromSpec builds a path from configuration.
func FromSpec(ps *config.PathSpec) (Path, error) {
	if ps.Type == "direct" {
		return &Direct{}, nil
	}
	name := ps.Name
	if name == "network" {
		name = "proxy"
	}
	urls := ps.URLs
	if ps.URL != "" {
		urls = []string{ps.URL}
	}
	// In a file, names resolve at the exit unless dns = "local".
	dns := "remote"
	if ps.DNS == "local" {
		dns = "local"
	}
	dir := ""
	if ps.File != "" {
		dir = filepath.Dir(ps.File)
	}
	return Build(name, urls, Options{DNS: dns, CAFile: ps.CAFile, TokenFile: ps.TokenFile, Dir: dir})
}

// FromURL builds a proxy path from a URL such as socks5://127.0.0.1:1080.
// socks5h:// is accepted as socks5 with DNS at the exit.
func FromURL(name, raw string) (Path, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("%q is not a proxy URL such as socks5://host:port", redact(raw))
	}
	// As in curl: socks5:// resolves names here, socks5h:// and http://
	// hand the name to the exit. A config file's dns key overrides this.
	// Over TLS (https://, socks5+tls://) names go to the exit too, so a VPN
	// Works exit can check its client's name rules.
	px := &Proxy{Name: name}
	switch u.Scheme {
	case "socks5":
		px.Scheme = "socks5"
	case "socks5h":
		px.Scheme, px.Remote = "socks5", true
	case "http":
		px.Scheme, px.Remote = "http", true
	case "https":
		px.Scheme, px.Remote = "http", true
	case "socks5+tls":
		px.Scheme, px.Remote = "socks5", true
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q; use socks5://, http://, https:// or socks5+tls://", u.Scheme)
	}
	if u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("a proxy URL has only a host and port")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return nil, fmt.Errorf("proxy URL %q needs a port", redact(raw))
	}
	if _, err := strconv.Atoi(port); err != nil {
		return nil, fmt.Errorf("proxy URL %q has a bad port", redact(raw))
	}
	px.Addr = net.JoinHostPort(host, port)
	if u.User != nil {
		px.User = u.User.Username()
		px.Pass, _ = u.User.Password()
		if len(px.User) > 255 || len(px.Pass) > 255 {
			return nil, errors.New("proxy user name and password must be at most 255 bytes")
		}
	}
	if u.Scheme == "https" || u.Scheme == "socks5+tls" {
		if err := px.useTLS(host, u.User, raw); err != nil {
			return nil, err
		}
	}
	return px, nil
}

// redact hides everything between the scheme and the last "@", so a
// password is hidden even in a URL too broken to parse.
func redact(raw string) string {
	if j := strings.Index(raw, "://"); j >= 0 {
		if i := strings.LastIndex(raw, "@"); i > j {
			return raw[:j+3] + "***" + raw[i:]
		}
	}
	return raw
}

// Redact removes a password from a URL for logs and events.
func Redact(raw string) string { return redact(raw) }

// socks5Connect runs the RFC 1928 client handshake on c.
func socks5Connect(c net.Conn, host string, port int, user, pass string) (net.Conn, error) {
	methods := []byte{0x00}
	if user != "" {
		methods = []byte{0x02, 0x00}
	}
	hello := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := c.Write(hello); err != nil {
		return nil, &downError{err}
	}
	var rep [2]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		return nil, &downError{fmt.Errorf("socks5 exit: %v", err)}
	}
	if rep[0] != 0x05 {
		return nil, errors.New("socks5 exit answered with the wrong version")
	}
	switch rep[1] {
	case 0x00:
	case 0x02:
		if user == "" {
			return nil, errors.New("socks5 exit wants a password")
		}
		auth := []byte{0x01, byte(len(user))}
		auth = append(auth, user...)
		auth = append(auth, byte(len(pass)))
		auth = append(auth, pass...)
		if _, err := c.Write(auth); err != nil {
			return nil, err
		}
		var ar [2]byte
		if _, err := io.ReadFull(c, ar[:]); err != nil {
			return nil, err
		}
		if ar[1] != 0x00 {
			return nil, errors.New("socks5 exit refused the password")
		}
	default:
		return nil, errors.New("socks5 exit accepts none of our login methods")
	}
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("host name too long for socks5")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		return nil, err
	}
	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return nil, fmt.Errorf("socks5 exit: %v", err)
	}
	if head[1] != 0x00 {
		return nil, fmt.Errorf("socks5 exit: %s", SOCKSReplyText(head[1]))
	}
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return nil, err
		}
		skip = int(l[0])
	default:
		return nil, errors.New("socks5 exit sent a bad reply")
	}
	if _, err := io.CopyN(io.Discard, c, int64(skip+2)); err != nil {
		return nil, err
	}
	return c, nil
}

// SOCKSReplyText explains a SOCKS5 reply code.
func SOCKSReplyText(code byte) string {
	switch code {
	case 0x01:
		return "general failure"
	case 0x02:
		return "connection not allowed by its rules"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	}
	return fmt.Sprintf("error code %d", code)
}

// httpConnect runs an HTTP CONNECT handshake on c. ex is set for a VPN Works
// exit: it adds the run and connection IDs, and reads the exit's reason when
// it refuses.
func httpConnect(c net.Conn, host string, port int, user, pass string, ex *exitIDs) (net.Conn, error) {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if user != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", cred)
	}
	for _, h := range ex.headers() {
		b.WriteString(h + "\r\n")
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(c, b.String()); err != nil {
		return nil, &downError{err}
	}
	br := bufio.NewReaderSize(c, 4096)
	status, err := br.ReadString('\n')
	if err != nil {
		return nil, &downError{fmt.Errorf("http exit: %v", err)}
	}
	f := strings.Fields(status)
	if len(f) < 2 || !strings.HasPrefix(f[0], "HTTP/1.") {
		return nil, errors.New("http exit sent a bad status line")
	}
	code, _ := strconv.Atoi(f[1])
	total := len(status)
	var why exitAnswer
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("http exit: %v", err)
		}
		total += len(l)
		if total > 64<<10 {
			return nil, errors.New("http exit sent too many headers")
		}
		if l == "\r\n" || l == "\n" {
			break
		}
		if ex != nil {
			why.note(l)
		}
	}
	if code != 200 {
		if ex != nil {
			return nil, why.err(code, f)
		}
		return nil, fmt.Errorf("http exit answered %s", printable(strings.TrimSpace(strings.Join(f[1:], " ")), 300))
	}
	if br.Buffered() > 0 {
		return &bufConn{Conn: c, r: br}, nil
	}
	return c, nil
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// CloseWrite passes half-close through when the underlying conn supports it.
func (b *bufConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
