// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package path

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Conn is the connection a dial is for. The broker puts one in the context of
// each dial. A proxy reached over TLS sends the run and connection IDs to the
// exit with the request, so the exit's record joins the run's, and it notes
// which exit answered.
type Conn struct {
	Run string
	ID  uint64
	// Switched, if set, is told when a list of exits gives up on one exit
	// and moves to the next while opening this connection: from and to are
	// host:port, reason is why from was given up, ms how long that took.
	Switched func(from, to, reason string, ms int64)
	// Exit is set by the path: the exit that answered, as host:port.
	Exit string
}

type connKey struct{}

// WithConn returns a context that carries c to the path's Dial.
func WithConn(ctx context.Context, c *Conn) context.Context {
	return context.WithValue(ctx, connKey{}, c)
}

// ConnOf returns the Conn a context carries, or nil.
func ConnOf(ctx context.Context) *Conn {
	c, _ := ctx.Value(connKey{}).(*Conn)
	return c
}

// downError means a proxy did not answer: it could not be reached, TLS
// failed, or it closed the connection before it answered. A list of exits
// moves on to the next exit after one. Its message is the wrapped error's.
type downError struct{ err error }

func (d *downError) Error() string { return d.err.Error() }
func (d *downError) Unwrap() error { return d.err }

func isDown(err error) bool {
	var d *downError
	return errors.As(err, &d)
}

// tlsReason words a failed TLS handshake.
func tlsReason(err error) string {
	var ce *tls.CertificateVerificationError
	if errors.As(err, &ce) {
		return "certificate not accepted: " + ce.Err.Error()
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		return op.Err.Error()
	}
	return err.Error()
}

// useTLS makes p a proxy reached over TLS. The token is the URL's password;
// a URL with a token and no user name gets the user name "vpnw".
func (p *Proxy) useTLS(host string, ui *url.Userinfo, raw string) error {
	if ui != nil {
		if _, ok := ui.Password(); !ok && p.User != "" {
			return fmt.Errorf("%s: put the token after a colon, as in https://vpnw:TOKEN@host:port, or give it in a token file", redact(raw))
		}
	}
	if p.User == "" && p.Pass != "" {
		p.User = "vpnw"
	}
	p.TLS = &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		ClientSessionCache: tls.NewLRUClientSessionCache(64),
	}
	return nil
}

// validRun reports whether a run ID can travel to an exit as it is: 1 to 64
// letters, digits, dots, dashes and underscores.
func validRun(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// exitIDs carries the VPN Works exit conventions for one request: the run
// and connection IDs go to the exit with it. A nil *exitIDs adds nothing.
type exitIDs struct{ conn *Conn }

// headers returns the HTTP CONNECT request headers that carry the IDs.
func (x *exitIDs) headers() []string {
	if x == nil || x.conn == nil || x.conn.ID == 0 || !validRun(x.conn.Run) {
		return nil
	}
	return []string{"VPNW-Run: " + x.conn.Run, "VPNW-Conn: " + strconv.FormatUint(x.conn.ID, 10)}
}

// socksUser returns the SOCKS5 user name to send. With the IDs and a token,
// it is RUN/CONN, which a VPN Works exit reads; the token is the password.
func (x *exitIDs) socksUser(user, pass string) string {
	if x == nil || x.conn == nil || pass == "" || x.conn.ID == 0 || !validRun(x.conn.Run) {
		return user
	}
	return x.conn.Run + "/" + strconv.FormatUint(x.conn.ID, 10)
}

// exitAnswer keeps what a VPN Works exit says when it refuses a request: the
// rule and the reason, in the VPNW-Rule and VPNW-Reason headers.
type exitAnswer struct{ rule, reason string }

func (a *exitAnswer) note(line string) {
	name, value, ok := strings.Cut(line, ":")
	if !ok {
		return
	}
	value = printable(strings.TrimSpace(value), 300)
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "vpnw-rule":
		a.rule = value
	case "vpnw-reason":
		a.reason = value
	}
}

func (a *exitAnswer) err(code int, status []string) error {
	switch {
	case code == 407:
		return errors.New("the exit refused the token")
	case code == 403 && a.reason != "":
		return fmt.Errorf("the exit refused it (%s): %s", a.rule, a.reason)
	case a.reason != "":
		return fmt.Errorf("the exit answered %d: %s", code, a.reason)
	}
	return fmt.Errorf("http exit answered %s", printable(strings.TrimSpace(strings.Join(status[1:], " ")), 300))
}

// printable keeps text from a remote side short and free of control
// characters before it goes into an error or an event.
func printable(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= max {
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

// tlsHealth checks a proxy reached over TLS: it must accept a connection,
// show a certificate that passes the check, and accept the token. An https://
// proxy is asked GET /health, which a VPN Works exit answers; a socks5+tls://
// proxy is logged in to.
func (p *Proxy) tlsHealth(ctx context.Context) error {
	c, err := p.Dialer.DialContext(ctx, "tcp", p.Addr)
	if err != nil {
		return fmt.Errorf("proxy %s is not reachable: %v", p.Addr, shortErr(err))
	}
	defer c.Close()
	tc := tls.Client(c, p.TLS)
	if err := tc.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("TLS with %s: %v", p.Addr, tlsReason(err))
	}
	if dl, ok := ctx.Deadline(); ok {
		tc.SetDeadline(dl)
	}
	if p.Scheme == "http" {
		err = p.httpHealth(tc)
	} else {
		err = p.socksHealth(tc)
	}
	if err != nil {
		return fmt.Errorf("exit %s: %v", p.Addr, err)
	}
	return nil
}

// httpHealth asks GET /health. 200 is healthy; 407 means the token was
// refused and 503 that the exit takes no connections. Any other answer
// still shows a working proxy that has no health page, and passes.
func (p *Proxy) httpHealth(c net.Conn) error {
	var b strings.Builder
	fmt.Fprintf(&b, "GET /health HTTP/1.1\r\nHost: %s\r\n", p.Addr)
	if p.User != "" {
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", base64.StdEncoding.EncodeToString([]byte(p.User+":"+p.Pass)))
	}
	b.WriteString("Connection: close\r\n\r\n")
	if _, err := io.WriteString(c, b.String()); err != nil {
		return err
	}
	br := bufio.NewReader(io.LimitReader(c, 16<<10))
	status, err := br.ReadString('\n')
	if err != nil {
		return fmt.Errorf("no answer to the health check: %v", err)
	}
	f := strings.Fields(status)
	if len(f) < 2 || !strings.HasPrefix(f[0], "HTTP/1.") {
		return errors.New("bad answer to the health check")
	}
	switch f[1] {
	case "407":
		return errors.New("the exit refused the token")
	case "503":
		return errors.New("the exit is not taking connections")
	}
	return nil
}

// socksHealth logs in to a SOCKS5 proxy and leaves before asking for
// anything.
func (p *Proxy) socksHealth(c net.Conn) error {
	method := byte(0x00)
	if p.User != "" {
		method = 0x02
	}
	if _, err := c.Write([]byte{0x05, 0x01, method}); err != nil {
		return err
	}
	var rep [2]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		return fmt.Errorf("no answer to the health check: %v", err)
	}
	if rep[0] != 0x05 {
		return errors.New("socks5 exit answered with the wrong version")
	}
	switch rep[1] {
	case 0x00:
		return nil
	case 0x02:
		if method != 0x02 {
			return errors.New("the exit wants a token")
		}
	default:
		return errors.New("the exit accepts none of our login methods")
	}
	auth := []byte{0x01, byte(len(p.User))}
	auth = append(auth, p.User...)
	auth = append(auth, byte(len(p.Pass)))
	auth = append(auth, p.Pass...)
	if _, err := c.Write(auth); err != nil {
		return err
	}
	var ar [2]byte
	if _, err := io.ReadFull(c, ar[:]); err != nil {
		return fmt.Errorf("no answer to the login: %v", err)
	}
	if ar[1] != 0x00 {
		return errors.New("the exit refused the token")
	}
	return nil
}

// Options are what a proxy path takes besides its URLs.
type Options struct {
	// DNS is "local", "remote", or "" for each URL scheme's own default.
	DNS string
	// CAFile holds the certificates (PEM) to trust for proxies reached over
	// TLS, for exits with a private CA. Empty means the system's.
	CAFile string
	// TokenFile holds the token, sent as the proxy password. It is never
	// printed or recorded.
	TokenFile string
	// Dir is where relative file names start: the configuration file's
	// folder.
	Dir string
}

// Build makes a proxy path from one URL, or a list of exits from several.
func Build(name string, urls []string, o Options) (Path, error) {
	if len(urls) == 0 {
		return nil, errors.New("no proxy URL")
	}
	if o.DNS != "" && o.DNS != "local" && o.DNS != "remote" {
		return nil, errors.New("dns must be local or remote")
	}
	var roots *x509.CertPool
	if o.CAFile != "" {
		var err error
		if roots, err = loadCA(inDir(o.Dir, o.CAFile)); err != nil {
			return nil, err
		}
	}
	token := ""
	if o.TokenFile != "" {
		var err error
		if token, err = readToken(inDir(o.Dir, o.TokenFile)); err != nil {
			return nil, err
		}
	}
	list := make([]*Proxy, 0, len(urls))
	seen := map[string]bool{}
	for _, raw := range urls {
		p, err := FromURL(name, raw)
		if err != nil {
			return nil, err
		}
		px := p.(*Proxy)
		if seen[px.Addr] {
			return nil, fmt.Errorf("exit %s is listed twice", px.Addr)
		}
		seen[px.Addr] = true
		switch o.DNS {
		case "local":
			px.Remote = false
		case "remote":
			px.Remote = true
		}
		if roots != nil {
			if px.TLS == nil {
				return nil, fmt.Errorf("a CA file is for proxies reached over TLS (https://, socks5+tls://), not %s", redact(raw))
			}
			px.TLS.RootCAs = roots
		}
		if o.TokenFile != "" {
			if px.Pass != "" {
				return nil, fmt.Errorf("%s has a password already; give the token in the URL or in a token file, not both", redact(raw))
			}
			px.Pass = token
			if px.User == "" {
				px.User = "vpnw"
			}
		}
		list = append(list, px)
	}
	if len(list) == 1 {
		return list[0], nil
	}
	for _, px := range list[1:] {
		if px.Remote != list[0].Remote {
			return nil, errors.New("the exits in a list must resolve names the same way; set dns to \"local\" or \"remote\"")
		}
	}
	return &Exits{Name: name, List: list}, nil
}

func inDir(dir, name string) string {
	if dir == "" || filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(dir, name)
}

func fileErr(err error) string {
	if pe, ok := err.(*os.PathError); ok {
		return pe.Err.Error()
	}
	return err.Error()
}

// readToken reads a token file: one token of 1 to 255 printable characters,
// with surrounding spaces and newlines removed. Errors never show its
// contents.
func readToken(name string) (string, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return "", fmt.Errorf("token file %s: %s", name, fileErr(err))
	}
	t := strings.TrimSpace(string(b))
	if t == "" {
		return "", fmt.Errorf("token file %s is empty", name)
	}
	if len(t) > 255 {
		return "", fmt.Errorf("token file %s: the token is longer than 255 bytes", name)
	}
	for i := 0; i < len(t); i++ {
		if t[i] <= 0x20 || t[i] >= 0x7f {
			return "", fmt.Errorf("token file %s must hold one token, with no spaces or other characters around it", name)
		}
	}
	return t, nil
}

// loadCA reads PEM certificates to trust.
func loadCA(name string) (*x509.CertPool, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("CA file %s: %s", name, fileErr(err))
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("CA file %s holds no PEM certificate", name)
	}
	return pool, nil
}
