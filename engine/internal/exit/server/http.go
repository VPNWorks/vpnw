// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"vpnw.com/vpnw/internal/exit"
	"vpnw.com/vpnw/internal/policy"
)

// Limits on an HTTP request head, as at the Agent's broker.
const (
	MaxHeadBytes   = 64 << 10
	MaxHeaderLines = 100
)

type header struct{ name, value string }

type head struct {
	method, target, proto string
	headers               []header
}

// get returns a header's value. A header sent twice is refused when the head
// is read, so there is never a choice between two values.
func (h *head) get(name string) string {
	for _, x := range h.headers {
		if strings.EqualFold(x.name, name) {
			return x.value
		}
	}
	return ""
}

var errHeadTooLarge = errors.New("request head too large")

// onlyOnce are the headers that decide who a request is from and how it is
// recorded; a second copy would make the answer depend on which one is read.
var onlyOnce = []string{"proxy-authorization", "authorization", "vpnw-run", "vpnw-conn", "vpnw-source"}

// readHead reads an HTTP/1.x request line and headers, strictly.
func readHead(br *bufio.Reader) (*head, error) {
	total := 0
	line, err := readLine(br, &total)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(line, " ")
	if len(parts) != 3 {
		return nil, errors.New("malformed request line")
	}
	h := &head{method: parts[0], target: parts[1], proto: parts[2]}
	if h.proto != "HTTP/1.1" && h.proto != "HTTP/1.0" {
		return nil, errors.New("unsupported protocol version")
	}
	if !token(h.method) || h.target == "" {
		return nil, errors.New("malformed request line")
	}
	seen := map[string]bool{}
	for {
		l, err := readLine(br, &total)
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
		name := strings.ToLower(l[:i])
		for _, o := range onlyOnce {
			if name == o {
				if seen[name] {
					return nil, fmt.Errorf("header %s is sent twice", l[:i])
				}
				seen[name] = true
			}
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

// basicPassword returns the password of a Basic credential: the token. The
// user name is not used; the token alone says who the client is.
func basicPassword(v string) string {
	const pfx = "Basic "
	if len(v) < len(pfx) || !strings.EqualFold(v[:len(pfx)], pfx) {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v[len(pfx):]))
	if err != nil {
		return ""
	}
	_, pass, ok := strings.Cut(string(raw), ":")
	if !ok {
		return ""
	}
	return pass
}

// bearer returns the token of an Authorization: Bearer header.
func bearer(v string) string {
	const pfx = "Bearer "
	if len(v) < len(pfx) || !strings.EqualFold(v[:len(pfx)], pfx) {
		return ""
	}
	return strings.TrimSpace(v[len(pfx):])
}

func reply(c net.Conn, status, extra, contentType, body string) {
	msg := fmt.Sprintf("HTTP/1.1 %s\r\nContent-Type: %s\r\nConnection: close\r\n%sContent-Length: %d\r\n\r\n%s",
		status, contentType, extra, len(body), body)
	c.Write([]byte(msg))
}

func text(c net.Conn, status, extra, body string) {
	reply(c, status, extra, "text/plain; charset=utf-8", body)
}

// headerValue makes text safe for one header line.
func headerValue(s string) string {
	s = sanitize(s)
	if len(s) > 400 {
		s = s[:400] + "..."
	}
	return s
}

const authHeader = "Proxy-Authenticate: Basic realm=\"vpnw-exit\"\r\n"

func (s *Server) http(c net.Conn, br *bufio.Reader, peer string) {
	h, err := readHead(br)
	if err != nil {
		if errors.Is(err, errHeadTooLarge) {
			text(c, "431 Request Header Fields Too Large", "", "vpnw-exit: request head too large\n")
		} else if err != io.EOF {
			text(c, "400 Bad Request", "", "vpnw-exit: "+err.Error()+"\n")
		}
		return
	}
	if h.method == "GET" && h.target == "/health" {
		s.healthCheck(c, h, peer)
		return
	}
	if h.method != "CONNECT" {
		text(c, "405 Method Not Allowed", "Allow: CONNECT\r\n", "vpnw-exit: this is an exit; send CONNECT host:port, or GET /health\n")
		return
	}
	host, port, err := splitTarget(h.target)
	if err != nil {
		text(c, "400 Bad Request", "", "vpnw-exit: "+err.Error()+"\n")
		return
	}
	tok := basicPassword(h.get("Proxy-Authorization"))
	cl := s.Config.Lookup(tok)
	if cl == nil {
		s.refuseAuth(peer, "http-connect", host, port, tokenReason(tok))
		text(c, "407 Proxy Authentication Required", authHeader, "vpnw-exit: a valid token is required\n")
		return
	}
	ids, err := exit.FromHeaders(h.get("VPNW-Run"), h.get("VPNW-Conn"), h.get("VPNW-Source"))
	if err != nil {
		text(c, "400 Bad Request", "", "vpnw-exit: "+err.Error()+"\n")
		return
	}
	o := s.open(cl, ids, host, port, "http-connect", peer)
	where := net.JoinHostPort(host, strconv.Itoa(port))
	if o.denied != nil {
		text(c, "403 Forbidden", "VPNW-Rule: "+headerValue(o.denied.rule)+"\r\nVPNW-Reason: "+headerValue(o.denied.reason)+"\r\n",
			fmt.Sprintf("vpnw-exit: refused %s (%s: %s)\n", sanitize(where), o.denied.rule, o.denied.reason))
		return
	}
	if o.err != nil {
		text(c, "502 Bad Gateway", "VPNW-Reason: "+headerValue(o.err.Error())+"\r\n",
			fmt.Sprintf("vpnw-exit: cannot reach %s: %v\n", sanitize(where), o.err))
		return
	}
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		o.conn.Close()
		s.recordClose(o, 0, 0)
		return
	}
	s.relay(o, c, br)
}

// Health is what GET /health answers a client with a valid token.
type Health struct {
	Exit    string `json:"exit"`
	Version string `json:"version"`
	Status  string `json:"status"`
	Client  string `json:"client"`
}

// healthCheck answers GET /health: 200 with the exit's name for a client
// with a valid token (in Proxy-Authorization, or Authorization as Basic or
// Bearer), 407 for anyone else.
func (s *Server) healthCheck(c net.Conn, h *head, peer string) {
	tok := basicPassword(h.get("Proxy-Authorization"))
	if tok == "" {
		tok = basicPassword(h.get("Authorization"))
	}
	if tok == "" {
		tok = bearer(h.get("Authorization"))
	}
	cl := s.Config.Lookup(tok)
	if cl == nil {
		s.refuseAuth(peer, "health", "", 0, tokenReason(tok))
		text(c, "407 Proxy Authentication Required", authHeader, "vpnw-exit: a valid token is required\n")
		return
	}
	s.health.Add(1)
	b, _ := json.Marshal(Health{Exit: s.Config.Name, Version: exit.Version, Status: "ok", Client: cl.Name})
	reply(c, "200 OK", "", "application/json", string(b)+"\n")
}
