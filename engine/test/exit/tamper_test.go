// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package exittest

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// answer is what an exit told a client that talked to it directly.
type answer struct {
	status       int
	rule, reason string
	body         string // the destination's answer, when the tunnel opened
	err          error
}

// tamper is a client that skips any policy of its own and talks to an exit
// directly, from the agents' machine: one HTTP CONNECT with the token given,
// then, if the exit opens the tunnel, one HTTP request through it. source,
// if set, asks for a source address.
func (w *world) tamper(token, exitName, target, source string) answer {
	return w.tamperIDs(token, exitName, target, source, "", 0)
}

func (w *world) tlsConfig() *tls.Config {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(w.ca.pem)
	return &tls.Config{RootCAs: pool}
}

func (w *world) dialExit(exitName string) (*tls.Conn, error) {
	addr := deListen
	if exitName == "exit-nl" {
		addr = nlListen
	}
	var c net.Conn
	err := w.agents.Do(func() error {
		var err error
		c, err = net.DialTimeout("tcp", net.JoinHostPort(addr, strconv.Itoa(exitPort)), 5*time.Second)
		return err
	})
	if err != nil {
		return nil, err
	}
	cfg := w.tlsConfig()
	cfg.ServerName = addr
	tc := tls.Client(c, cfg)
	tc.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tc.Handshake(); err != nil {
		c.Close()
		return nil, err
	}
	return tc, nil
}

func (w *world) tamperIDs(token, exitName, target, source, run string, conn uint64) answer {
	tc, err := w.dialExit(exitName)
	if err != nil {
		return answer{err: err}
	}
	defer tc.Close()
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if token != "" {
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", base64.StdEncoding.EncodeToString([]byte("tampered:"+token)))
	}
	if source != "" {
		fmt.Fprintf(&b, "VPNW-Source: %s\r\n", source)
	}
	if run != "" {
		fmt.Fprintf(&b, "VPNW-Run: %s\r\nVPNW-Conn: %d\r\n", run, conn)
	}
	b.WriteString("\r\n")
	io.WriteString(tc, b.String())
	br := bufio.NewReader(tc)
	status, err := br.ReadString('\n')
	if err != nil {
		return answer{err: err}
	}
	var a answer
	f := strings.Fields(status)
	if len(f) >= 2 {
		a.status, _ = strconv.Atoi(f[1])
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil || l == "\r\n" {
			break
		}
		k, v, _ := strings.Cut(strings.TrimSpace(l), ":")
		switch strings.ToLower(k) {
		case "vpnw-rule":
			a.rule = strings.TrimSpace(v)
		case "vpnw-reason":
			a.reason = strings.TrimSpace(v)
		}
	}
	if a.status == 200 {
		host, _, _ := net.SplitHostPort(target)
		fmt.Fprintf(tc, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
		resp, _ := io.ReadAll(br)
		if i := strings.Index(string(resp), "\r\n\r\n"); i >= 0 {
			a.body = strings.TrimSpace(string(resp[i+4:]))
		}
	}
	return a
}

// socksTamper does the same over SOCKS5: user is the SOCKS5 user name, the
// token the password. It returns the reply code, or 0xff when the login
// was refused.
func (w *world) socksTamper(token, user, exitName, host string, port int) (byte, error) {
	tc, err := w.dialExit(exitName)
	if err != nil {
		return 0, err
	}
	defer tc.Close()
	tc.Write([]byte{5, 1, 2})
	var m [2]byte
	if _, err := io.ReadFull(tc, m[:]); err != nil {
		return 0, err
	}
	auth := append([]byte{1, byte(len(user))}, user...)
	auth = append(append(auth, byte(len(token))), token...)
	tc.Write(auth)
	var a [2]byte
	if _, err := io.ReadFull(tc, a[:]); err != nil {
		return 0, err
	}
	if a[1] != 0 {
		return 0xff, nil
	}
	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		req = append(append(req, 1), ip.To4()...)
	} else {
		req = append(append(req, 3, byte(len(host))), host...)
	}
	tc.Write(append(req, byte(port>>8), byte(port)))
	rep := make([]byte, 10)
	if _, err := io.ReadFull(tc, rep); err != nil {
		return 0, err
	}
	return rep[1], nil
}
