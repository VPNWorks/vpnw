// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package wgtest runs a WireGuard peer for tests, in user space, the same
// way vpnw runs its end of a tunnel. Inside the tunnel the peer is
// 10.9.0.1, with a web server on port 80 that says who is asking and a DNS
// server on port 53 that knows a few names. Its UDP end listens on
// 127.0.0.1, so nothing leaves the machine.
package wgtest

import (
	"crypto/ecdh"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Addresses inside the test tunnel.
var (
	PeerIP   = netip.MustParseAddr("10.9.0.1")
	ClientIP = netip.MustParseAddr("10.9.0.2")
)

// Names the DNS server inside the tunnel answers.
var Names = map[string]netip.Addr{
	"web.tunnel.test.":      PeerIP,
	"internal.tunnel.test.": netip.MustParseAddr("10.9.0.99"),
}

type key struct{ priv, pub []byte }

func newKey() key {
	k, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		panic(err)
	}
	return key{k.Bytes(), k.PublicKey().Bytes()}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// BigSize is what GET /big sends.
const BigSize = 16 << 20

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// Server is a running test peer.
type Server struct {
	Port     int // its UDP port on 127.0.0.1
	dev      *device.Device
	peer     key
	client   key
	Requests atomic.Int64 // web requests served
	DNS      atomic.Int64 // DNS queries answered
	closers  []io.Closer
}

// Start runs a test peer that accepts one client key.
func Start() (*Server, error) {
	s := &Server{peer: newKey(), client: newKey()}
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{PeerIP}, nil, 1420)
	if err != nil {
		return nil, err
	}
	// A free UDP port, picked by the system.
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s.Port = pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	s.dev = device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	cfg := fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\nallowed_ip=%s/32\n",
		hex.EncodeToString(s.peer.priv), s.Port, hex.EncodeToString(s.client.pub), ClientIP)
	if err := s.dev.IpcSet(cfg); err != nil {
		s.dev.Close()
		return nil, err
	}
	if err := s.dev.Up(); err != nil {
		s.dev.Close()
		return nil, err
	}

	web, err := tnet.ListenTCPAddrPort(netip.AddrPortFrom(PeerIP, 80))
	if err != nil {
		s.Close()
		return nil, err
	}
	s.closers = append(s.closers, web)
	go http.Serve(web, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			// 16 MiB, for measuring how fast the tunnel carries data.
			w.Header().Set("Content-Length", fmt.Sprint(BigSize))
			io.CopyN(w, zeros{}, BigSize)
			return
		}
		s.Requests.Add(1)
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		fmt.Fprintf(w, "hello through the tunnel, %s\n", host)
	}))

	dns, err := tnet.ListenUDPAddrPort(netip.AddrPortFrom(PeerIP, 53))
	if err != nil {
		s.Close()
		return nil, err
	}
	s.closers = append(s.closers, dns)
	go s.serveDNS(dns)
	return s, nil
}

func (s *Server) serveDNS(c net.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			return
		}
		var p dnsmessage.Parser
		h, err := p.Start(buf[:n])
		if err != nil {
			continue
		}
		q, err := p.Question()
		if err != nil {
			continue
		}
		s.DNS.Add(1)
		rh := dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true}
		ip, ok := Names[strings.ToLower(q.Name.String())]
		if !ok {
			rh.RCode = dnsmessage.RCodeNameError
		}
		b := dnsmessage.NewBuilder(nil, rh)
		b.EnableCompression()
		b.StartQuestions()
		b.Question(q)
		b.StartAnswers()
		if ok && q.Type == dnsmessage.TypeA {
			b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: ip.As4()})
		}
		out, err := b.Finish()
		if err == nil {
			c.WriteTo(out, from)
		}
	}
}

// ClientConfig is a wg-quick file for the one client this peer accepts.
func (s *Server) ClientConfig() string {
	return s.config(s.client.priv)
}

// StrangerConfig is a wg-quick file with a key the peer doesn't know: its
// handshakes go unanswered, as WireGuard answers no one it doesn't know.
func (s *Server) StrangerConfig() string {
	return s.config(newKey().priv)
}

func (s *Server) config(priv []byte) string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
DNS = %s

[Peer]
PublicKey = %s
Endpoint = 127.0.0.1:%d
AllowedIPs = 10.9.0.0/24
`, b64(priv), ClientIP, PeerIP, b64(s.peer.pub), s.Port)
}

// Close stops the peer.
func (s *Server) Close() {
	for _, c := range s.closers {
		c.Close()
	}
	s.dev.Close()
}
