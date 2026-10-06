// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package scopetest runs Scope against the Linux kernel: a VPN gateway, the
// clients behind it and the office servers, each in a private network
// namespace, with Scope's nftables rules loaded into the gateway's real
// firewall. It checks that the kernel decides every connection exactly as
// Scope's simulator does, and that the recorder sees every new connection.
package scopetest

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"vpnw.com/vpnw/internal/scope"
	"vpnw.com/vpnw/internal/scope/office"
	"vpnw.com/vpnw/internal/testnet"
)

func TestMain(m *testing.M) {
	if err := testnet.Reexec(); err != nil {
		fmt.Println("scope integration tests need user namespaces:", err)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// world is a gateway (this process's namespace) between a clients
// namespace and an office namespace.
type world struct {
	clients, office *testnet.NS
	closers         []func()
	jobs            chan func()
}

func need(t testing.TB) {
	t.Helper()
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft is not installed")
	}
}

// build wires up the namespaces for an office: every person's VPN address on
// the clients side, every system's address and service on the office side.
func build(t testing.TB, o *office.Office, extra ...netip.Addr) *world {
	t.Helper()
	need(t)
	w := &world{}
	var err error
	if w.clients, err = testnet.NewNS("clients"); err != nil {
		t.Fatal(err)
	}
	if w.office, err = testnet.NewNS("office"); err != nil {
		w.clients.Close()
		t.Fatal(err)
	}
	t.Cleanup(w.close)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	// The gateway routes the VPN range to the clients namespace and the
	// office ranges to the office namespace, over two small point-to-point
	// links, much as a tunnel interface would. Client and system addresses
	// live on the loopback of their own namespace, so the gateway has one
	// neighbour on each side however many people there are.
	must(testnet.AddVeth("g0", "c0"))
	must(testnet.MoveLink("c0", w.clients))
	must(testnet.AddVeth("g1", "o0"))
	must(testnet.MoveLink("o0", w.office))
	must(testnet.AddAddr("g0", "172.31.0.1/30"))
	must(testnet.LinkUp("g0"))
	must(testnet.AddAddr("g1", "172.31.1.1/30"))
	must(testnet.LinkUp("g1"))
	must(testnet.AddRoute(o.VPNNet.String(), "172.31.0.2"))
	nets := map[string]bool{}
	for _, s := range o.Systems {
		b := s.Addr.As4()
		nets[fmt.Sprintf("%d.%d.0.0/16", b[0], b[1])] = true
	}
	for n := range nets {
		must(testnet.AddRoute(n, "172.31.1.2"))
	}
	must(testnet.Here.Sysctl("net/ipv4/ip_forward", "1"))
	// Refusals are ICMP errors, which Linux rate-limits; lift the limits so
	// every refused connection is refused at once instead of timing out.
	for _, ns := range []*testnet.NS{testnet.Here, w.clients, w.office} {
		must(ns.Sysctl("net/ipv4/icmp_ratelimit", "0"))
		must(ns.Sysctl("net/ipv4/icmp_msgs_per_sec", "100000"))
		must(ns.Sysctl("net/ipv4/icmp_msgs_burst", "100000"))
	}
	must(w.clients.Do(func() error {
		for _, m := range o.Members {
			if err := testnet.AddAddr("lo", m.Addr.String()+"/32"); err != nil {
				return err
			}
		}
		for _, a := range extra {
			if err := testnet.AddAddr("lo", a.String()+"/32"); err != nil {
				return err
			}
		}
		if err := testnet.AddAddr("c0", "172.31.0.2/30"); err != nil {
			return err
		}
		if err := testnet.LinkUp("c0"); err != nil {
			return err
		}
		return testnet.AddRoute("default", "172.31.0.1")
	}))
	must(w.office.Do(func() error {
		for _, s := range o.Systems {
			if err := testnet.AddAddr("lo", s.Addr.String()+"/32"); err != nil {
				return err
			}
		}
		if err := testnet.AddAddr("o0", "172.31.1.2/30"); err != nil {
			return err
		}
		if err := testnet.LinkUp("o0"); err != nil {
			return err
		}
		if err := testnet.AddRoute("default", "172.31.1.1"); err != nil {
			return err
		}
		// One listener per service.
		for _, s := range o.Systems {
			for _, sv := range s.Services {
				addr := fmt.Sprintf("%s:%d", s.Addr, sv.Port)
				if sv.Proto == scope.TCP {
					ln, err := net.Listen("tcp", addr)
					if err != nil {
						return err
					}
					w.closers = append(w.closers, func() { ln.Close() })
					go func() {
						for {
							c, err := ln.Accept()
							if err != nil {
								return
							}
							c.Close()
						}
					}()
				} else {
					pc, err := net.ListenPacket("udp", addr)
					if err != nil {
						return err
					}
					w.closers = append(w.closers, func() { pc.Close() })
					go func() {
						buf := make([]byte, 512)
						for {
							n, from, err := pc.ReadFrom(buf)
							if err != nil {
								return
							}
							pc.WriteTo(buf[:n], from)
						}
					}()
				}
			}
		}
		return nil
	}))
	// One thread stays in the clients namespace to open every probe socket.
	w.jobs = make(chan func())
	ready := make(chan struct{})
	go w.clients.Do(func() error {
		close(ready)
		for job := range w.jobs {
			job()
		}
		return nil
	})
	<-ready
	return w
}

func (w *world) close() {
	if w.jobs != nil {
		close(w.jobs)
	}
	for _, c := range w.closers {
		c()
	}
	w.clients.Close()
	w.office.Close()
	testnet.DelLink("g0")
	testnet.DelLink("g1")
	exec.Command("nft", "flush", "ruleset").Run()
}

// load loads an nftables script into the gateway.
func load(t testing.TB, script string) {
	t.Helper()
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft: %v\n%s", err, out)
	}
}

// Result of one real connection attempt.
type Result int

const (
	Reached Result = iota // the office host answered: open or closed port
	Refused               // the gateway refused it
)

func (r Result) String() string {
	if r == Reached {
		return "reached"
	}
	return "refused"
}

// probe makes one real connection attempt from f.Src to f.Dst:f.Port.
func (w *world) probe(f scope.Flow) (Result, error) {
	type answer struct {
		r   Result
		err error
	}
	ch := make(chan answer, 1)
	w.jobs <- func() {
		r, err := attempt(f)
		ch <- answer{r, err}
	}
	a := <-ch
	return a.r, a.err
}

func attempt(f scope.Flow) (Result, error) {
	classify := func(err error) (Result, error) {
		switch {
		case err == nil, errors.Is(err, syscall.ECONNREFUSED):
			return Reached, nil
		case errors.Is(err, syscall.EHOSTUNREACH):
			return Refused, nil
		}
		return Refused, fmt.Errorf("%s -> %s:%d/%s: %v", f.Src, f.Dst, f.Port, f.Proto, err)
	}
	if f.Proto == scope.TCP {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: f.Src.AsSlice()}, Timeout: 2 * time.Second}
		c, err := d.Dial("tcp", fmt.Sprintf("%s:%d", f.Dst, f.Port))
		if c != nil {
			c.Close()
		}
		return classify(err)
	}
	d := net.Dialer{LocalAddr: &net.UDPAddr{IP: f.Src.AsSlice()}, Timeout: 2 * time.Second}
	c, err := d.Dial("udp", fmt.Sprintf("%s:%d", f.Dst, f.Port))
	if err != nil {
		return classify(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("?")); err != nil {
		return classify(err)
	}
	buf := make([]byte, 16)
	_, err = c.Read(buf)
	return classify(err)
}
