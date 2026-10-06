// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package testnet

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if err := Reexec(); err != nil {
		fmt.Println("testnet: no user namespaces here, skipping:", err)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// TestForwardAndFirewall builds clients <-> gateway (here) <-> office,
// checks that traffic is forwarded, then loads an nftables ruleset with a
// concatenated interval set and checks that it allows one client and
// rejects the other.
func TestForwardAndFirewall(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	c, err := NewNS("clients")
	must(t, err)
	defer c.Close()
	o, err := NewNS("office")
	must(t, err)
	defer o.Close()

	must(t, AddVeth("g0", "c0"))
	must(t, MoveLink("c0", c))
	must(t, AddVeth("g1", "o0"))
	must(t, MoveLink("o0", o))
	must(t, AddAddr("g0", "10.8.0.1/24"))
	must(t, LinkUp("g0"))
	must(t, AddAddr("g1", "10.0.0.1/16"))
	must(t, LinkUp("g1"))
	must(t, Here.Sysctl("net/ipv4/ip_forward", "1"))
	must(t, c.Do(func() error {
		for _, a := range []string{"10.8.0.11/24", "10.8.0.12/24"} {
			if err := AddAddr("c0", a); err != nil {
				return err
			}
		}
		if err := LinkUp("c0"); err != nil {
			return err
		}
		return AddRoute("default", "10.8.0.1")
	}))
	must(t, o.Do(func() error {
		for _, a := range []string{"10.0.0.2/16", "10.0.1.20/16"} {
			if err := AddAddr("o0", a); err != nil {
				return err
			}
		}
		if err := LinkUp("o0"); err != nil {
			return err
		}
		return AddRoute("default", "10.0.0.1")
	}))

	var ln net.Listener
	must(t, o.Do(func() error {
		var err error
		ln, err = net.Listen("tcp", "10.0.1.20:443")
		return err
	}))
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	dial := func(src string) error {
		return c.Do(func() error {
			d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: 2 * time.Second}
			conn, err := d.Dial("tcp", "10.0.1.20:443")
			if conn != nil {
				conn.Close()
			}
			return err
		})
	}
	must(t, dial("10.8.0.11"))
	must(t, dial("10.8.0.12"))

	rules := `table inet probe {
	set alice_tcp {
		type ipv4_addr . inet_service
		flags interval
		elements = { 10.0.1.20 . 443, 10.0.3.0/24 . 8000-8100 }
	}
	chain forward {
		type filter hook forward priority filter; policy accept;
		ip saddr 10.8.0.0/24 jump from_vpn
	}
	chain from_vpn {
		ct state established,related accept
		ip saddr 10.8.0.11 ip daddr . tcp dport @alice_tcp accept
		reject with icmpx type admin-prohibited
	}
}
`
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft: %v: %s", err, out)
	}
	must(t, dial("10.8.0.11"))
	err = dial("10.8.0.12")
	if !errors.Is(err, syscall.EHOSTUNREACH) {
		t.Fatalf("10.8.0.12 should be rejected with host unreachable, got %v", err)
	}
}
