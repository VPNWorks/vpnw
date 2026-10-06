// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package netlink

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"vpnw.com/vpnw/internal/testnet"
)

func TestMain(m *testing.M) {
	if err := testnet.Reexec(); err != nil {
		fmt.Println("netlink tests need user namespaces, skipping:", err)
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

var (
	pfx  = netip.MustParsePrefix
	addr = netip.MustParseAddr
)

func has(routes []Route, want Route) bool {
	for _, r := range routes {
		if r.Dst == want.Dst && r.Gateway == want.Gateway && (want.Dev == "" || r.Dev == want.Dev) {
			return true
		}
	}
	return false
}

func TestAddressesRoutesAndTUN(t *testing.T) {
	f, err := OpenTUN("labtun0", false)
	must(t, err)
	defer f.Close()
	must(t, SetUp("labtun0", true))
	must(t, AddAddr("labtun0", pfx("10.66.0.2/24")))
	if err := AddAddr("labtun0", pfx("10.66.0.2/24")); !errors.Is(err, syscall.EEXIST) {
		t.Fatalf("second add: %v", err)
	}
	must(t, SetMTU("labtun0", 1400))
	if ifi, _ := net.InterfaceByName("labtun0"); ifi.MTU != 1400 || ifi.Flags&net.FlagUp == 0 {
		t.Fatalf("interface: %+v", ifi)
	}
	main, err := Routes(0)
	must(t, err)
	if !has(main, Route{Dst: pfx("10.66.0.0/24"), Dev: "labtun0"}) {
		t.Fatalf("no prefix route for the address: %v", main)
	}
	def := Route{Dst: pfx("0.0.0.0/0"), Dev: "labtun0", Table: 51820}
	must(t, AddRoute(def))
	if err := AddRoute(def); !errors.Is(err, syscall.EEXIST) {
		t.Fatalf("second add: %v", err)
	}
	tbl, err := Routes(51820)
	must(t, err)
	if len(tbl) != 1 || !has(tbl, def) || tbl[0].Table != 51820 || tbl[0].String() != "default dev labtun0 table 51820" {
		t.Fatalf("table 51820: %v", tbl)
	}
	must(t, DelRoute(def))
	if err := DelRoute(def); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("second delete: %v", err)
	}
	gw := Route{Dst: pfx("198.51.100.0/24"), Gateway: addr("10.66.0.1"), Metric: 5}
	must(t, AddRoute(gw))
	main, _ = Routes(0)
	if !has(main, gw) || gw.String() != "198.51.100.0/24 via 10.66.0.1" {
		t.Fatalf("gateway route: %v", main)
	}
	must(t, DelRoute(gw))
	must(t, DelAddr("labtun0", pfx("10.66.0.2/24")))
	must(t, SetUp("labtun0", false))
	if ifi, _ := net.InterfaceByName("labtun0"); ifi.Flags&net.FlagUp != 0 {
		t.Fatal("still up")
	}
}

func TestRules(t *testing.T) {
	strict := Rule{Priority: 100, Table: 51820, Mark: 0x51, Invert: true}
	lan := Rule{Priority: 90, Table: MainTable, Dst: pfx("192.168.1.0/24")}
	for _, r := range []Rule{strict, lan} {
		must(t, AddRule(r))
		if err := AddRule(r); !errors.Is(err, syscall.EEXIST) {
			t.Fatalf("second add of %s: %v", r, err)
		}
	}
	rules, err := Rules()
	must(t, err)
	found := 0
	for _, r := range rules {
		if r == strict || r == lan {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("rules: %v", rules)
	}
	if strict.String() != "100: not fwmark 0x51 lookup 51820" || lan.String() != "90: to 192.168.1.0/24 lookup 254" {
		t.Fatal(strict.String(), lan.String())
	}
	for _, r := range []Rule{strict, lan} {
		must(t, DelRule(r))
		if err := DelRule(r); !errors.Is(err, syscall.ENOENT) {
			t.Fatalf("second delete of %s: %v", r, err)
		}
	}
}

// source asks the kernel which source address it would use to reach dst,
// for a socket with an optional mark and device: the route it picked.
func source(t *testing.T, dst string, mark int, dev string) string {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	must(t, err)
	defer syscall.Close(fd)
	if mark != 0 {
		must(t, syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, mark))
	}
	if dev != "" {
		must(t, syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, dev))
	}
	a := addr(dst).As4()
	if err := syscall.Connect(fd, &syscall.SockaddrInet4{Port: 9, Addr: a}); err != nil {
		return "error: " + err.Error()
	}
	sa, err := syscall.Getsockname(fd)
	must(t, err)
	return netip.AddrFrom4(sa.(*syscall.SockaddrInet4).Addr).String()
}

// TestRoutingDecisions checks the kernel behavior the stand-in clients
// depend on, by the source address the kernel picks:
//   - a rule "not fwmark 0x51 lookup 51820" sends unmarked traffic to the
//     tunnel's table, past any more specific route in the main table, while
//     marked traffic (the client's own) uses the main table;
//   - routes 0/1 and 128/1 through the tunnel lose to a more specific route
//     in the main table, the flaw the follows-routes client keeps;
//   - a socket bound to the physical device skips the tunnel's routes.
func TestRoutingDecisions(t *testing.T) {
	must(t, testnet.AddVeth("phys0", "peer0"))
	defer testnet.DelLink("phys0")
	must(t, AddAddr("phys0", pfx("192.168.1.10/24")))
	must(t, SetUp("phys0", true))
	must(t, SetUp("peer0", true))
	must(t, AddRoute(Route{Dst: pfx("0.0.0.0/0"), Gateway: addr("192.168.1.1")}))
	f, err := OpenTUN("labtun2", false)
	must(t, err)
	defer f.Close()
	must(t, SetUp("labtun2", true))
	must(t, AddAddr("labtun2", pfx("10.66.0.2/24")))

	if got := source(t, "198.51.100.10", 0, ""); got != "192.168.1.10" {
		t.Fatalf("before the tunnel: %s", got)
	}
	// Strict: everything unmarked goes to table 51820.
	strict := Rule{Priority: 100, Table: 51820, Mark: 0x51, Invert: true}
	must(t, AddRule(strict))
	must(t, AddRoute(Route{Dst: pfx("0.0.0.0/0"), Dev: "labtun2", Table: 51820}))
	// A pushed route names its device, as a DHCP client does. Without it,
	// the kernel finds the gateway through the rules, and so the tunnel.
	pushed := Route{Dst: pfx("198.51.100.0/24"), Gateway: addr("192.168.1.1"), Dev: "phys0"}
	must(t, AddRoute(pushed))
	if got := source(t, "198.51.100.10", 0, ""); got != "10.66.0.2" {
		t.Fatalf("strict routing with a pushed route: %s", got)
	}
	if got := source(t, "192.0.2.10", 0x51, ""); got != "192.168.1.10" {
		t.Fatalf("the client's own marked traffic: %s", got)
	}
	// With the tunnel's route gone, unmarked traffic falls through to main.
	must(t, DelRoute(Route{Dst: pfx("0.0.0.0/0"), Dev: "labtun2", Table: 51820}))
	if got := source(t, "203.0.113.5", 0, ""); got != "192.168.1.10" {
		t.Fatalf("strict routing with the tunnel's route removed: %s", got)
	}
	must(t, DelRule(strict))

	// Main-table routing: the pushed /24 beats 0/1 and 128/1.
	for _, p := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		must(t, AddRoute(Route{Dst: pfx(p), Dev: "labtun2"}))
	}
	if got := source(t, "203.0.113.5", 0, ""); got != "10.66.0.2" {
		t.Fatalf("main-table routing: %s", got)
	}
	if got := source(t, "198.51.100.10", 0, ""); got != "192.168.1.10" {
		t.Fatalf("main-table routing with a pushed route should leave the tunnel: %s", got)
	}
	if got := source(t, "192.0.2.10", 0, "phys0"); got != "192.168.1.10" {
		t.Fatalf("a socket bound to the physical device: %s", got)
	}
	must(t, DelRoute(pushed))
}

func TestPersistentTUN(t *testing.T) {
	f, err := OpenTUN("labtun3", true)
	must(t, err)
	f.Close()
	if _, err := net.InterfaceByName("labtun3"); err != nil {
		t.Fatal("a persistent TUN went away with its file")
	}
	f, err = OpenTUN("labtun3", true)
	must(t, err)
	must(t, DropPersist(f))
	f.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := net.InterfaceByName("labtun3"); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the TUN stayed after its persistence was dropped")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestTUNCarriesPackets writes a packet in through the TUN device and reads
// the kernel's reply out of it.
func TestTUNCarriesPackets(t *testing.T) {
	f, err := OpenTUN("labtun4", false)
	must(t, err)
	defer f.Close()
	must(t, SetUp("labtun4", true))
	must(t, AddAddr("labtun4", pfx("10.77.0.1/24")))
	// An ICMP echo request from 10.77.0.2 to 10.77.0.1.
	pkt := []byte{0x45, 0, 0, 28, 0, 1, 0, 0, 64, 1, 0, 0, 10, 77, 0, 2, 10, 77, 0, 1, 8, 0, 0, 0, 0x12, 0x34, 0, 1}
	csum := func(b []byte) uint16 {
		var s uint32
		for i := 0; i+1 < len(b); i += 2 {
			s += uint32(b[i])<<8 | uint32(b[i+1])
		}
		for s>>16 != 0 {
			s = s&0xffff + s>>16
		}
		return ^uint16(s)
	}
	c := csum(pkt[:20])
	pkt[10], pkt[11] = byte(c>>8), byte(c)
	c = csum(pkt[20:])
	pkt[22], pkt[23] = byte(c>>8), byte(c)
	if _, err := f.Write(pkt); err != nil {
		t.Fatal(err)
	}
	f.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	for {
		n, err := f.Read(buf)
		if err != nil {
			t.Fatalf("no reply: %v", err)
		}
		if n >= 28 && buf[9] == 1 && buf[20] == 0 && netip.AddrFrom4([4]byte(buf[16:20])).String() == "10.77.0.2" {
			return
		}
	}
}

func TestErrors(t *testing.T) {
	for i, err := range []error{
		AddRoute(Route{Dst: pfx("10.0.0.0/8")}),
		AddRoute(Route{Dst: pfx("2001:db8::/32"), Dev: "lo"}),
		AddRoute(Route{Gateway: addr("10.0.0.1")}),
		AddRoute(Route{Dst: pfx("10.0.0.0/8"), Dev: "nosuchdev"}),
		DelRoute(Route{Dst: pfx("10.0.0.0/8")}),
		AddRule(Rule{Priority: 1}),
		DelRule(Rule{Priority: 1}),
		AddRule(Rule{Priority: 1, Table: 5, Dst: pfx("2001:db8::/32")}),
		AddAddr("lo", pfx("2001:db8::1/64")),
		AddAddr("nosuchdev", pfx("10.0.0.1/8")),
		DelAddr("nosuchdev", pfx("10.0.0.1/8")),
		SetUp("nosuchdev", true),
		SetMTU("nosuchdev", 1400),
		func() error {
			f, err := OpenTUN("labtun5", false)
			if err != nil {
				return nil
			}
			defer f.Close()
			return SetMTU("labtun5", 70000)
		}(),
	} {
		if err == nil {
			t.Errorf("case %d: an error was expected", i)
		}
	}
	for _, name := range []string{"", strings.Repeat("x", 16)} {
		if _, err := OpenTUN(name, false); err == nil {
			t.Errorf("OpenTUN(%q) should fail", name)
		}
	}
	if _, err := Index("nosuchdev"); err == nil {
		t.Fatal("Index of a missing interface")
	}
	if a := attrs([]byte{2, 0, 1, 0}); len(a) != 0 {
		t.Fatal("a short attribute should end the list")
	}
}
