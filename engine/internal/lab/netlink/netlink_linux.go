// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package netlink changes a Linux network namespace the way Lab's stand-in
// VPN clients and test world need: addresses, routes in any table and
// through a device, policy-routing rules, and TUN devices. It speaks
// rtnetlink with the standard library only, in the calling thread's
// namespace.
package netlink

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"unsafe"
)

const (
	nlmsgHdrLen   = 16
	nlaHdrLen     = 4
	sizeofIfinfo  = 16
	sizeofIfaddr  = 8
	sizeofRtmsg   = 12
	nlmCreateExcl = syscall.NLM_F_CREATE | syscall.NLM_F_EXCL

	iflaMTU      = 4
	ifaAddress   = 1
	ifaLocal     = 2
	rtaDst       = 1
	rtaOif       = 4
	rtaGateway   = 5
	rtaPriority  = 6
	rtaTable     = 15
	rtTableMain  = 254
	rtprotStatic = 4
	rtScopeUniv  = 0
	rtScopeLink  = 253
	rtnUnicast   = 1

	rtmNewRule   = 32
	rtmDelRule   = 33
	rtmGetRule   = 34
	fraDst       = 1
	fraPriority  = 6
	fraFwmark    = 10
	fraTable     = 15
	fraFwmask    = 16
	frActToTbl   = 1
	fibRuleInv   = 0x2
	sizeofFibHdr = 12
)

var native = binary.NativeEndian

// MainTable is the number of the main routing table.
const MainTable = rtTableMain

func align4(n int) int { return (n + 3) &^ 3 }

func attr(typ uint16, data []byte) []byte {
	b := make([]byte, align4(nlaHdrLen+len(data)))
	native.PutUint16(b[0:], uint16(nlaHdrLen+len(data)))
	native.PutUint16(b[2:], typ)
	copy(b[nlaHdrLen:], data)
	return b
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	native.PutUint32(b, v)
	return b
}

// request sends one rtnetlink request and waits for the acknowledgement.
// With dump set it calls fn for every message of the answer instead.
func request(typ, flags uint16, body []byte, fn func(syscall.NetlinkMessage)) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	msg := make([]byte, nlmsgHdrLen+len(body))
	native.PutUint32(msg[0:], uint32(len(msg)))
	native.PutUint16(msg[4:], typ)
	native.PutUint16(msg[6:], flags|syscall.NLM_F_REQUEST|syscall.NLM_F_ACK)
	native.PutUint32(msg[8:], 1)
	copy(msg[nlmsgHdrLen:], body)
	if err := syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 1<<16)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return err
		}
		for _, m := range msgs {
			switch m.Header.Type {
			case syscall.NLMSG_DONE:
				return nil
			case syscall.NLMSG_ERROR:
				if len(m.Data) < 4 {
					return errors.New("short netlink error")
				}
				if code := int32(native.Uint32(m.Data[:4])); code != 0 {
					return syscall.Errno(-code)
				}
				return nil
			default:
				if fn != nil {
					fn(m)
				}
			}
		}
	}
}

// attrs splits a run of netlink attributes into a map by type.
func attrs(b []byte) map[uint16][]byte {
	out := map[uint16][]byte{}
	for len(b) >= nlaHdrLen {
		l := int(native.Uint16(b[0:]))
		if l < nlaHdrLen || l > len(b) {
			break
		}
		out[native.Uint16(b[2:])&0x3fff] = b[nlaHdrLen:l]
		b = b[min(align4(l), len(b)):]
	}
	return out
}

// Index returns an interface's index.
func Index(name string) (int, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return 0, fmt.Errorf("interface %s: %w", name, err)
	}
	return ifi.Index, nil
}

func ifinfo(index int, flags, change uint32) []byte {
	b := make([]byte, sizeofIfinfo)
	b[0] = syscall.AF_UNSPEC
	native.PutUint32(b[4:], uint32(index))
	native.PutUint32(b[8:], flags)
	native.PutUint32(b[12:], change)
	return b
}

// SetUp brings an interface up or takes it down.
func SetUp(name string, up bool) error {
	i, err := Index(name)
	if err != nil {
		return err
	}
	var flags uint32
	if up {
		flags = syscall.IFF_UP
	}
	if err := request(syscall.RTM_NEWLINK, 0, ifinfo(i, flags, syscall.IFF_UP), nil); err != nil {
		return fmt.Errorf("set %s up=%v: %w", name, up, err)
	}
	return nil
}

// SetMTU sets an interface's MTU.
func SetMTU(name string, mtu int) error {
	i, err := Index(name)
	if err != nil {
		return err
	}
	if err := request(syscall.RTM_NEWLINK, 0, append(ifinfo(i, 0, 0), attr(iflaMTU, u32(uint32(mtu)))...), nil); err != nil {
		return fmt.Errorf("set %s mtu %d: %w", name, mtu, err)
	}
	return nil
}

func addrMsg(typ, flags uint16, name string, p netip.Prefix) error {
	if !p.Addr().Is4() {
		return fmt.Errorf("address %s: want IPv4", p)
	}
	i, err := Index(name)
	if err != nil {
		return err
	}
	hdr := make([]byte, sizeofIfaddr)
	hdr[0] = syscall.AF_INET
	hdr[1] = byte(p.Bits())
	native.PutUint32(hdr[4:], uint32(i))
	a := p.Addr().As4()
	body := append(hdr, attr(ifaLocal, a[:])...)
	body = append(body, attr(ifaAddress, a[:])...)
	return request(typ, flags, body, nil)
}

// AddAddr adds an IPv4 address with its prefix to an interface. Adding one
// that is already there gives syscall.EEXIST.
func AddAddr(name string, p netip.Prefix) error {
	if err := addrMsg(syscall.RTM_NEWADDR, nlmCreateExcl, name, p); err != nil {
		return fmt.Errorf("add %s to %s: %w", p, name, err)
	}
	return nil
}

// DelAddr removes an address from an interface.
func DelAddr(name string, p netip.Prefix) error {
	if err := addrMsg(syscall.RTM_DELADDR, 0, name, p); err != nil {
		return fmt.Errorf("remove %s from %s: %w", p, name, err)
	}
	return nil
}

// Route is an IPv4 route.
type Route struct {
	Dst     netip.Prefix // 0.0.0.0/0 for the default route
	Gateway netip.Addr   // the next hop, or none for a route straight through Dev
	Dev     string       // the output device; may be empty when Gateway is set
	Table   int          // 0 means the main table
	Metric  int
}

func (r Route) String() string {
	s := r.Dst.String()
	if r.Dst.Bits() == 0 {
		s = "default"
	}
	if r.Gateway.IsValid() {
		s += " via " + r.Gateway.String()
	}
	if r.Dev != "" {
		s += " dev " + r.Dev
	}
	if r.Table != 0 && r.Table != MainTable {
		s += fmt.Sprintf(" table %d", r.Table)
	}
	return s
}

func (r Route) body() ([]byte, error) {
	if !r.Dst.IsValid() || !r.Dst.Addr().Is4() {
		return nil, fmt.Errorf("route %s: want an IPv4 destination", r)
	}
	if !r.Gateway.IsValid() && r.Dev == "" {
		return nil, fmt.Errorf("route %s: needs a gateway or a device", r)
	}
	table := r.Table
	if table == 0 {
		table = MainTable
	}
	hdr := make([]byte, sizeofRtmsg)
	hdr[0] = syscall.AF_INET
	hdr[1] = byte(r.Dst.Bits())
	if table < 256 {
		hdr[4] = byte(table)
	}
	hdr[5] = rtprotStatic
	hdr[6] = rtScopeUniv
	if !r.Gateway.IsValid() {
		hdr[6] = rtScopeLink
	}
	hdr[7] = rtnUnicast
	body := hdr
	if r.Dst.Bits() > 0 {
		a := r.Dst.Masked().Addr().As4()
		body = append(body, attr(rtaDst, a[:])...)
	}
	if r.Gateway.IsValid() {
		g := r.Gateway.As4()
		body = append(body, attr(rtaGateway, g[:])...)
	}
	if r.Dev != "" {
		i, err := Index(r.Dev)
		if err != nil {
			return nil, err
		}
		body = append(body, attr(rtaOif, u32(uint32(i)))...)
	}
	if r.Metric > 0 {
		body = append(body, attr(rtaPriority, u32(uint32(r.Metric)))...)
	}
	return append(body, attr(rtaTable, u32(uint32(table)))...), nil
}

// AddRoute adds a route. Adding one that is already there gives
// syscall.EEXIST.
func AddRoute(r Route) error {
	body, err := r.body()
	if err != nil {
		return err
	}
	if err := request(syscall.RTM_NEWROUTE, nlmCreateExcl, body, nil); err != nil {
		return fmt.Errorf("add route %s: %w", r, err)
	}
	return nil
}

// DelRoute deletes a route. Deleting one that isn't there gives
// syscall.ESRCH.
func DelRoute(r Route) error {
	body, err := r.body()
	if err != nil {
		return err
	}
	if err := request(syscall.RTM_DELROUTE, 0, body, nil); err != nil {
		return fmt.Errorf("delete route %s: %w", r, err)
	}
	return nil
}

// Routes lists the IPv4 unicast routes of a table (0: main).
func Routes(table int) ([]Route, error) {
	if table == 0 {
		table = MainTable
	}
	hdr := make([]byte, sizeofRtmsg)
	hdr[0] = syscall.AF_INET
	var out []Route
	var perr error
	err := request(syscall.RTM_GETROUTE, syscall.NLM_F_DUMP, hdr, func(m syscall.NetlinkMessage) {
		if m.Header.Type != syscall.RTM_NEWROUTE || len(m.Data) < sizeofRtmsg {
			return
		}
		h := m.Data[:sizeofRtmsg]
		if h[7] != rtnUnicast {
			return
		}
		at := attrs(m.Data[sizeofRtmsg:])
		t := int(h[4])
		if v, ok := at[rtaTable]; ok && len(v) == 4 {
			t = int(native.Uint32(v))
		}
		if t != table {
			return
		}
		r := Route{Table: t}
		dst := netip.IPv4Unspecified()
		if v, ok := at[rtaDst]; ok && len(v) == 4 {
			dst = netip.AddrFrom4([4]byte(v))
		}
		p, err := dst.Prefix(int(h[1]))
		if err != nil {
			perr = err
			return
		}
		r.Dst = p
		if v, ok := at[rtaGateway]; ok && len(v) == 4 {
			r.Gateway = netip.AddrFrom4([4]byte(v))
		}
		if v, ok := at[rtaOif]; ok && len(v) == 4 {
			if ifi, err := net.InterfaceByIndex(int(native.Uint32(v))); err == nil {
				r.Dev = ifi.Name
			}
		}
		if v, ok := at[rtaPriority]; ok && len(v) == 4 {
			r.Metric = int(native.Uint32(v))
		}
		out = append(out, r)
	})
	if err == nil {
		err = perr
	}
	return out, err
}

// Rule is an IPv4 policy-routing rule that sends matching packets to a
// table.
type Rule struct {
	Priority int
	Table    int
	Mark     uint32       // match packets with this firewall mark, if not 0
	Invert   bool         // match packets the rest of the rule does not match
	Dst      netip.Prefix // match packets to this range, if set
}

func (r Rule) String() string {
	s := fmt.Sprintf("%d: ", r.Priority)
	if r.Invert {
		s += "not "
	}
	if r.Mark != 0 {
		s += fmt.Sprintf("fwmark %#x ", r.Mark)
	}
	if r.Dst.IsValid() {
		s += "to " + r.Dst.String() + " "
	}
	return s + fmt.Sprintf("lookup %d", r.Table)
}

func (r Rule) body() ([]byte, error) {
	if r.Table <= 0 {
		return nil, fmt.Errorf("rule %s: needs a table", r)
	}
	hdr := make([]byte, sizeofFibHdr)
	hdr[0] = syscall.AF_INET
	if r.Table < 256 {
		hdr[4] = byte(r.Table)
	}
	hdr[7] = frActToTbl
	if r.Invert {
		native.PutUint32(hdr[8:], fibRuleInv)
	}
	body := hdr
	if r.Dst.IsValid() {
		if !r.Dst.Addr().Is4() {
			return nil, fmt.Errorf("rule %s: want an IPv4 range", r)
		}
		hdr[1] = byte(r.Dst.Bits())
		a := r.Dst.Masked().Addr().As4()
		body = append(body, attr(fraDst, a[:])...)
	}
	body = append(body, attr(fraPriority, u32(uint32(r.Priority)))...)
	if r.Mark != 0 {
		body = append(body, attr(fraFwmark, u32(r.Mark))...)
		body = append(body, attr(fraFwmask, u32(0xffffffff))...)
	}
	return append(body, attr(fraTable, u32(uint32(r.Table)))...), nil
}

// AddRule adds a rule. Adding one that is already there gives
// syscall.EEXIST.
func AddRule(r Rule) error {
	body, err := r.body()
	if err != nil {
		return err
	}
	if err := request(rtmNewRule, nlmCreateExcl, body, nil); err != nil {
		return fmt.Errorf("add rule %s: %w", r, err)
	}
	return nil
}

// DelRule deletes a rule. Deleting one that isn't there gives
// syscall.ENOENT.
func DelRule(r Rule) error {
	body, err := r.body()
	if err != nil {
		return err
	}
	if err := request(rtmDelRule, 0, body, nil); err != nil {
		return fmt.Errorf("delete rule %s: %w", r, err)
	}
	return nil
}

// Rules lists the IPv4 rules.
func Rules() ([]Rule, error) {
	hdr := make([]byte, sizeofFibHdr)
	hdr[0] = syscall.AF_INET
	var out []Rule
	err := request(rtmGetRule, syscall.NLM_F_DUMP, hdr, func(m syscall.NetlinkMessage) {
		if m.Header.Type != rtmNewRule || len(m.Data) < sizeofFibHdr {
			return
		}
		h := m.Data[:sizeofFibHdr]
		at := attrs(m.Data[sizeofFibHdr:])
		r := Rule{Table: int(h[4]), Invert: native.Uint32(h[8:])&fibRuleInv != 0}
		if v, ok := at[fraTable]; ok && len(v) == 4 {
			r.Table = int(native.Uint32(v))
		}
		if v, ok := at[fraPriority]; ok && len(v) == 4 {
			r.Priority = int(native.Uint32(v))
		}
		if v, ok := at[fraFwmark]; ok && len(v) == 4 {
			r.Mark = native.Uint32(v)
		}
		if v, ok := at[fraDst]; ok && len(v) == 4 {
			r.Dst = netip.PrefixFrom(netip.AddrFrom4([4]byte(v)), int(h[1]))
		}
		out = append(out, r)
	})
	return out, err
}

const (
	tunSetIff     = 0x400454ca // _IOW('T', 202, int)
	tunSetPersist = 0x400454cb // _IOW('T', 203, int)
	iffTun        = 0x0001
	iffNoPI       = 0x1000
)

// OpenTUN creates the TUN device name, or attaches to it if it already
// exists as a persistent device, and returns it open for packets. A
// persistent device, and its addresses and routes, outlive the process; any
// other goes away when the file is closed or the process dies.
func OpenTUN(name string, persist bool) (*os.File, error) {
	if len(name) == 0 || len(name) > 15 {
		return nil, fmt.Errorf("TUN name %q: want 1 to 15 characters", name)
	}
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	var req [40]byte
	copy(req[:15], name)
	native.PutUint16(req[16:], iffTun|iffNoPI)
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tunSetIff, uintptr(unsafe.Pointer(&req[0]))); e != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("create TUN %s: %w", name, e)
	}
	if persist {
		if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tunSetPersist, 1); e != 0 {
			syscall.Close(fd)
			return nil, fmt.Errorf("make TUN %s persistent: %w", name, e)
		}
	}
	return os.NewFile(uintptr(fd), "tun:"+name), nil
}

// DropPersist turns a persistent TUN device back into an ordinary one, so
// it goes away when f is closed.
func DropPersist(f *os.File) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var e syscall.Errno
	if err := rc.Control(func(fd uintptr) {
		_, _, e = syscall.Syscall(syscall.SYS_IOCTL, fd, tunSetPersist, 0)
	}); err != nil {
		return err
	}
	if e != 0 {
		return e
	}
	return nil
}
