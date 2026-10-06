// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package record reads new connections from a Linux VPN gateway's firewall.
//
// The gateway's nftables ruleset sends the first packet of every new
// connection from the VPN range to an NFLOG group, before any filtering, so
// attempts that are later rejected are recorded too. Record listens on that
// group over netfilter netlink and turns each packet header into a flow:
// time, protocol, source, destination and destination port. It keeps no
// payload.
package record

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"vpnw.com/vpnw/internal/scope"
)

const (
	netlinkNetfilter   = 12
	nfnlSubsysULOG     = 4
	nfulnlMsgPacket    = 0
	nfulnlMsgConfig    = 1
	nfulaCfgCmd        = 1
	nfulaCfgMode       = 2
	nfulaCfgTimeout    = 4
	nfulaCfgQthresh    = 5
	nfulnlCfgCmdBind   = 1
	nfulnlCfgCmdUnbind = 2
	nfulnlCopyPacket   = 2
	nfulaPayload       = 9
	nlaTypeMask        = 0x3fff
	copyRange          = 64 // IPv4 header with options, plus the ports
)

// TableName is the nftables table Record adds to the gateway and removes when
// it stops.
const TableName = "vpnw_scope_record"

// Rules returns the nftables script that sends new connections from vpnNet
// to NFLOG group group. It runs at priority -10, before the usual filter
// chains, so rejected attempts are logged as well.
func Rules(vpnNet netip.Prefix, group uint16) string {
	return fmt.Sprintf(`table inet %[1]s
delete table inet %[1]s
table inet %[1]s {
	chain forward {
		type filter hook forward priority -10; policy accept;
		ip saddr %[2]s ct state new meta l4proto { tcp, udp } log group %[3]d
	}
}
`, TableName, vpnNet, group)
}

// Install loads Rules into the running kernel with nft.
func Install(vpnNet netip.Prefix, group uint16) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(Rules(vpnNet, group))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Remove deletes the recording table.
func Remove() error {
	out, err := exec.Command("nft", "delete", "table", "inet", TableName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Listener receives flows from one NFLOG group.
type Listener struct {
	fd    int
	group uint16
	buf   []byte
	// Skipped counts packets that could not become a flow: IPv6, fragments,
	// truncated headers or other protocols.
	Skipped int
}

// Listen binds to NFLOG group group in the calling thread's network
// namespace.
func Listen(group uint16) (*Listener, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, netlinkNetfilter)
	if err != nil {
		return nil, fmt.Errorf("netfilter netlink: %w", err)
	}
	l := &Listener{fd: fd, group: group, buf: make([]byte, 1<<18)}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		l.Close()
		return nil, err
	}
	// A larger receive buffer keeps bursts from being dropped.
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4<<20)
	if err := l.config(attr(nfulaCfgCmd, []byte{nfulnlCfgCmdBind})); err != nil {
		l.Close()
		return nil, fmt.Errorf("bind NFLOG group %d: %w", group, err)
	}
	mode := make([]byte, 6)
	binary.BigEndian.PutUint32(mode, copyRange)
	mode[4] = nfulnlCopyPacket
	if err := l.config(attr(nfulaCfgMode, mode)); err != nil {
		l.Close()
		return nil, fmt.Errorf("NFLOG copy mode: %w", err)
	}
	// Deliver each packet at once instead of batching for up to a second.
	one := make([]byte, 4)
	binary.BigEndian.PutUint32(one, 1)
	if err := l.config(append(attr(nfulaCfgQthresh, one), attr(nfulaCfgTimeout, one)...)); err != nil {
		l.Close()
		return nil, fmt.Errorf("NFLOG timing: %w", err)
	}
	return l, nil
}

// Close unbinds from the group and closes the socket.
func (l *Listener) Close() error {
	if l.fd < 0 {
		return nil
	}
	l.config(attr(nfulaCfgCmd, []byte{nfulnlCfgCmdUnbind}))
	err := syscall.Close(l.fd)
	l.fd = -1
	return err
}

// SetDeadline makes Read return with no flows once t has passed.
func (l *Listener) SetDeadline(t time.Time) error {
	d := time.Until(t)
	if d <= 0 {
		d = time.Microsecond
	}
	tv := syscall.NsecToTimeval(d.Nanoseconds())
	return syscall.SetsockoptTimeval(l.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
}

// Read waits for the next batch of packets and returns their flows. It
// returns an empty slice and no error when the deadline passes.
func (l *Listener) Read() ([]scope.Flow, error) {
	n, _, err := syscall.Recvfrom(l.fd, l.buf, 0)
	now := time.Now().UTC()
	if err != nil {
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
			return nil, nil
		}
		if errors.Is(err, syscall.ENOBUFS) {
			return nil, fmt.Errorf("the kernel dropped log messages; the receive buffer overflowed")
		}
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(l.buf[:n])
	if err != nil {
		return nil, err
	}
	var out []scope.Flow
	for _, m := range msgs {
		if m.Header.Type != nfnlSubsysULOG<<8|nfulnlMsgPacket || len(m.Data) < 4 {
			continue
		}
		payload := findAttr(m.Data[4:], nfulaPayload)
		f, ok := ParsePacket(payload)
		if !ok {
			l.Skipped++
			continue
		}
		f.Time = now
		out = append(out, f)
	}
	return out, nil
}

// ParsePacket reads protocol, addresses and destination port from an IPv4
// packet that starts at its IP header. It reports false for anything else.
func ParsePacket(b []byte) (scope.Flow, bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return scope.Flow{}, false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl+4 {
		return scope.Flow{}, false
	}
	if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
		return scope.Flow{}, false // a later fragment: no transport header
	}
	var proto scope.Proto
	switch b[9] {
	case syscall.IPPROTO_TCP:
		proto = scope.TCP
	case syscall.IPPROTO_UDP:
		proto = scope.UDP
	default:
		return scope.Flow{}, false
	}
	return scope.Flow{
		Proto: proto,
		Src:   netip.AddrFrom4([4]byte(b[12:16])),
		Dst:   netip.AddrFrom4([4]byte(b[16:20])),
		Port:  binary.BigEndian.Uint16(b[ihl+2 : ihl+4]),
	}, true
}

func (l *Listener) config(attrs []byte) error {
	body := make([]byte, 4, 4+len(attrs))
	body[0] = syscall.AF_UNSPEC
	binary.BigEndian.PutUint16(body[2:], l.group)
	body = append(body, attrs...)
	msg := make([]byte, syscall.NLMSG_HDRLEN+len(body))
	binary.NativeEndian.PutUint32(msg[0:], uint32(len(msg)))
	binary.NativeEndian.PutUint16(msg[4:], nfnlSubsysULOG<<8|nfulnlMsgConfig)
	binary.NativeEndian.PutUint16(msg[6:], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK)
	binary.NativeEndian.PutUint32(msg[8:], 1)
	copy(msg[syscall.NLMSG_HDRLEN:], body)
	if err := syscall.Sendto(l.fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	for {
		n, _, err := syscall.Recvfrom(l.fd, buf, 0)
		if err != nil {
			return err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if m.Header.Type == syscall.NLMSG_ERROR && len(m.Data) >= 4 {
				if code := int32(binary.NativeEndian.Uint32(m.Data[:4])); code != 0 {
					return syscall.Errno(-code)
				}
				return nil
			}
		}
	}
}

func attr(typ uint16, data []byte) []byte {
	n := 4 + len(data)
	b := make([]byte, (n+3)&^3)
	binary.NativeEndian.PutUint16(b[0:], uint16(n))
	binary.NativeEndian.PutUint16(b[2:], typ)
	copy(b[4:], data)
	return b
}

func findAttr(b []byte, typ uint16) []byte {
	for len(b) >= 4 {
		n := int(binary.NativeEndian.Uint16(b[0:2]))
		t := binary.NativeEndian.Uint16(b[2:4]) & nlaTypeMask
		if n < 4 || n > len(b) {
			return nil
		}
		if t == typ {
			return b[4:n]
		}
		next := (n + 3) &^ 3
		if next > len(b) {
			return nil
		}
		b = b[next:]
	}
	return nil
}
