// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package testnet builds small private networks for tests: network
// namespaces held by child processes, veth pairs between them, addresses,
// routes and forwarding. It speaks rtnetlink with the standard library only.
//
// It needs root inside a user namespace (unshare --user --map-root-user
// --net) or real root. Tests that use it re-execute themselves inside such a
// namespace with Reexec, so nothing here touches the network the test was
// started in.
package testnet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
)

// ReexecEnv marks a process that already runs in its own namespaces.
const ReexecEnv = "VPNW_TESTNET_INSIDE"

// Reexec runs the current program again inside new user and network
// namespaces, with the same arguments, and exits with its status. It returns
// normally only in the re-executed process, or with an error when user
// namespaces are not available.
func Reexec() error {
	if os.Getenv(ReexecEnv) == "1" {
		return nil
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		return fmt.Errorf("unshare not found: %w", err)
	}
	if err := Available(); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := append([]string{"--user", "--map-root-user", "--net", exe}, os.Args[1:]...)
	cmd := exec.Command(unshare, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = append(os.Environ(), ReexecEnv+"=1")
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode())
		}
		return err
	}
	os.Exit(0)
	return nil
}

// Available reports whether this machine lets an unprivileged process make
// user and network namespaces, by trying it with unshare and a command that
// does nothing. A kernel or AppArmor policy that forbids them (Ubuntu 23.10
// and later restrict them by default) makes it return the reason, so tests
// can skip instead of failing.
func Available() error {
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		return fmt.Errorf("unshare not found: %w", err)
	}
	out, err := exec.Command(unshare, "--user", "--map-root-user", "--net", "true").CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("unprivileged user namespaces are not allowed here: %s", msg)
	}
	return nil
}

// NS is a network namespace. The zero-cost one, Here, is the namespace the
// process started in; the others are held open by a sleeping child.
type NS struct {
	Name   string
	holder *exec.Cmd
	stdin  io.WriteCloser
	path   string
}

// Here is the namespace this process runs in.
var Here = &NS{Name: "here"}

// NewNS starts a child process in a new network namespace and returns it.
// The child reads its standard input until it closes, so it ends with Close
// or, if the test dies, with the test.
func NewNS(name string) (*NS, error) {
	cmd := exec.Command("cat")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("namespace %s: %w", name, err)
	}
	ns := &NS{Name: name, holder: cmd, stdin: stdin, path: fmt.Sprintf("/proc/%d/ns/net", cmd.Process.Pid)}
	if err := ns.Do(func() error { return LinkUp("lo") }); err != nil {
		ns.Close()
		return nil, err
	}
	return ns, nil
}

// Close ends the namespace's holder process.
func (ns *NS) Close() {
	if ns.holder != nil && ns.holder.Process != nil {
		ns.stdin.Close()
		ns.holder.Process.Kill()
		ns.holder.Wait()
	}
}

// Do runs fn on an operating-system thread inside the namespace. Sockets
// created by fn stay in that namespace and can be used from anywhere
// afterwards. The thread is thrown away when fn returns.
func (ns *NS) Do(fn func() error) error {
	if ns.path == "" {
		return fn()
	}
	errc := make(chan error, 1)
	go func() {
		// The thread is never unlocked, so the runtime ends it with this
		// goroutine instead of reusing it in the wrong namespace.
		runtime.LockOSThread()
		fd, err := syscall.Open(ns.path, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if err != nil {
			errc <- err
			return
		}
		if sysSetns == 0 {
			syscall.Close(fd)
			errc <- errors.New("setns is not wired up on " + runtime.GOARCH)
			return
		}
		_, _, e := syscall.RawSyscall(sysSetns, uintptr(fd), syscall.CLONE_NEWNET, 0)
		syscall.Close(fd)
		if e != 0 {
			errc <- fmt.Errorf("setns %s: %w", ns.Name, e)
			return
		}
		errc <- fn()
	}()
	return <-errc
}

// Start starts cmd inside the namespace.
func (ns *NS) Start(cmd *exec.Cmd) error {
	return ns.Do(cmd.Start)
}

// Run runs cmd inside the namespace and returns its combined output.
func (ns *NS) Run(name string, args ...string) (string, error) {
	var out []byte
	err := ns.Do(func() error {
		var err error
		out, err = exec.Command(name, args...).CombinedOutput()
		return err
	})
	if err != nil {
		return string(out), fmt.Errorf("%s %s in %s: %w: %s", name, strings.Join(args, " "), ns.Name, err, out)
	}
	return string(out), nil
}

// Sysctl writes a value under /proc/sys inside the namespace, for example
// Sysctl("net/ipv4/ip_forward", "1").
func (ns *NS) Sysctl(key, value string) error {
	return ns.Do(func() error {
		return os.WriteFile("/proc/sys/"+key, []byte(value), 0)
	})
}

// --- rtnetlink ---------------------------------------------------------

const (
	iflaIfname    = 3
	iflaLinkinfo  = 18
	iflaNetNSFD   = 28
	iflaInfoKind  = 1
	iflaInfoData  = 2
	vethInfoPeer  = 1
	ifaAddress    = 1
	ifaLocal      = 2
	rtaDst        = 1
	rtaGateway    = 5
	rtTableMain   = 254
	rtprotBoot    = 3
	rtnUnicast    = 1
	sizeofIfinfo  = 16
	sizeofIfaddr  = 8
	sizeofRtmsg   = 12
	nlmsgHdrLen   = 16
	nlaHdrLen     = 4
	nlmCreateExcl = syscall.NLM_F_CREATE | syscall.NLM_F_EXCL
)

var native = binary.NativeEndian

func align4(n int) int { return (n + 3) &^ 3 }

func attr(typ uint16, data []byte) []byte {
	b := make([]byte, align4(nlaHdrLen+len(data)))
	native.PutUint16(b[0:], uint16(nlaHdrLen+len(data)))
	native.PutUint16(b[2:], typ)
	copy(b[nlaHdrLen:], data)
	return b
}

func nested(typ uint16, parts ...[]byte) []byte {
	var data []byte
	for _, p := range parts {
		data = append(data, p...)
	}
	return attr(typ, data)
}

func cstr(s string) []byte { return append([]byte(s), 0) }

func ifinfo(index int32, flags, change uint32) []byte {
	b := make([]byte, sizeofIfinfo)
	b[0] = syscall.AF_UNSPEC
	native.PutUint32(b[4:], uint32(index))
	native.PutUint32(b[8:], flags)
	native.PutUint32(b[12:], change)
	return b
}

// request sends one rtnetlink request in the calling thread's namespace and
// waits for the kernel's acknowledgement.
func request(typ, flags uint16, body []byte) error {
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
			if m.Header.Type == syscall.NLMSG_ERROR {
				if len(m.Data) < 4 {
					return errors.New("short netlink error")
				}
				if code := int32(native.Uint32(m.Data[:4])); code != 0 {
					return syscall.Errno(-code)
				}
				return nil
			}
		}
	}
}

func index(name string) (int32, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return 0, fmt.Errorf("interface %s: %w", name, err)
	}
	return int32(ifi.Index), nil
}

// AddVeth creates a veth pair a <-> b in the calling namespace.
func AddVeth(a, b string) error {
	peer := append(ifinfo(0, 0, 0), attr(iflaIfname, cstr(b))...)
	body := append(ifinfo(0, 0, 0), attr(iflaIfname, cstr(a))...)
	body = append(body, nested(iflaLinkinfo,
		attr(iflaInfoKind, []byte("veth")),
		nested(iflaInfoData, attr(vethInfoPeer, peer)),
	)...)
	if err := request(syscall.RTM_NEWLINK, nlmCreateExcl, body); err != nil {
		return fmt.Errorf("veth %s-%s: %w", a, b, err)
	}
	return nil
}

// MoveLink moves an interface from the calling namespace into ns.
func MoveLink(name string, ns *NS) error {
	i, err := index(name)
	if err != nil {
		return err
	}
	path := ns.path
	if path == "" {
		path = "/proc/self/ns/net"
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	v := make([]byte, 4)
	native.PutUint32(v, uint32(fd))
	body := append(ifinfo(i, 0, 0), attr(iflaNetNSFD, v)...)
	if err := request(syscall.RTM_NEWLINK, 0, body); err != nil {
		return fmt.Errorf("move %s to %s: %w", name, ns.Name, err)
	}
	return nil
}

func setFlags(name string, up bool) error {
	i, err := index(name)
	if err != nil {
		return err
	}
	var flags uint32
	if up {
		flags = syscall.IFF_UP
	}
	if err := request(syscall.RTM_NEWLINK, 0, ifinfo(i, flags, syscall.IFF_UP)); err != nil {
		return fmt.Errorf("set %s up=%v: %w", name, up, err)
	}
	return nil
}

// DelLink deletes an interface in the calling namespace. Deleting one end of
// a veth pair deletes both.
func DelLink(name string) error {
	i, err := index(name)
	if err != nil {
		return err
	}
	if err := request(syscall.RTM_DELLINK, 0, ifinfo(i, 0, 0)); err != nil {
		return fmt.Errorf("delete %s: %w", name, err)
	}
	return nil
}

// LinkUp brings an interface up in the calling namespace.
func LinkUp(name string) error { return setFlags(name, true) }

// LinkDown takes an interface down in the calling namespace.
func LinkDown(name string) error { return setFlags(name, false) }

// AddAddr adds an IPv4 address with its prefix, such as "10.8.0.1/24", to an
// interface in the calling namespace.
func AddAddr(name, cidr string) error {
	p, err := netip.ParsePrefix(cidr)
	if err != nil || !p.Addr().Is4() {
		return fmt.Errorf("address %q: want an IPv4 address with a prefix", cidr)
	}
	i, err := index(name)
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
	if err := request(syscall.RTM_NEWADDR, nlmCreateExcl, body); err != nil {
		return fmt.Errorf("add %s to %s: %w", cidr, name, err)
	}
	return nil
}

// AddRoute adds an IPv4 route in the calling namespace. dst is a prefix such
// as "10.0.0.0/16", or "default".
func AddRoute(dst, via string) error {
	p := netip.MustParsePrefix("0.0.0.0/0")
	if dst != "default" {
		var err error
		if p, err = netip.ParsePrefix(dst); err != nil {
			return err
		}
	}
	gw, err := netip.ParseAddr(via)
	if err != nil || !gw.Is4() {
		return fmt.Errorf("gateway %q: want an IPv4 address", via)
	}
	hdr := make([]byte, sizeofRtmsg)
	hdr[0] = syscall.AF_INET
	hdr[1] = byte(p.Bits())
	hdr[4] = rtTableMain
	hdr[5] = rtprotBoot
	hdr[6] = 0 // RT_SCOPE_UNIVERSE
	hdr[7] = rtnUnicast
	var body []byte
	body = append(body, hdr...)
	if p.Bits() > 0 {
		a := p.Addr().As4()
		body = append(body, attr(rtaDst, a[:])...)
	}
	g := gw.As4()
	body = append(body, attr(rtaGateway, g[:])...)
	if err := request(syscall.RTM_NEWROUTE, nlmCreateExcl, body); err != nil {
		return fmt.Errorf("route %s via %s: %w", dst, via, err)
	}
	return nil
}
