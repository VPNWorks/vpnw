// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package process

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	prCapAmbient         = 47
	prCapAmbientClearAll = 4
)

// SandboxMain is the helper's entry point, inside the new namespaces.
// args are os.Args[2:]. It returns the process exit code.
func SandboxMain(args []string) int {
	if len(args) == 1 && args[0] == "--probe" {
		if err := loopbackUp(); err != nil {
			fmt.Fprintln(os.Stderr, "cannot bring loopback up:", err)
			return ExitNoEnforcement
		}
		ifs, _ := interfaces()
		l, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(InnerHTTPPort))
		if err != nil {
			fmt.Fprintln(os.Stderr, "cannot listen inside the namespace:", err)
			return ExitNoEnforcement
		}
		l.Close()
		fmt.Printf("probe ok: interfaces %s\n", strings.Join(ifs, ","))
		return 0
	}
	status := os.NewFile(3, "vpnw-status")
	report := func(v map[string]any) {
		if status == nil {
			return
		}
		b, _ := json.Marshal(v)
		status.Write(append(b, '\n'))
	}
	if len(args) < 2 || args[0] != "--" {
		report(map[string]any{"error": "sandbox helper started without a command", "code": ExitInternal})
		return ExitInternal
	}
	argv := args[1:]
	sock := os.Getenv("VPNW_SANDBOX_SOCK")
	if sock == "" {
		report(map[string]any{"error": "sandbox helper has no broker socket", "code": ExitInternal})
		return ExitInternal
	}
	if err := loopbackUp(); err != nil {
		report(map[string]any{"error": "cannot bring loopback up in the sandbox: " + err.Error(), "code": ExitNoEnforcement})
		return ExitNoEnforcement
	}
	ifs, err := interfaces()
	if err != nil || !InterfacesOK(ifs) {
		report(map[string]any{"error": fmt.Sprintf("the sandbox has unexpected interfaces %v; refusing to run", ifs), "code": ExitNoEnforcement})
		return ExitNoEnforcement
	}
	var ls []net.Listener
	for _, port := range []int{InnerHTTPPort, InnerSOCKSPort} {
		l, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			report(map[string]any{"error": "cannot listen inside the sandbox: " + err.Error(), "code": ExitNoEnforcement})
			return ExitNoEnforcement
		}
		ls = append(ls, l)
		go bridge(l, sock)
	}
	// The workload gets no capabilities from us. The thread that starts it
	// is the one whose capabilities it inherits, so this goroutine stays on
	// one thread from here until the workload has started.
	runtime.LockOSThread()
	if os.Geteuid() != 0 {
		if err := dropCapabilities(); err != nil {
			report(map[string]any{"error": "cannot drop capabilities: " + err.Error(), "code": ExitInternal})
			return ExitInternal
		}
	}
	if os.Getenv("VPNW_SANDBOX_UNIX") != "allow" {
		if err := denyUnixSockets(); err != nil {
			report(map[string]any{"error": err.Error(), "code": ExitNoEnforcement})
			return ExitNoEnforcement
		}
	}
	env := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "VPNW_SANDBOX_") {
			env = append(env, kv)
		}
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		se := lookError(argv[0], err)
		report(map[string]any{"error": se.Msg, "code": se.Code})
		return se.Code
	}
	cmd := exec.Command(path, argv[1:]...)
	cmd.Args[0] = argv[0]
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	// Signals are delivered to the workload by the vpnw parent or by the
	// terminal; the helper only has to outlive the workload.
	sigs := make(chan os.Signal, 16)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		for range sigs {
		}
	}()
	if err := cmd.Start(); err != nil {
		se := lookError(argv[0], err)
		report(map[string]any{"error": se.Msg, "code": se.Code})
		return se.Code
	}
	report(map[string]any{"ready": true, "pid": cmd.Process.Pid, "interfaces": ifs})
	cmd.Wait()
	code, sig := ExitInfo(cmd.ProcessState)
	report(map[string]any{"exit": code, "signal": sig})
	for _, l := range ls {
		l.Close()
	}
	return code
}

type capHeader struct {
	version uint32
	pid     int32
}

type capData struct {
	effective, permitted, inheritable uint32
}

const linuxCapabilityVersion3 = 0x20080522

// dropCapabilities clears the ambient and inheritable capability sets, which
// are the ones a program keeps across exec. The helper raised CAP_NET_ADMIN
// only to bring loopback up. It clears every thread when the Go runtime
// allows it (builds without cgo), and always the current thread, the one
// that starts the workload, so the result holds in every build.
func dropCapabilities() error {
	if _, _, e := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, prCapAmbient, prCapAmbientClearAll, 0); e != 0 && e != syscall.ENOTSUP {
		return e
	}
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prCapAmbient, prCapAmbientClearAll, 0); e != 0 {
		return e
	}
	hdr := capHeader{version: linuxCapabilityVersion3}
	var data [2]capData
	if _, _, e := syscall.RawSyscall(syscall.SYS_CAPGET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		return e
	}
	data[0].inheritable, data[1].inheritable = 0, 0
	if _, _, e := syscall.RawSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		return e
	}
	return nil
}

// bridge carries each connection made inside the namespace to the broker's
// Unix socket outside it. Unix sockets live in the file system, not in a
// network namespace, which is what makes this door possible.
func bridge(l net.Listener, sock string) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			u, err := net.Dial("unix", sock)
			if err != nil {
				return
			}
			defer u.Close()
			done := make(chan struct{}, 2)
			go func() { io.Copy(u, c); u.(*net.UnixConn).CloseWrite(); done <- struct{}{} }()
			go func() { io.Copy(c, u); c.(*net.TCPConn).CloseWrite(); done <- struct{}{} }()
			<-done
			<-done
		}(c)
	}
}

// loopbackUp sets IFF_UP on lo, the one interface a new namespace has.
func loopbackUp() error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var ifr [40]byte
	copy(ifr[:], "lo")
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifr[0]))); e != 0 {
		return e
	}
	flags := (*uint16)(unsafe.Pointer(&ifr[16]))
	*flags |= syscall.IFF_UP | syscall.IFF_RUNNING
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr[0]))); e != 0 {
		return e
	}
	return nil
}

// interfaces lists network interfaces visible to this process.
func interfaces() ([]string, error) {
	b, err := os.ReadFile("/proc/self/net/dev")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n")[2:] {
		if i := strings.IndexByte(line, ':'); i > 0 {
			out = append(out, strings.TrimSpace(line[:i]))
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no interfaces")
	}
	return out, nil
}
