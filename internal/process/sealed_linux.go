// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package process

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// SandboxArg is argv[1] of the helper that runs inside the namespace.
const SandboxArg = "__vpnw_sandbox__"

const capNetAdmin = 12

// Sealed runs the workload in a new user and network namespace.
type Sealed struct {
	dir      string
	sock     string
	l        net.Listener
	cmd      *exec.Cmd
	status   *os.File
	statusR  *bufio.Reader
	pid      int
	start    time.Time
	mu       sync.Mutex
	finalMsg map[string]any
	// Interfaces seen inside the namespace at start (should be just "lo").
	Interfaces []string
}

func (s *Sealed) Name() string   { return "sealed" }
func (s *Sealed) Enforced() bool { return true }

// Listen creates a private directory and the broker's Unix socket in it.
func (s *Sealed) Listen() (net.Listener, error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		base = os.TempDir()
	}
	dir, err := os.MkdirTemp(base, "vpnw-")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	s.dir = dir
	s.sock = filepath.Join(dir, "broker.sock")
	l, err := net.Listen("unix", s.sock)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	s.l = l
	return l, nil
}

// Start launches the helper in new namespaces; the helper starts the
// workload once loopback and the two proxy ports are up.
func (s *Sealed) Start(spec Spec) (int, error) {
	self, err := os.Executable()
	if err != nil {
		return 0, &StartError{Code: ExitInternal, Msg: "cannot find the vpnw executable: " + err.Error()}
	}
	if _, err := exec.LookPath(spec.Argv[0]); err != nil {
		return 0, lookError(spec.Argv[0], err)
	}
	httpURL := "http://127.0.0.1:" + strconv.Itoa(InnerHTTPPort)
	socksURL := "socks5h://127.0.0.1:" + strconv.Itoa(InnerSOCKSPort)
	env := proxyEnv(spec.Env, httpURL, socksURL, spec.RunID, spec.PathID)
	env = append(env, "VPNW_SANDBOX_SOCK="+s.sock)
	if spec.AllowUnix {
		env = append(env, "VPNW_SANDBOX_UNIX=allow")
	}

	r, w, err := os.Pipe()
	if err != nil {
		return 0, &StartError{Code: ExitInternal, Msg: err.Error()}
	}
	args := append([]string{SandboxArg, "--"}, spec.Argv...)
	cmd := exec.Command(self, args...)
	cmd.Env = env
	cmd.Dir, cmd.Stdin, cmd.Stdout, cmd.Stderr = spec.Dir, spec.Stdin, spec.Stdout, spec.Stderr
	cmd.ExtraFiles = []*os.File{w}
	uid, gid := os.Geteuid(), os.Getegid()
	attr := &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: uid, HostID: uid, Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: gid, HostID: gid, Size: 1}},
		GidMappingsEnableSetgroups: false,
		Pdeathsig:                  syscall.SIGKILL,
	}
	if uid != 0 {
		// The helper needs CAP_NET_ADMIN inside its own namespace for one
		// thing, bringing loopback up. It drops it before the workload starts.
		attr.AmbientCaps = []uintptr{capNetAdmin}
	}
	cmd.SysProcAttr = attr
	if err := cmd.Start(); err != nil {
		r.Close()
		w.Close()
		return 0, &StartError{Code: ExitNoEnforcement, Msg: "cannot create a network namespace: " + err.Error() + "; run `vpnw doctor`"}
	}
	w.Close()
	s.cmd, s.status, s.statusR = cmd, r, bufio.NewReader(r)
	s.start = time.Now()

	line, err := s.statusR.ReadString('\n')
	if err != nil {
		cmd.Wait()
		return 0, &StartError{Code: ExitNoEnforcement, Msg: "the sandbox helper stopped before it was ready; run `vpnw doctor`"}
	}
	var st map[string]any
	if err := json.Unmarshal([]byte(line), &st); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return 0, &StartError{Code: ExitInternal, Msg: "bad status from the sandbox helper"}
	}
	if msg, ok := st["error"].(string); ok {
		cmd.Wait()
		code := ExitNoEnforcement
		if c, ok := st["code"].(float64); ok {
			code = int(c)
		}
		return 0, &StartError{Code: code, Msg: msg}
	}
	pid, _ := st["pid"].(float64)
	s.pid = int(pid)
	if ifs, ok := st["interfaces"].([]any); ok {
		for _, x := range ifs {
			s.Interfaces = append(s.Interfaces, fmt.Sprint(x))
		}
	}
	return s.pid, nil
}

// Wait waits for the helper, which exits when the workload does.
func (s *Sealed) Wait() (Result, error) {
	var final map[string]any
	if line, err := s.statusR.ReadString('\n'); err == nil {
		json.Unmarshal([]byte(line), &final)
	}
	err := s.cmd.Wait()
	s.status.Close()
	r := Result{PID: s.pid, Started: s.start, Ended: time.Now()}
	if final != nil {
		if c, ok := final["exit"].(float64); ok {
			r.Code = int(c)
			r.Signal, _ = final["signal"].(string)
			return r, nil
		}
	}
	// The helper died without reporting: it was killed.
	r.Code, r.Signal = ExitInfo(s.cmd.ProcessState)
	if err != nil && s.cmd.ProcessState == nil {
		return r, err
	}
	return r, errors.New("the sandbox helper ended unexpectedly")
}

// Signal sends a signal straight to the workload. It shares our user, so
// the kernel allows it even across the user namespace.
func (s *Sealed) Signal(sig os.Signal) error {
	if s.pid <= 0 {
		return nil
	}
	p, err := os.FindProcess(s.pid)
	if err != nil {
		return err
	}
	return p.Signal(sig)
}

// Close removes the socket and its directory.
func (s *Sealed) Close() error {
	if s.l != nil {
		s.l.Close()
	}
	if s.dir != "" {
		return os.RemoveAll(s.dir)
	}
	return nil
}

// Check reports whether this machine can create sealed namespaces, and
// explains how to fix it when it cannot.
func Check() error {
	if b, err := os.ReadFile("/proc/sys/user/max_user_namespaces"); err == nil {
		if strings.TrimSpace(string(b)) == "0" {
			return errors.New("user namespaces are switched off (user.max_user_namespaces = 0); ask an administrator to raise it")
		}
	}
	if b, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil && os.Geteuid() != 0 {
		if strings.TrimSpace(string(b)) == "0" {
			return errors.New("unprivileged user namespaces are disabled (kernel.unprivileged_userns_clone = 0)")
		}
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	uid, gid := os.Geteuid(), os.Getegid()
	cmd := exec.Command(self, SandboxArg, "--probe")
	attr := &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: uid, HostID: uid, Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: gid, HostID: gid, Size: 1}},
		GidMappingsEnableSetgroups: false,
		Pdeathsig:                  syscall.SIGKILL,
	}
	if uid != 0 {
		attr.AmbientCaps = []uintptr{capNetAdmin}
	}
	cmd.SysProcAttr = attr
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if b, e := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"); e == nil && strings.TrimSpace(string(b)) == "1" {
			return fmt.Errorf("AppArmor restricts unprivileged user namespaces on this system (Ubuntu 23.10 and later); vpnw needs an AppArmor profile that allows \"userns\", or run it with sudo (%v %s)", err, msg)
		}
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("cannot create a sealed network namespace: %s", msg)
	}
	if !strings.Contains(string(out), "probe ok") {
		return fmt.Errorf("the sandbox probe failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}
