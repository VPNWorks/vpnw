// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package process starts a workload attached to a network path.
//
// Two backends exist in the Alpha:
//
//   - sealed (Linux): the workload runs in its own network namespace that
//     holds nothing but a loopback interface. The only listeners inside are
//     VPNW's HTTP and SOCKS5 ports, which lead to the broker outside. Traffic
//     that ignores the proxy settings has no route anywhere and fails.
//   - env: the workload runs normally with proxy settings pointing at the
//     broker. Programs that honor them are routed and traced; programs that
//     don't are not. Guard refuses to run on this backend.
package process

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// Exit codes VPNW itself uses. Any other code is the workload's own.
const (
	ExitDenied        = 120 // guard: the workload exited 0 but a connection was denied
	ExitConfig        = 121 // usage or configuration error; nothing was started
	ExitNoEnforcement = 122 // enforcement was requested but cannot be provided here
	ExitPath          = 123 // the requested path is not usable; nothing was started
	ExitInternal      = 124 // VPNW failed after start
	ExitCannotRun     = 126 // the workload could not be executed
	ExitNotFound      = 127 // the workload was not found
)

// Ports inside the sealed namespace. The namespace is private to the run,
// so fixed, conventional ports never collide with anything.
const (
	InnerHTTPPort  = 3128
	InnerSOCKSPort = 1080
)

// Spec is what to run.
type Spec struct {
	Argv   []string
	Env    []string
	Dir    string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	RunID  string
	PathID string
	// AllowUnix lets a sealed program use Unix sockets in the file system.
	// By default a seccomp filter refuses to create them.
	AllowUnix bool
}

// Result is how the workload ended.
type Result struct {
	PID     int
	Code    int
	Signal  string
	Started time.Time
	Ended   time.Time
}

// Backend attaches a workload to the broker.
type Backend interface {
	Name() string
	// Enforced reports whether traffic that ignores proxy settings is
	// blocked rather than let through.
	Enforced() bool
	// Listen returns the listener the broker must serve.
	Listen() (net.Listener, error)
	// Start launches the workload. started is called with its pid.
	Start(spec Spec) (pid int, err error)
	// Wait blocks until the workload ends.
	Wait() (Result, error)
	// Signal delivers a signal to the workload.
	Signal(sig os.Signal) error
	// Close releases what Listen created.
	Close() error
}

// StartError is a failure to launch the workload, with the exit code to use.
type StartError struct {
	Code int
	Msg  string
}

func (e *StartError) Error() string { return e.Msg }

// proxyEnv returns env with proxy settings pointing at httpURL/socksURL.
// NO_PROXY is removed so no program is told to go around the broker.
func proxyEnv(env []string, httpURL, socksURL, runID, pathID string) []string {
	drop := map[string]bool{
		"http_proxy": true, "https_proxy": true, "all_proxy": true, "no_proxy": true,
		"ftp_proxy": true, "grpc_proxy": true, "socks_proxy": true, "vpnw_run": true, "vpnw_path": true,
		"node_use_env_proxy": true,
	}
	out := make([]string, 0, len(env)+12)
	for _, kv := range env {
		k := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			k = kv[:i]
		}
		if drop[strings.ToLower(k)] || strings.HasPrefix(k, "VPNW_SANDBOX_") {
			continue
		}
		out = append(out, kv)
	}
	out = append(out,
		"HTTP_PROXY="+httpURL, "http_proxy="+httpURL,
		"HTTPS_PROXY="+httpURL, "https_proxy="+httpURL,
		"ALL_PROXY="+socksURL, "all_proxy="+socksURL,
		"NODE_USE_ENV_PROXY=1",
		"VPNW_RUN="+runID, "VPNW_PATH="+pathID,
	)
	return out
}

// ExitInfo converts a finished process state to a code and signal name.
func ExitInfo(ps *os.ProcessState) (int, string) {
	if ps == nil {
		return ExitInternal, ""
	}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal()), signalName(ws.Signal())
	}
	return ps.ExitCode(), ""
}

func signalName(s syscall.Signal) string {
	names := map[syscall.Signal]string{
		syscall.SIGHUP: "SIGHUP", syscall.SIGINT: "SIGINT", syscall.SIGQUIT: "SIGQUIT",
		syscall.SIGKILL: "SIGKILL", syscall.SIGTERM: "SIGTERM", syscall.SIGSEGV: "SIGSEGV",
		syscall.SIGABRT: "SIGABRT", syscall.SIGPIPE: "SIGPIPE", syscall.SIGUSR1: "SIGUSR1",
		syscall.SIGUSR2: "SIGUSR2",
	}
	if n, ok := names[s]; ok {
		return n
	}
	return "signal " + s.String()
}

// lookError maps exec lookup and start errors to exit codes.
func lookError(argv0 string, err error) *StartError {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "executable file not found") || os.IsNotExist(err) {
		return &StartError{Code: ExitNotFound, Msg: argv0 + ": command not found"}
	}
	if os.IsPermission(err) || strings.Contains(err.Error(), "permission denied") {
		return &StartError{Code: ExitCannotRun, Msg: argv0 + ": permission denied"}
	}
	return &StartError{Code: ExitCannotRun, Msg: argv0 + ": " + err.Error()}
}

func randomToken() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Env is the non-enforcing backend.
type Env struct {
	Token string
	l     net.Listener
	cmd   *exec.Cmd
	start time.Time
}

func (e *Env) Name() string   { return "env" }
func (e *Env) Enforced() bool { return false }

// Listen opens a loopback TCP listener protected by a per-run token.
func (e *Env) Listen() (net.Listener, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	e.l = l
	if e.Token == "" {
		e.Token = randomToken()
	}
	return l, nil
}

// Start runs the workload with proxy settings pointing at the broker.
func (e *Env) Start(spec Spec) (int, error) {
	addr := e.l.Addr().String()
	httpURL := "http://vpnw:" + e.Token + "@" + addr
	socksURL := "socks5h://vpnw:" + e.Token + "@" + addr
	path, err := exec.LookPath(spec.Argv[0])
	if err != nil {
		return 0, lookError(spec.Argv[0], err)
	}
	cmd := exec.Command(path, spec.Argv[1:]...)
	cmd.Env = proxyEnv(spec.Env, httpURL, socksURL, spec.RunID, spec.PathID)
	cmd.Dir, cmd.Stdin, cmd.Stdout, cmd.Stderr = spec.Dir, spec.Stdin, spec.Stdout, spec.Stderr
	if err := cmd.Start(); err != nil {
		return 0, lookError(spec.Argv[0], err)
	}
	e.cmd, e.start = cmd, time.Now()
	return cmd.Process.Pid, nil
}

// Wait waits for the workload.
func (e *Env) Wait() (Result, error) {
	err := e.cmd.Wait()
	r := Result{PID: e.cmd.Process.Pid, Started: e.start, Ended: time.Now()}
	r.Code, r.Signal = ExitInfo(e.cmd.ProcessState)
	if err != nil && e.cmd.ProcessState == nil {
		return r, err
	}
	return r, nil
}

// Signal forwards a signal.
func (e *Env) Signal(sig os.Signal) error {
	if e.cmd == nil || e.cmd.Process == nil {
		return nil
	}
	return e.cmd.Process.Signal(sig)
}

// Close closes the listener.
func (e *Env) Close() error {
	if e.l != nil {
		return e.l.Close()
	}
	return nil
}
