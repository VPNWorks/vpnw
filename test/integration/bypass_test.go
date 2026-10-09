// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package integration runs the built vpnw binary end to end on Linux and
// checks the enforcement boundary from the inside: a workload in the sealed
// namespace must reach the network only through the broker, and every entry
// in the bypass matrix must be blocked or routed, never leaked.
package integration

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

var vpnw string

func TestMain(m *testing.M) {
	if runtime.GOOS != "linux" {
		fmt.Println("integration tests need Linux")
		os.Exit(0)
	}
	dir, _ := os.MkdirTemp("", "vpnw-it-")
	vpnw = filepath.Join(dir, "vpnw")
	args := []string{"build", "-o", vpnw}
	if os.Getenv("GOCOVERDIR") != "" {
		// tools/measure.sh: count what the real binary runs in these tests.
		args = append(args, "-cover", "-coverpkg=github.com/VPNWorks/vpnw/...")
	}
	build := exec.Command("go", append(args, "github.com/VPNWorks/vpnw/cmd/vpnw")...)
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Println("build failed:", err)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// server is a plain TCP listener that records how many connections it got.
type server struct {
	ln   net.Listener
	port int
	hits chan string
}

func newServer(t *testing.T) *server { return newServerAt(t, "tcp", "127.0.0.1:0") }

func newServerAt(t *testing.T, network, addr string) *server {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	s := &server{ln: ln, port: ln.Addr().(*net.TCPAddr).Port, hits: make(chan string, 64)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				line, _ := br.ReadString('\n')
				s.hits <- line
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nhi\n")
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

// abstractServer listens on an abstract Unix socket in this test's network
// namespace. Abstract sockets belong to a network namespace, so a sealed
// workload must not be able to reach it.
type abstractServer struct {
	name string
	hits chan struct{}
}

func newAbstractServer(t *testing.T) *abstractServer {
	t.Helper()
	name := fmt.Sprintf("vpnw-bypass-%d", os.Getpid())
	ln, err := net.Listen("unix", "@"+name)
	if err != nil {
		t.Fatal(err)
	}
	a := &abstractServer{name: name, hits: make(chan struct{}, 64)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			a.hits <- struct{}{}
			c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return a
}

func (a *abstractServer) count() int { return len(a.hits) }

// unixServer listens on a Unix socket in the file system.
type unixServer struct {
	path string
	hits chan struct{}
}

func newUnixServer(t *testing.T) *unixServer {
	t.Helper()
	dir, err := os.MkdirTemp("", "vpnw-unix-")
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0o755)
	u := &unixServer{path: filepath.Join(dir, "s.sock"), hits: make(chan struct{}, 64)}
	ln, err := net.Listen("unix", u.path)
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(u.path, 0o777)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			u.hits <- struct{}{}
			c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close(); os.RemoveAll(dir) })
	return u
}

func (u *unixServer) count() int { return len(u.hits) }

func newServerAll(t *testing.T) *server {
	t.Helper()
	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &server{ln: ln, port: ln.Addr().(*net.TCPAddr).Port, hits: make(chan string, 64)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.hits <- "conn"
			c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

type udpServer struct {
	port int
	hits chan struct{}
}

func newUDPServer(t *testing.T) *udpServer {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	u := &udpServer{port: pc.LocalAddr().(*net.UDPAddr).Port, hits: make(chan struct{}, 64)}
	go func() {
		buf := make([]byte, 64)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			u.hits <- struct{}{}
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return u
}

func (u *udpServer) count() int { return len(u.hits) }

func (s *server) count() int { return len(s.hits) }

// run runs vpnw with a small python probe as the workload and returns its
// combined output and the trace it wrote.
func runProbe(t *testing.T, args []string, probe string) (string, []map[string]any) {
	t.Helper()
	trace := filepath.Join(t.TempDir(), "t.jsonl")
	full := append([]string{}, args...)
	full = append(full, "--no-save", "--out", trace, "--", "python3", "-c", probe)
	cmd := exec.Command(vpnw, full...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	out, _ := cmd.CombinedOutput()
	var evs []map[string]any
	if b, err := os.ReadFile(trace); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if line == "" {
				continue
			}
			var e map[string]any
			if json.Unmarshal([]byte(line), &e) == nil {
				evs = append(evs, e)
			}
		}
	}
	return string(out), evs
}

// skipIfNoSeal skips a test that needs the sealed backend where this
// machine can't provide it. CI sets VPNW_REQUIRE_SEAL=1 on Linux, so there
// a missing backend fails the run instead of passing it quietly.
func skipIfNoSeal(t *testing.T) {
	t.Helper()
	out, err := exec.Command(vpnw, "doctor").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "sealed backend   ok") {
		if os.Getenv("VPNW_REQUIRE_SEAL") == "1" {
			t.Fatal("VPNW_REQUIRE_SEAL=1 but the sealed backend is not available:\n" + string(out))
		}
		t.Skip("sealed backend not available here:\n" + string(out))
	}
}

// The bypass matrix. Each row is one way a workload could try to reach the
// network on its own. A row passes only if the attempt fails inside the
// sandbox with the error that proves there is no way out (no route, or
// nothing listening in the sandbox's own loopback) and, where this machine
// has a listener, that listener saw nothing. Rows whose target is on this
// machine also run once outside the sandbox as a control: the same probe
// must succeed there, which shows the probe itself works.
//
// Set VPNW_MATRIX_OUT to a file name to get the results as a Markdown table.
func TestBypassMatrix(t *testing.T) {
	skipIfNoSeal(t)
	hostIP := hostAddress(t)
	tcp := newServer(t)       // 127.0.0.1
	tcpAll := newServerAll(t) // 0.0.0.0, reached at this machine's own address
	udp := newUDPServer(t)    // 0.0.0.0, UDP
	abstract := newAbstractServer(t)
	unixFS := newUnixServer(t)
	v6 := ipv6Available()
	if !v6 && os.Getenv("VPNW_REQUIRE_IPV6") == "1" {
		t.Fatal("VPNW_REQUIRE_IPV6=1 but this machine's kernel has no IPv6")
	}
	var tcp6 *server // [::1], for the IPv6 loopback row and its control
	if v6 {
		tcp6 = newServerAt(t, "tcp6", "[::1]:0")
	}
	const (
		enetunreach  = "101"
		econnrefused = "111"
	)
	type row struct {
		name, probe string
		want        []string // acceptable failure codes inside the sandbox
		control     bool     // must succeed outside the sandbox
		soft        bool     // control is informational only
		skip        string   // reason to skip on this machine
		hits        func() int
	}
	rows := []row{
		{name: "IPv4 TCP to this machine's loopback (127.0.0.1)", probe: pyConnect("127.0.0.1", tcp.port), want: []string{econnrefused}, control: true, hits: tcp.count},
		{name: "IPv4 TCP to this machine's own address (" + hostIP + ")", probe: pyConnect(hostIP, tcpAll.port), want: []string{enetunreach}, control: true, hits: tcpAll.count},
		{name: "IPv4 TCP to a public address (1.1.1.1:443)", probe: pyConnect("1.1.1.1", 443), want: []string{enetunreach}, control: true, soft: true},
		{name: "IPv4 TCP to a private address (10.0.0.1:80)", probe: pyConnect("10.0.0.1", 80), want: []string{enetunreach}},
		{name: "IPv4 TCP to cloud metadata (169.254.169.254:80)", probe: pyConnect("169.254.169.254", 80), want: []string{enetunreach}},
		{name: "UDP to this machine's own address", probe: pyUDP(hostIP, udp.port), want: []string{enetunreach}, control: true, hits: udp.count},
		{name: "UDP to a public DNS resolver (8.8.8.8:53)", probe: pyUDP("8.8.8.8", 53), want: []string{enetunreach}},
		{name: "DNS lookup through the system resolver", probe: "import socket; socket.getaddrinfo('example.com', 443)", want: []string{"gaierror"}},
		{name: "Raw IP socket (ICMP echo to 1.1.1.1)", probe: "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP); s.sendto(b'\\x08\\x00\\xf7\\xff\\x00\\x00\\x00\\x00',('1.1.1.1',0))", want: []string{enetunreach, "1"}},
		{name: "A child process connecting on its own", probe: pyChild(pyConnect(hostIP, tcpAll.port)), want: []string{enetunreach}, hits: tcpAll.count},
		{name: "Abstract Unix socket (@vpnw-bypass)", probe: fmt.Sprintf("import socket; s=socket.socket(socket.AF_UNIX); s.settimeout(2); s.connect('\\0%s')", abstract.name), want: []string{"1", econnrefused}, control: true, hits: abstract.count},
		{name: "Unix socket in the file system (like the Docker socket)", probe: fmt.Sprintf("s=socket.socket(socket.AF_UNIX); s.settimeout(2); s.connect(%q)", unixFS.path), want: []string{"1"}, control: true, hits: unixFS.count},
		{name: "io_uring, which can create sockets without socket()", probe: "import ctypes, os\nl=ctypes.CDLL(None, use_errno=True)\nr=l.syscall(425, 1, ctypes.create_string_buffer(120))\nif r < 0: raise OSError(ctypes.get_errno(), 'io_uring_setup')", want: []string{"1"}, control: true, soft: true},
		{name: "IPv6 TCP to this machine's loopback (::1)", want: []string{econnrefused, enetunreach, "99"}, control: true},
		{name: "IPv6 TCP to a public address (2606:4700:4700::1111)", probe: pyConnect("2606:4700:4700::1111", 443), want: []string{enetunreach, "99"}, control: true, soft: true},
	}
	for i := range rows {
		if !strings.HasPrefix(rows[i].name, "IPv6") {
			continue
		}
		switch {
		case !v6:
			rows[i].skip = "this machine's kernel has no IPv6"
		case rows[i].probe == "": // the loopback row, aimed at the [::1] listener
			rows[i].probe, rows[i].hits = pyConnect("::1", tcp6.port), tcp6.count
		}
	}
	if runtime.GOARCH == "amd64" {
		rows = append(rows, row{name: "An x32 system call (a second system call table)", probe: "import ctypes\nl=ctypes.CDLL(None, use_errno=True)\nr=l.syscall(0x40000000 | 41, 1, 1, 0)\nif r < 0: raise OSError(ctypes.get_errno(), 'x32 socket')", want: []string{"1"}})
	}
	if _, err := exec.LookPath("ping"); err == nil {
		rows = append(rows, row{name: "ping (ICMP) to 1.1.1.1", probe: "import subprocess,sys; r=subprocess.run(['ping','-c1','-W1','1.1.1.1'],capture_output=True); sys.exit(0) if r.returncode==0 else (_ for _ in ()).throw(OSError(101,'ping failed'))", want: []string{enetunreach}})
	}

	var md strings.Builder
	md.WriteString("| Way out | Inside the sandbox | Outside (control) | Result |\n|---|---|---|---|\n")
	for _, r := range rows {
		r := r
		t.Run(r.name, func(t *testing.T) {
			if r.skip != "" {
				fmt.Fprintf(&md, "| %s | not run | not run | skipped: %s |\n", r.name, r.skip)
				t.Skip(r.skip)
			}
			before := 0
			if r.hits != nil {
				before = r.hits()
			}
			out, _ := runProbe(t, []string{"trace", "--backend", "sealed"}, wrap(r.probe))
			got := probeResult(out)
			leaked := 0
			if r.hits != nil {
				leaked = r.hits() - before
			}
			ok := !strings.HasPrefix(got, "ok") && leaked == 0 && matchesAny(got, r.want)
			ctl := "not needed"
			if r.control {
				cout, _ := exec.Command("python3", "-c", wrap(r.probe)).CombinedOutput()
				c := probeResult(string(cout))
				if strings.HasPrefix(c, "ok") {
					ctl = "reached"
				} else {
					ctl = "failed (" + c + ")"
					if !r.soft {
						t.Errorf("control probe failed outside the sandbox, so its result inside proves nothing: %s", c)
						ok = false
					}
				}
			}
			res := "blocked"
			if !ok {
				res = "NOT BLOCKED"
				t.Errorf("%s: inside the sandbox got %q (listener saw %d), want one of %v\n%s", r.name, got, leaked, r.want, out)
			}
			fmt.Fprintf(&md, "| %s | %s | %s | %s |\n", r.name, describe(got), ctl, res)
		})
	}
	if fn := os.Getenv("VPNW_MATRIX_OUT"); fn != "" {
		os.WriteFile(fn, []byte(md.String()), 0o644)
	}
}

// wrap turns a probe into a script that prints one RESULT line: "ok" if the
// network action worked, or the error class and code if it failed.
func wrap(body string) string {
	return "import sys, socket, subprocess\ntry:\n" +
		indent(body) +
		"\n    print('RESULT ok')\n" +
		"except socket.gaierror as e:\n    print('RESULT gaierror', e.errno)\n" +
		"except OSError as e:\n    print('RESULT', e.errno, type(e).__name__)\n" +
		"except Exception as e:\n    print('RESULT other', type(e).__name__, e)\n"
}

func probeResult(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "RESULT ") {
			return strings.TrimPrefix(line, "RESULT ")
		}
	}
	return "no result"
}

func matchesAny(got string, want []string) bool {
	for _, w := range want {
		if strings.HasPrefix(got, w+" ") || got == w {
			return true
		}
	}
	return false
}

func describe(got string) string {
	switch {
	case strings.HasPrefix(got, "101 "):
		return "no route (ENETUNREACH)"
	case strings.HasPrefix(got, "111 "):
		return "nothing listening in the sandbox (ECONNREFUSED)"
	case strings.HasPrefix(got, "gaierror"):
		return "name lookup failed"
	case strings.HasPrefix(got, "1 "):
		return "not permitted (EPERM)"
	case strings.HasPrefix(got, "99 "):
		return "no such address (EADDRNOTAVAIL)"
	}
	return got
}

func indent(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = "    " + l
	}
	return strings.Join(lines, "\n")
}

func pyConnect(host string, port int) string {
	fam := "socket.AF_INET"
	if strings.Contains(host, ":") {
		fam = "socket.AF_INET6"
	}
	return fmt.Sprintf("s=socket.socket(%s, socket.SOCK_STREAM); s.settimeout(3); s.connect((%q,%d))", fam, host, port)
}

func pyUDP(host string, port int) string {
	return fmt.Sprintf("s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); s.connect((%q,%d)); s.send(b'vpnw-probe')", host, port)
}

// pyChild runs a probe in a child process and re-raises its failure code.
func pyChild(probe string) string {
	script := wrap(probe)
	return fmt.Sprintf("r=subprocess.run([sys.executable,'-c',%q],capture_output=True,text=True)\n"+
		"line=[l for l in r.stdout.splitlines() if l.startswith('RESULT ')]\n"+
		"code=line[0].split()[1] if line else 'none'\n"+
		"if code!='ok': raise OSError(int(code) if code.isdigit() else -1, 'child: '+code)", script)
}

// hostAddress returns this machine's own non-loopback IPv4 address.
func hostAddress(t *testing.T) string {
	t.Helper()
	c, err := net.Dial("udp4", "192.0.2.123:9") // no packet is sent
	if err == nil {
		defer c.Close()
		if a, ok := c.LocalAddr().(*net.UDPAddr); ok && !a.IP.IsLoopback() {
			return a.IP.String()
		}
	}
	ifs, _ := net.InterfaceAddrs()
	for _, a := range ifs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
			return n.IP.String()
		}
	}
	t.Skip("this machine has no non-loopback IPv4 address to test against")
	return ""
}

func ipv6Available() bool {
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		return false
	}
	l.Close()
	return true
}

// With the broker in front, the same workload reaches only what the proxy
// settings point at, and the trace shows it.
func TestSealedRoutesThroughBroker(t *testing.T) {
	skipIfNoSeal(t)
	srv := newServer(t)
	probe := fmt.Sprintf("import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:%d/', timeout=3).read())", srv.port)
	out, evs := runProbe(t, []string{"trace", "--backend", "sealed"}, probe)
	if srv.count() == 0 {
		t.Fatalf("the server saw no connection through the broker:\n%s", out)
	}
	var opened bool
	for _, e := range evs {
		if e["type"] == "connection.open" {
			opened = true
		}
	}
	if !opened {
		t.Errorf("no connection.open event:\n%s", out)
	}
}

// A denied destination fails inside the sandbox, and guard reports it and
// turns a zero exit into 120.
func TestGuardDeniesAndExit(t *testing.T) {
	skipIfNoSeal(t)
	blocked := newServer(t)
	allowed := newServer(t)
	// The workload exits 0, but one connection was denied.
	probe := fmt.Sprintf(
		"import urllib.request as u\n"+
			"u.urlopen('http://127.0.0.1:%d/',timeout=3)\n"+
			"try:\n u.urlopen('http://127.0.0.1:%d/',timeout=3)\nexcept Exception: pass\n",
		allowed.port, blocked.port)
	trace := filepath.Join(t.TempDir(), "t.jsonl")
	cmd := exec.Command(vpnw, "guard", "--backend", "sealed", "--no-save", "--out", trace,
		"--allow", fmt.Sprintf("127.0.0.1:%d", allowed.port), "--",
		"python3", "-c", probe)
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	out, _ := cmd.CombinedOutput()
	code := cmd.ProcessState.ExitCode()
	if code != 120 {
		t.Errorf("exit code %d, want 120 (a denial with a zero workload exit)\n%s", code, out)
	}
	if allowed.count() != 1 {
		t.Error("the allowed server should have been reached once")
	}
	if blocked.count() != 0 {
		t.Error("the blocked server was reached; policy did not hold")
	}
	if !strings.Contains(string(out), "DENY") {
		t.Errorf("no denial reported:\n%s", out)
	}
}

// A run whose exit code must be preserved for scripts.
func TestExitCodePreserved(t *testing.T) {
	skipIfNoSeal(t)
	cmd := exec.Command(vpnw, "run", "--backend", "sealed", "--no-save", "--", "sh", "-c", "exit 7")
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	cmd.Run()
	if cmd.ProcessState.ExitCode() != 7 {
		t.Errorf("exit code %d, want 7", cmd.ProcessState.ExitCode())
	}
}

func TestUnknownCommand(t *testing.T) {
	cmd := exec.Command(vpnw, "run", "--backend", "env", "--no-save", "--", "definitely-not-a-real-command-xyz")
	out, _ := cmd.CombinedOutput()
	if cmd.ProcessState.ExitCode() != 127 {
		t.Errorf("exit %d, want 127: %s", cmd.ProcessState.ExitCode(), out)
	}
}

func TestStdinPassthrough(t *testing.T) {
	skipIfNoSeal(t)
	cmd := exec.Command(vpnw, "run", "--backend", "sealed", "--no-save", "--", "cat")
	cmd.Stdin = strings.NewReader("round trip\n")
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	out, err := cmd.Output()
	if err != nil || string(out) != "round trip\n" {
		t.Errorf("stdin/stdout not wired: %q %v", out, err)
	}
}

// --allow-unix-sockets lifts the Unix-socket filter, for programs that
// need one (an SSH agent, say). The network stays sealed.
func TestAllowUnixSocketsFlag(t *testing.T) {
	skipIfNoSeal(t)
	srv := newUnixServer(t)
	probe := fmt.Sprintf("s=socket.socket(socket.AF_UNIX); s.settimeout(2); s.connect(%q)", srv.path)
	out, _ := runProbe(t, []string{"trace", "--backend", "sealed", "--allow-unix-sockets"}, wrap(probe))
	if probeResult(out) != "ok" || srv.count() == 0 {
		t.Errorf("with --allow-unix-sockets the program should reach the socket:\n%s", out)
	}
	out, _ = runProbe(t, []string{"trace", "--backend", "sealed", "--allow-unix-sockets"}, wrap(pyConnect("1.1.1.1", 443)))
	if !strings.HasPrefix(probeResult(out), "101 ") {
		t.Errorf("the network must stay sealed with --allow-unix-sockets:\n%s", out)
	}
}

// The filter leaves socketpair alone, which programs use to talk to their
// own children, and plain TCP through vpnw keeps working.
func TestSocketpairStillWorks(t *testing.T) {
	skipIfNoSeal(t)
	out, _ := runProbe(t, []string{"trace", "--backend", "sealed"}, wrap("a, b = socket.socketpair(); a.send(b'x'); assert b.recv(1) == b'x'"))
	if probeResult(out) != "ok" {
		t.Errorf("socketpair should work inside the sandbox:\n%s", out)
	}
}

// A path that cannot be used stops the run before the program starts: vpnw
// never falls back to connecting directly.
func TestDeadPathRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()
	marker := filepath.Join(t.TempDir(), "ran")
	cmd := exec.Command(vpnw, "run", "--backend", "env", "--no-save", "--proxy", "socks5://"+dead, "--", "touch", marker)
	out, _ := cmd.CombinedOutput()
	if code := cmd.ProcessState.ExitCode(); code != 123 {
		t.Errorf("exit %d, want 123 (path not usable)\n%s", code, out)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the program ran although its path was down")
	}
}

// The usual case: vpnw started by an ordinary user. The helper needs one
// capability inside its own namespace to bring loopback up, and must drop it
// before the program starts. When the tests run as root, they check this as
// the "nobody" user.
func TestUnprivilegedWorkloadHasNoCapabilities(t *testing.T) {
	skipIfNoSeal(t)
	bin := vpnw
	var cred *syscall.Credential
	if os.Geteuid() == 0 {
		dir, err := os.MkdirTemp("", "vpnw-nobody-")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)
		os.Chmod(dir, 0o755)
		bin = filepath.Join(dir, "vpnw")
		data, err := os.ReadFile(vpnw)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(bin, data, 0o755); err != nil {
			t.Fatal(err)
		}
		cred = &syscall.Credential{Uid: 65534, Gid: 65534}
	}
	probe := "import os, socket\n" +
		"eff = open('/proc/self/status').read().split('CapEff:')[1].split()[0]\n" +
		"print('UID', os.getuid(), 'CAPEFF', eff)\n" +
		"try:\n    socket.create_connection(('1.1.1.1', 443), 2); print('LEAK')\n" +
		"except OSError as e:\n    print('ERRNO', e.errno)\n"
	cmd := exec.Command(bin, "run", "--backend", "sealed", "--no-save", "--", "python3", "-c", probe)
	cmd.Dir = os.TempDir()
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=/tmp", "NO_COLOR=1"}
	if cred != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("unprivileged sealed run failed: %v\n%s", err, out)
	}
	s := string(out)
	if !strings.Contains(s, "CAPEFF 0000000000000000") {
		t.Errorf("the workload kept capabilities:\n%s", s)
	}
	if strings.Contains(s, "UID 0 ") {
		t.Errorf("the workload runs as root:\n%s", s)
	}
	if !strings.Contains(s, "ERRNO 101") {
		t.Errorf("a direct connection was not refused with ENETUNREACH:\n%s", s)
	}
}
