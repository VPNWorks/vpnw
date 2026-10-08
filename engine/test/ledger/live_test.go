// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package ledgertest seals records as they come off the network path: the
// trace of a real vpnw run, and the flows vpnw-scope records on a test
// gateway. vpnw-ledger seal --follow seals each file while it is written,
// is stopped with SIGTERM like a service, and the result is checked with
// verify, prove and check-proof. Every program here is the real command.
package ledgertest

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"vpnw.com/vpnw/internal/testnet"
)

// bin holds the commands, built once; VPNW_LEDGER_BIN passes them on to a
// test run again inside namespaces.
var bin string

func TestMain(m *testing.M) {
	bin = os.Getenv("VPNW_LEDGER_BIN")
	if bin == "" {
		dir, err := os.MkdirTemp("", "vpnw-ledger-it-")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		defer os.RemoveAll(dir)
		bin = dir
		for _, c := range []string{"vpnw-ledger", "vpnw", "vpnw-scope"} {
			args := []string{"build", "-o", filepath.Join(dir, c)}
			if c == "vpnw-ledger" && os.Getenv("VPNW_LEDGER_BINCOVER") != "" {
				// tools/measure-ledger.sh: count what the real command runs.
				args = append(args, "-cover", "-coverpkg=vpnw.com/vpnw/...")
			}
			if out, err := exec.Command("go", append(args, "vpnw.com/vpnw/cmd/"+c)...).CombinedOutput(); err != nil {
				fmt.Printf("build %s: %v\n%s", c, err, out)
				os.Exit(1)
			}
		}
	}
	code := m.Run()
	if os.Getenv("VPNW_LEDGER_BIN") == "" {
		os.RemoveAll(bin)
	}
	os.Exit(code)
}

// ledgerCmd is the real vpnw-ledger command.
func ledgerCmd(args ...string) *exec.Cmd {
	cmd := exec.Command(filepath.Join(bin, "vpnw-ledger"), args...)
	if d := os.Getenv("VPNW_LEDGER_BINCOVER"); d != "" {
		cmd.Env = append(os.Environ(), "GOCOVERDIR="+d)
	}
	return cmd
}

// ledger runs vpnw-ledger and returns its exit code and output.
func ledger(t *testing.T, args ...string) (int, string) {
	t.Helper()
	out, err := ledgerCmd(args...).CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(out)
	} else if err != nil {
		t.Fatal(err)
	}
	return 0, string(out)
}

// follower is vpnw-ledger seal --follow running as its own process.
type follower struct {
	cmd    *exec.Cmd
	stdout bytes.Buffer
	stderr bytes.Buffer
}

// follow starts seal --follow on records, which must exist, and waits until
// the ledger has its header.
func follow(t *testing.T, dir, records string, args ...string) *follower {
	t.Helper()
	if code, out := ledger(t, "keygen", "-o", filepath.Join(dir, "k")); code != 0 {
		t.Fatal(out)
	}
	f := &follower{cmd: ledgerCmd(append([]string{"seal", "--follow", "--key", filepath.Join(dir, "k.key")}, append(args, records)...)...)}
	f.cmd.Stdout, f.cmd.Stderr = &f.stdout, &f.stderr
	if err := f.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.cmd.Process.Kill() })
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if b, _ := os.ReadFile(records + ".ledger"); bytes.HasPrefix(b, []byte(`{"vpnw-ledger":1`)) {
			return f
		}
		if time.Now().After(deadline) {
			t.Fatalf("seal --follow didn't start: %s", f.stderr.String())
		}
	}
}

// stop stops the follower with SIGTERM, as a service manager would, and
// returns how many checkpoints it signed.
func (f *follower) stop(t *testing.T) int {
	t.Helper()
	f.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- f.cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("seal --follow: %v\n%s", err, f.stderr.String())
		}
	case <-time.After(60 * time.Second):
		t.Fatal("seal --follow didn't stop on SIGTERM")
	}
	return strings.Count(f.stdout.String(), `{"cp":`)
}

// check verifies records, proves line n and checks the proof; it returns
// verify's output.
func check(t *testing.T, dir, records string, n int) string {
	t.Helper()
	code, out := ledger(t, "verify", "--pub", filepath.Join(dir, "k.pub"), records)
	if code != 0 {
		t.Fatalf("verify: %d %s", code, out)
	}
	proof := filepath.Join(dir, "proof.json")
	if code, out := ledger(t, "prove", "--line", fmt.Sprint(n), "-o", proof, records); code != 0 {
		t.Fatalf("prove: %d %s", code, out)
	}
	if code, out := ledger(t, "check-proof", "--pub", filepath.Join(dir, "k.pub"), proof); code != 0 || !strings.Contains(out, "The proof holds.") {
		t.Fatalf("check-proof: %d %s", code, out)
	}
	return out
}

func lines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

// TestSealAgentLive runs a program under vpnw trace, as an agent would run,
// while seal --follow seals the trace vpnw writes.
func TestSealAgentLive(t *testing.T) {
	if out, err := exec.Command(filepath.Join(bin, "vpnw"), "doctor").CombinedOutput(); err != nil || !strings.Contains(string(out), "sealed backend   ok") {
		t.Skip("vpnw's sealed backend isn't available here:\n" + string(out))
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				bufio.NewReader(c).ReadString('\n')
				fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n")
			}(c)
		}
	}()
	dir := t.TempDir()
	trace := filepath.Join(dir, "trace.jsonl")
	os.WriteFile(trace, nil, 0o600)
	f := follow(t, dir, trace, "--every", "16", "--interval", "200ms")
	const conns = 12
	probe := fmt.Sprintf("import time, urllib.request\nfor i in range(%d):\n    urllib.request.urlopen('http://127.0.0.1:%d/r%%d' %% i, timeout=5).read()\n    time.sleep(0.05)\n",
		conns, ln.Addr().(*net.TCPAddr).Port)
	run := exec.Command(filepath.Join(bin, "vpnw"), "trace", "--backend", "sealed", "--no-save", "--out", trace, "--", "python3", "-c", probe)
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("vpnw trace: %v\n%s", err, out)
	}
	cps := f.stop(t)
	evs := lines(t, trace)
	opened := 0
	line := 0 // the seventh connection.open
	for i, e := range evs {
		if strings.Contains(e, `"type":"connection.open"`) {
			if opened++; opened == 7 {
				line = i + 1
			}
		}
	}
	if opened != conns || !strings.Contains(f.stderr.String(), fmt.Sprintf("sealed %d new records", len(evs))) {
		t.Fatalf("%d connections opened, %d events: %s", opened, len(evs), f.stderr.String())
	}
	out := check(t, dir, trace, line)
	if !strings.Contains(out, fmt.Sprintf("is intact: %d records", len(evs))) {
		t.Fatalf("verify: %s", out)
	}
	t.Logf("RESULT agent-live: vpnw trace ran a program that opened %d connections; seal --follow sealed the %d events of its trace as vpnw wrote them, under %d checkpoints, and stopped on SIGTERM; verify: intact; the proof of line %d, the 7th connection.open, checks with the public key alone",
		conns, len(evs), cps, line)
}

// inside runs the calling test again in new user and network namespaces,
// as root there, and reports whether this is the run inside.
func inside(t *testing.T) bool {
	t.Helper()
	if os.Getenv(testnet.ReexecEnv) == "1" {
		return true
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"--user", "--map-root-user", "--net", exe, "-test.run", "^" + t.Name() + "$", "-test.v", "-test.count=1"}
	for _, a := range os.Args[1:] {
		if strings.HasPrefix(a, "-test.gocoverdir") {
			args = append(args, a)
		}
	}
	cmd := exec.Command("unshare", args...)
	cmd.Env = append(os.Environ(), testnet.ReexecEnv+"=1", "VPNW_LEDGER_BIN="+bin)
	out, err := cmd.CombinedOutput()
	for _, l := range strings.Split(string(out), "\n") {
		if i := strings.Index(l, "RESULT "); i >= 0 {
			t.Log(l[i:])
		}
	}
	if err != nil {
		t.Fatalf("inside new namespaces: %v\n%s", err, out)
	}
	return false
}

// TestSealScopeLive records connections through a test gateway with
// vpnw-scope record, while seal --follow seals the flows it writes.
func TestSealScopeLive(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft is not installed")
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare is not installed")
	}
	if os.Getenv(testnet.ReexecEnv) != "1" {
		if err := testnet.Available(); err != nil {
			t.Skip(err)
		}
	}
	if !inside(t) {
		return
	}
	// A gateway (this namespace) between a client at 10.8.0.11 and an
	// office server at 10.0.1.20, each in a namespace of its own.
	clients, err := testnet.NewNS("clients")
	if err != nil {
		t.Fatal(err)
	}
	defer clients.Close()
	office, err := testnet.NewNS("office")
	if err != nil {
		t.Fatal(err)
	}
	defer office.Close()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(testnet.LinkUp("lo"))
	must(testnet.AddVeth("g0", "c0"))
	must(testnet.MoveLink("c0", clients))
	must(testnet.AddVeth("g1", "o0"))
	must(testnet.MoveLink("o0", office))
	must(testnet.AddAddr("g0", "172.31.0.1/30"))
	must(testnet.LinkUp("g0"))
	must(testnet.AddAddr("g1", "172.31.1.1/30"))
	must(testnet.LinkUp("g1"))
	must(testnet.AddRoute("10.8.0.0/24", "172.31.0.2"))
	must(testnet.AddRoute("10.0.0.0/16", "172.31.1.2"))
	must(testnet.Here.Sysctl("net/ipv4/ip_forward", "1"))
	side := func(ns *testnet.NS, addr, link, cidr, gw string) {
		must(ns.Do(func() error {
			for _, step := range []func() error{
				func() error { return testnet.AddAddr("lo", addr) },
				func() error { return testnet.AddAddr(link, cidr) },
				func() error { return testnet.LinkUp(link) },
				func() error { return testnet.AddRoute("default", gw) },
			} {
				if err := step(); err != nil {
					return err
				}
			}
			return nil
		}))
	}
	side(clients, "10.8.0.11/32", "c0", "172.31.0.2/30", "172.31.0.1")
	side(office, "10.0.1.20/32", "o0", "172.31.1.2/30", "172.31.1.1")
	var srv net.Listener
	must(office.Do(func() error { srv, err = net.Listen("tcp", "10.0.1.20:443"); return err }))
	defer srv.Close()
	go func() {
		for {
			c, err := srv.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	dir := t.TempDir()
	people := filepath.Join(dir, "people.toml")
	os.WriteFile(people, []byte("version = 1\nvpn_net = \"10.8.0.0/24\"\n\n[people.alice]\naddresses = [\"10.8.0.11\"]\n"), 0o644)
	flows := filepath.Join(dir, "flows.jsonl")
	os.WriteFile(flows, nil, 0o644)
	f := follow(t, dir, flows, "--every", "10", "--interval", "300ms")
	rec := exec.Command(filepath.Join(bin, "vpnw-scope"), "record", "--people", people, "--out", flows, "--group", "9", "--duration", "5s")
	var recErr bytes.Buffer
	rec.Stderr = &recErr
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(30 * time.Second); exec.Command("nft", "list", "table", "inet", "vpnw_scope_record").Run() != nil; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			rec.Process.Kill()
			t.Fatalf("the recorder's table never appeared: %s", recErr.String())
		}
	}
	const conns = 30
	for i := 0; i < conns; i++ {
		must(clients.Do(func() error {
			d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("10.8.0.11")}, Timeout: 5 * time.Second}
			c, err := d.Dial("tcp", "10.0.1.20:443")
			if err == nil {
				c.Close()
			}
			return err
		}))
		time.Sleep(20 * time.Millisecond)
	}
	if err := rec.Wait(); err != nil || !strings.Contains(recErr.String(), fmt.Sprintf("recorded %d new connections", conns)) {
		t.Fatalf("record: %v %s", err, recErr.String())
	}
	cps := f.stop(t)
	got := lines(t, flows)
	if len(got) != conns || !strings.Contains(got[0], `"src":"10.8.0.11","dst":"10.0.1.20","port":443`) {
		t.Fatalf("%d flows: %v", len(got), got)
	}
	out := check(t, dir, flows, conns)
	if !strings.Contains(out, fmt.Sprintf("is intact: %d records", conns)) {
		t.Fatalf("verify: %s", out)
	}
	t.Logf("RESULT scope-live: %d connections through a test gateway; vpnw-scope record wrote a flow for each, and seal --follow sealed the %d flows as they were written, under %d checkpoints, stopping on SIGTERM; verify: intact; the proof of line %d checks with the public key alone",
		conns, len(got), cps, conns)
}
