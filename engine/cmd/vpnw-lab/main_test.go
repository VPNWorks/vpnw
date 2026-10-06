// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"vpnw.com/vpnw/internal/lab"
)

var t0 = time.Date(2026, 10, 5, 21, 0, 0, 0, time.UTC)

// recording writes a small recording: ten ticks of DNS probes, the last
// five of which leak when leak is set.
func recording(t *testing.T, dir, name string, leak bool) string {
	t.Helper()
	exit, home := netip.MustParseAddr("192.0.2.20"), netip.MustParseAddr("203.0.113.2")
	at := func(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }
	rec := &lab.Recording{Header: lab.Event{T: t0, Ev: lab.EvRun, Lab: lab.Version, Run: "r-cli", App: "dns-leak", Scenario: "server-silent",
		Seed: 2, IntervalMS: 50, Exit: exit, Home: home}}
	add := func(e lab.Event) { rec.Events = append(rec.Events, e) }
	add(lab.Event{T: at(0), Ev: lab.EvStep, Step: lab.StepStart})
	add(lab.Event{T: at(200), Ev: lab.EvStep, Step: lab.StepFaultOn, Fault: "server-silent"})
	for i := 0; i < 10; i++ {
		add(lab.Event{T: at(i * 50), Ev: lab.EvSent, Kind: lab.DNS, Via: lab.Direct, Seq: i})
		src, where := exit, lab.AtZoneDNS
		if leak && i >= 5 {
			src, where = home, lab.AtZoneDNS
		}
		add(lab.Event{T: at(i*50 + 1), Ev: lab.EvArrival, Kind: lab.DNS, Via: lab.Direct, Seq: i, At: where, Src: src})
	}
	add(lab.Event{T: at(500), Ev: lab.EvStep, Step: lab.StepStop})
	p := filepath.Join(dir, name)
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	rec.WriteTo(f)
	f.Close()
	return p
}

func call(stdin string, args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestVerdict(t *testing.T) {
	dir := t.TempDir()
	leaky := recording(t, dir, "leaky.jsonl", true)
	clean := recording(t, dir, "clean.jsonl", false)
	code, out, _ := call("", "verdict", leaky)
	if code != exitLeak || !strings.HasPrefix(out, "dns-leak, server-silent (seed 2): LEAK\n") || !strings.Contains(out, "leak 1: 5 probes from 0.25 s to 0.45 s (dns), still leaking at the end") {
		t.Fatalf("leaky: %d\n%s", code, out)
	}
	code, out, _ = call("", "verdict", clean)
	if code != 0 || !strings.Contains(out, ": pass\n") {
		t.Fatalf("clean: %d\n%s", code, out)
	}
	code, out, _ = call("", "verdict", "--json", clean, leaky)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if code != exitLeak || len(lines) != 2 {
		t.Fatalf("two files: %d\n%s", code, out)
	}
	var r lab.Report
	if err := json.Unmarshal([]byte(lines[1]), &r); err != nil || r.Summary != "leak (dns)" || r.Leaked != 5 || r.FaultOn != 0.2 || r.FaultOff != -1 || len(r.Windows) != 1 || !r.Windows[0].Open {
		t.Fatalf("json: %v %+v", err, r)
	}
	b, _ := os.ReadFile(clean)
	if code, out, _ := call(string(b), "verdict", "-"); code != 0 || !strings.Contains(out, "pass") {
		t.Fatalf("stdin: %d %s", code, out)
	}
	// A recording with nothing through the tunnel is a failed run.
	empty := filepath.Join(dir, "empty.jsonl")
	os.WriteFile(empty, []byte(strings.SplitN(string(b), "\n", 2)[0]+"\n"), 0o644)
	if code, out, _ := call("", "verdict", empty); code != exitFailure || !strings.Contains(out, "no traffic") {
		t.Fatalf("no traffic: %d %s", code, out)
	}
	if code, _, _ := call("", "verdict", empty, leaky); code != exitLeak {
		t.Fatalf("a leak counts before no traffic: %d", code)
	}
	bad := filepath.Join(dir, "bad.jsonl")
	os.WriteFile(bad, []byte(strings.SplitN(string(b), "\n", 2)[0]+"\n{\"t\":1}\n"), 0o644)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"verdict"}, "give one or more recordings"},
		{[]string{"verdict", "--nope"}, "verdict:"},
		{[]string{"verdict", filepath.Join(dir, "missing.jsonl")}, "no such file"},
		{[]string{"verdict", bad}, "bad.jsonl:2:"},
	} {
		if code, _, stderr := call("", c.args...); code != exitConfig || !strings.Contains(stderr, c.want) {
			t.Errorf("%v: %d %s", c.args, code, stderr)
		}
	}
}

func TestListVersionHelp(t *testing.T) {
	code, out, _ := call("", "list")
	if code != 0 || !strings.Contains(out, "server-silent   The server goes silent") || !strings.Contains(out, "agent-env") || !strings.Contains(out, "on:  the app under test is killed") {
		t.Fatalf("list: %d\n%s", code, out)
	}
	if code, out, _ := call("", "version"); code != 0 || !strings.HasPrefix(out, "vpnw-lab 0.1.0 (") {
		t.Fatalf("version: %s", out)
	}
	if code, out, _ := call("", "help"); code != 0 || !strings.Contains(out, "vpnw-lab run") || !strings.Contains(out, "Exit codes: 0 pass; 120") {
		t.Fatalf("help: %s", out)
	}
	if code, _, stderr := call(""); code != exitConfig || !strings.Contains(stderr, "Usage:") {
		t.Fatalf("no command: %d", code)
	}
	if code, _, stderr := call("", "fly"); code != exitConfig || !strings.Contains(stderr, "unknown command") {
		t.Fatalf("unknown: %d %s", code, stderr)
	}
}

func TestArgumentErrors(t *testing.T) {
	dir := t.TempDir()
	resolv := filepath.Join(dir, "resolv.conf")
	os.WriteFile(resolv, []byte("nameserver 127.0.0.1\n"), 0o644)
	cases := []struct {
		args []string
		code int
		want string
	}{
		{[]string{"probe", "--bogus"}, exitConfig, "probe:"},
		{[]string{"probe", "--run", "r", "--direct"}, exitConfig, "--direct needs --resolv"},
		{[]string{"probe", "--run", "R!", "--direct", "--resolv", resolv}, exitConfig, "--run"},
		{[]string{"probe", "--run", "r"}, exitConfig, "nothing to send"},
		{[]string{"probe", "--run", "r", "--interval", "0s", "--direct", "--resolv", resolv}, exitConfig, "--interval"},
		{[]string{"probe", "--run", "r", "--epoch", "noon", "--direct", "--resolv", resolv}, exitConfig, "--epoch"},
		{[]string{"probe", "--run", "r", "--until", "later", "--direct", "--resolv", resolv}, exitConfig, "--until"},
		{[]string{"probe", "--run", "r", "--target", "example.com", "--direct", "--resolv", resolv}, exitConfig, "--target"},
		{[]string{"probe", "--run", "r", "--tcp-port", "0", "--direct", "--resolv", resolv}, exitConfig, "ports"},
		{[]string{"probe", "--run", "r", "--proxy", "http://127.0.0.1:1"}, exitConfig, "socks5"},
		{[]string{"probe", "--run", "r", "--proxy", "env"}, exitConfig, "ALL_PROXY is not set"},
		{[]string{"probe", "--run", "r", "--direct", "--resolv", resolv, "--log", filepath.Join(dir, "no", "log")}, exitFailure, "no such file"},
		{[]string{"probe", "--run", "r", "extra"}, exitConfig, "unexpected argument"},
		{[]string{"run"}, exitConfig, "give --app NAME and --scenario NAME"},
		{[]string{"run", "--app", "toaster", "--scenario", "steady"}, exitConfig, "unknown app"},
		{[]string{"run", "--app", "correct", "--scenario", "eclipse"}, exitConfig, "unknown scenario"},
		{[]string{"run", "--app", "correct", "--scenario", "steady", "--seed", "-1"}, exitConfig, "--seed"},
		{[]string{"run", "--app", "correct", "--scenario", "steady", "--fault-for", "1h"}, exitConfig, "--fault-for"},
		{[]string{"run", "--app", "correct", "--scenario", "steady", "--interval", "1ms"}, exitConfig, "--interval"},
		{[]string{"run", "--bogus"}, exitConfig, "run:"},
		{[]string{"run", "--app", "agent-sealed", "--scenario", "steady", "--vpnw", filepath.Join(dir, "none")}, exitConfig, "--vpnw"},
		{[]string{"client", "--bogus"}, exitConfig, "client:"},
		{[]string{"client", "--mode", "perfect", "--resolv", resolv}, exitConfig, "unknown mode"},
		{[]string{"client", "--mode", "correct"}, exitConfig, "give --resolv FILE"},
		{[]string{"client", "--mode", "correct", "--resolv", resolv, "--server", "vpn:1"}, exitConfig, "--server"},
		{[]string{"client", "--mode", "correct", "--resolv", resolv, "--dns", "x"}, exitConfig, "--dns"},
		{[]string{"client", "--mode", "correct", "--resolv", resolv, "--home-dns", "2001:db8::1"}, exitConfig, "--home-dns"},
		{[]string{"client", "--mode", "correct", "--resolv", resolv, "--addr", "10.66.0.2"}, exitConfig, "--addr"},
		{[]string{"client", "--mode", "correct", "--resolv", resolv, "--home-net", "lan"}, exitConfig, "--home-net"},
		{[]string{"client", "--mode", "correct", "--resolv", resolv, "--log", filepath.Join(dir, "no", "log")}, exitFailure, "no such file"},
	}
	if runtime.GOOS != "linux" {
		cases = cases[:13]
	}
	for _, c := range cases {
		code, out, stderr := call("", c.args...)
		if code != c.code || !strings.Contains(out+stderr, c.want) {
			t.Errorf("%v: exit %d, %q; want %d and %q", c.args, code, out+stderr, c.code, c.want)
		}
	}
}

// TestProbeCommand runs the probe command for a moment against local
// listeners.
func TestProbeCommand(t *testing.T) {
	dir := t.TempDir()
	resolv := filepath.Join(dir, "resolv.conf")
	os.WriteFile(resolv, []byte("nameserver 127.0.0.1\n"), 0o644)
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
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
			c.Close()
		}
	}()
	port := func(a net.Addr) string { return strconv.Itoa(int(netip.MustParseAddrPort(a.String()).Port())) }
	log := filepath.Join(dir, "probe.jsonl")
	now := time.Now()
	code, _, stderr := call("", "probe", "--run", "r-cmd", "--interval", "20ms", "--epoch", now.Format(time.RFC3339Nano),
		"--until", now.Add(100*time.Millisecond).Format(time.RFC3339Nano), "--target", "127.0.0.1", "--tcp-port", port(ln.Addr()),
		"--udp-port", port(udp.LocalAddr()), "--dns-port", port(udp.LocalAddr()), "--resolv", resolv, "--direct", "--log", log)
	if code != 0 {
		t.Fatalf("probe: %d %s", code, stderr)
	}
	f, _ := os.Open(log)
	defer f.Close()
	st, err := lab.ReadEvents(f, log, func(e lab.Event) error { return nil })
	if err != nil || st.Events < 9 || st.Events%3 != 0 {
		t.Fatalf("%v %+v", err, st)
	}
	// The log goes to standard output without --log, and --proxy env
	// takes ALL_PROXY.
	t.Setenv("ALL_PROXY", "socks5h://127.0.0.1:1")
	var out bytes.Buffer
	code = run([]string{"probe", "--run", "r-cmd", "--interval", "20ms", "--until", time.Now().Add(30 * time.Millisecond).Format(time.RFC3339Nano),
		"--proxy", "env"}, nil, &out, &out)
	if code != 0 || !strings.Contains(out.String(), `"via":"proxy"`) {
		t.Fatalf("stdout: %d %s", code, out.String())
	}
}
