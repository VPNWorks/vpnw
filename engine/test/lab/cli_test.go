// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package labtest

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"vpnw.com/vpnw/internal/lab"
	"vpnw.com/vpnw/internal/lab/bench"
	"vpnw.com/vpnw/internal/lab/client"
	"vpnw.com/vpnw/internal/lab/netlink"
	"vpnw.com/vpnw/internal/lab/world"
)

// command runs the built vpnw-lab and returns its exit code and output.
func command(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(filepath.Join(bins, "vpnw-lab"), args...)
	cmd.Env = append(os.Environ(), env()...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, out.String(), errb.String()
}

// TestRunCommand runs scenarios with the vpnw-lab command, as a user
// would, and decides its recordings again with vpnw-lab verdict.
func TestRunCommand(t *testing.T) {
	needBins(t)
	parallel <- struct{}{}
	defer func() { <-parallel }()
	dir := t.TempDir()
	rec := filepath.Join(dir, "dns-leak.jsonl")
	keep := filepath.Join(dir, "keep")
	code, out, stderr := command(t, "run", "--app", "dns-leak", "--scenario", "server-silent", "--seed", "3", "--fault-for", "2s", "-o", rec, "--keep", keep, "-v")
	if code != 120 || !strings.HasPrefix(out, "dns-leak, server-silent (seed 3): LEAK\n") || !strings.Contains(out, "(dns)") {
		t.Fatalf("run: exit %d\n%s\n%s", code, out, stderr)
	}
	for _, want := range []string{"world built in", "dns-leak, server-silent (seed 3): started", "fault-on server-silent", "fault-off server-silent", "stop"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("progress lacks %q:\n%s", want, stderr)
		}
	}
	for _, f := range []string{"client.jsonl", "probe.jsonl", "device/resolv.conf"} {
		if _, err := os.Stat(filepath.Join(keep, f)); err != nil {
			t.Errorf("--keep: %v", err)
		}
	}
	code, again, _ := command(t, "verdict", rec)
	if code != 120 || strings.SplitN(again, "\n", 2)[0] != strings.SplitN(out, "\n", 2)[0] {
		t.Fatalf("verdict: exit %d\n%s", code, again)
	}
	code, js, _ := command(t, "verdict", "--json", rec)
	var r lab.Report
	if err := json.Unmarshal([]byte(js), &r); err != nil || code != 120 || r.Summary != "leak (dns)" || r.Seed != 3 || len(r.Windows) != 1 {
		t.Fatalf("verdict --json: %d %v %s", code, err, js)
	}
	if r.FaultOff-r.FaultOn < 2 || r.FaultOff-r.FaultOn > 2.3 {
		t.Fatalf("--fault-for 2s gave a fault from %.2f to %.2f s", r.FaultOn, r.FaultOff)
	}
	code, js, stderr = command(t, "run", "--app", "correct", "--scenario", "steady", "--json")
	if err := json.Unmarshal([]byte(js), &r); err != nil || code != 0 || r.Status != lab.Pass || r.Sent < 100 {
		t.Fatalf("run --json: %d %v %s %s", code, err, js, stderr)
	}
	code, out, stderr = command(t, "run", "--app", "agent-sealed", "--scenario", "steady", "--vpnw", filepath.Join(bins, "vpnw"))
	if code != 0 || !strings.Contains(out, "dns via proxy") {
		t.Fatalf("agent-sealed: %d\n%s\n%s", code, out, stderr)
	}
	// vpnw next to vpnw-lab is found without --vpnw.
	code, out, _ = command(t, "run", "--app", "agent-env", "--scenario", "steady")
	if code != 120 || !strings.Contains(out, "agent-env, steady (seed 1): LEAK") {
		t.Fatalf("agent-env: %d\n%s", code, out)
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"run", "--app", "correct", "--scenario", "steady", "-o", filepath.Join(dir, "no", "such", "file")}, "no such file"},
		{[]string{"run", "--app", "agent-sealed", "--scenario", "steady", "--vpnw", filepath.Join(dir, "missing")}, "--vpnw"},
	} {
		if code, _, stderr := command(t, c.args...); code == 0 || !strings.Contains(stderr, c.want) {
			t.Errorf("%v: %d %s", c.args, code, stderr)
		}
	}
	t.Logf("RESULT command: vpnw-lab run gave the dns-leak client's leak (exit 120), the correct client's pass and the Agent's two modes; vpnw-lab verdict decided the recording the same way")
}

// TestSeeds checks that a seed fixes the timetable: the same seed plans the
// fault for the same moment, every step happens close to its plan, and
// another seed moves the fault.
func TestSeeds(t *testing.T) {
	needBins(t)
	app, _ := lab.FindApp("dns-leak")
	sc, _ := lab.FindScenario(lab.FaultServerSilent)
	var summaries []string
	var late time.Duration
	for _, seed := range []int64{4, 4, 9} {
		res := runOne(t, app, sc, seed, 0)
		v := res.Verdict
		summaries = append(summaries, v.Summary())
		plan := sc.Timetable(seed, 0)
		if !reflect.DeepEqual(plan, res.Steps) {
			t.Fatalf("seed %d: the run followed %v, not its plan %v", seed, res.Steps, plan)
		}
		for i, got := range []time.Duration{v.FaultOn.Sub(v.Start), v.FaultOff.Sub(v.Start)} {
			d := got - plan[i+1].At
			if d < 0 || d > 250*time.Millisecond {
				t.Errorf("seed %d: %s came %s after its plan", seed, plan[i+1].Name, d)
			}
			late = max(late, d)
		}
	}
	p4, p9 := sc.Timetable(4, 0), sc.Timetable(9, 0)
	if !reflect.DeepEqual(p4, sc.Timetable(4, 0)) || (p4[1].At-p9[1].At).Abs() < 20*time.Millisecond {
		t.Fatalf("plans: seed 4 %v, seed 9 %v", p4, p9)
	}
	for _, s := range summaries {
		if s != "leak (dns)" {
			t.Fatalf("verdicts: %v", summaries)
		}
	}
	t.Logf("RESULT seeds: seed 4 plans the fault at %s in both runs, seed 9 at %s; every step came at most %s after its plan; all three runs %s",
		lab.Seconds(p4[1].At), lab.Seconds(p9[1].At), lab.Millis(late), summaries[0])
}

// TestClientCleansUp starts the correct client on a world's device, stops
// it, and checks it left nothing behind: no firewall table, no rule, no
// route, and the home network's DNS server back in place.
func TestClientCleansUp(t *testing.T) {
	needBins(t)
	dir := t.TempDir()
	w, err := world.Build(filepath.Join(dir, "device"))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	log := filepath.Join(dir, "client.jsonl")
	cmd := exec.Command(filepath.Join(bins, "vpnw-lab"), "client", "--mode", "correct", "--resolv", w.Resolv, "--log", log)
	cmd.Env = append(os.Environ(), env()...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := w.Device.Start(cmd); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		b, _ := os.ReadFile(log)
		if bytes.Contains(b, []byte(`"state":"up"`)) {
			break
		}
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			t.Fatalf("the client never came up: %s", out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	nftList := func() string {
		var s string
		w.Device.Do(func() error {
			b, _ := exec.Command("nft", "list", "ruleset").CombinedOutput()
			s = string(b)
			return nil
		})
		return s
	}
	if rs := nftList(); !strings.Contains(rs, "table inet "+client.TableName) || !strings.Contains(rs, `drop comment "kill switch"`) {
		t.Fatalf("no kill switch while running:\n%s", rs)
	}
	if a, _ := world.ReadResolv(w.Resolv); a != world.TunnelPeer {
		t.Fatalf("DNS while running: %s", a)
	}
	cmd.Process.Signal(syscall.SIGTERM)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("the client's exit: %v\n%s", err, out.String())
	}
	if rs := nftList(); strings.Contains(rs, client.TableName) {
		t.Fatalf("the client left its table:\n%s", rs)
	}
	err = w.Device.Do(func() error {
		rules, err := netlink.Rules()
		if err != nil {
			return err
		}
		for _, r := range rules {
			if r.Table == 51820 {
				t.Errorf("the client left a rule: %s", r)
			}
		}
		routes, err := netlink.Routes(51820)
		if err != nil {
			return err
		}
		if len(routes) > 0 {
			t.Errorf("the client left routes: %v", routes)
		}
		if _, err := netlink.Index("tun0"); err == nil {
			t.Error("the client left its TUN device")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := world.ReadResolv(w.Resolv); a != world.RouterAddr {
		t.Fatalf("DNS after the client stopped: %s", a)
	}
	b, _ := os.ReadFile(log)
	if !bytes.Contains(b, []byte(`"state":"stop"`)) {
		t.Fatalf("no stop in the client's log:\n%s", b)
	}
	t.Logf("RESULT client-cleanup: the correct client removed its firewall table, rule, routes and TUN device on exit, and put the home network's DNS server back")
}

// TestFollowsRoutesHoldsRoutes checks the follows-routes client's routing
// kill switch: killed, it leaves a persistent TUN device and its routes, so
// traffic still goes nowhere instead of out the home network.
func TestFollowsRoutesHoldsRoutes(t *testing.T) {
	needBins(t)
	dir := t.TempDir()
	w, err := world.Build(filepath.Join(dir, "device"))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	log := filepath.Join(dir, "client.jsonl")
	cmd := exec.Command(filepath.Join(bins, "vpnw-lab"), "client", "--mode", "follows-routes", "--resolv", w.Resolv, "--log", log)
	cmd.Env = append(os.Environ(), env()...)
	if err := w.Device.Start(cmd); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		b, _ := os.ReadFile(log)
		if bytes.Contains(b, []byte(`"state":"up"`)) {
			break
		}
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			t.Fatal("the client never came up")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cmd.Process.Kill()
	cmd.Wait()
	err = w.Device.Do(func() error {
		routes, err := netlink.Routes(0)
		if err != nil {
			return err
		}
		held := 0
		for _, r := range routes {
			if r.Dev == "tun0" && (r.Dst == netip.MustParsePrefix("0.0.0.0/1") || r.Dst == netip.MustParsePrefix("128.0.0.0/1")) {
				held++
			}
		}
		if held != 2 {
			t.Errorf("after a crash: %v", routes)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// fake writes a stand-in for vpnw-lab whose client misbehaves as told.
func fake(t *testing.T, client string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake-lab")
	script := `#!/bin/sh
case "$1" in
client)
  while [ $# -gt 0 ]; do [ "$1" = --log ] && log=$2; shift; done
  ` + client + `
  ;;
probe) exit 0 ;;
esac
`
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestBenchErrors runs the bench with clients that fail, and with missing
// inputs, and checks it says what went wrong and leaves nothing running.
func TestBenchErrors(t *testing.T) {
	needBins(t)
	app, _ := lab.FindApp("correct")
	agent, _ := lab.FindApp("agent-sealed")
	steady, _ := lab.FindScenario("steady")
	up := `printf '{"t":"2026-10-05T21:00:00Z","ev":"client","state":"up"}\n' >> "$log"`
	for _, c := range []struct {
		cfg  bench.Config
		want string
	}{
		{bench.Config{App: app, Scenario: steady}, "needs the vpnw-lab executable"},
		{bench.Config{App: agent, Scenario: steady, Self: "x"}, "needs the vpnw executable"},
		{bench.Config{App: app, Scenario: steady, Self: "x", Dir: "/proc/version/run"}, "not a directory"},
		{bench.Config{App: app, Scenario: steady, Self: fake(t, "exit 3")}, "the client stopped before its tunnel came up"},
		{bench.Config{App: app, Scenario: steady, Self: fake(t, "exec sleep 30"), UpWait: 300 * time.Millisecond}, "did not come up within 300ms"},
		{bench.Config{App: app, Scenario: steady, Self: fake(t, up+"\n  echo 'not json' >> \"$log\"\n  exec sleep 30")}, "client.jsonl:2: not a JSON object"},
	} {
		if c.cfg.Dir == "" {
			c.cfg.Dir = t.TempDir()
		}
		_, err := bench.Run(c.cfg)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("want %q, got %v", c.want, err)
		}
	}
}
