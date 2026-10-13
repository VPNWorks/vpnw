// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/VPNWorks/vpnw/internal/path/wgtest"
)

// Lab: the faults a tunnel must survive before it ships. Each test puts a
// fault on the path WireGuard's UDP takes, with wgtest.Relay between vpnw and
// a real test peer, or has the tunnel's own DNS server lie. A case passes
// when the program learns of the fault, nothing goes around the tunnel,
// vpnw never hangs, and the record says what happened.
//
// Set VPNW_LAB_OUT to a file to get the results as a Markdown table.

var (
	labMu   sync.Mutex
	labRows []string
)

func labRecord(fault, want, got string, ok bool) {
	res := "passed"
	if !ok {
		res = "FAILED"
	}
	labMu.Lock()
	labRows = append(labRows, fmt.Sprintf("| %s | %s | %s | %s |", fault, want, got, res))
	labMu.Unlock()
}

func labWrite() {
	fn := os.Getenv("VPNW_LAB_OUT")
	if fn == "" {
		return
	}
	labMu.Lock()
	defer labMu.Unlock()
	os.WriteFile(fn, []byte("| Fault | What must happen | What happened | Result |\n|---|---|---|---|\n"+strings.Join(labRows, "\n")+"\n"), 0o644)
}

// labPeer is a test peer behind a relay, with the client's config.
func labPeer(t *testing.T) (*wgtest.Server, *wgtest.Relay, *env, string) {
	t.Helper()
	skipIfNoSeal(t)
	s := wgPeer(t)
	r, err := wgtest.NewRelay(s.Port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	e := newEnv(t)
	return s, r, e, writeFile(t, e.dir, "wg0.conf", s.ConfigVia(r))
}

// loop is a program that asks the peer's web server for a page every
// 200 ms, for secs seconds, and prints one line per try: OK, or FAIL with
// the reason, each with the second it started.
func loop(secs float64) string {
	return fmt.Sprintf(`import urllib.request as u, time, sys
t0 = time.time()
while time.time() - t0 < %g:
    s = time.time() - t0
    try:
        u.urlopen('http://web.tunnel.test/', timeout=3).read()
        sys.stdout.write('OK %%.1f\n' %% s)
    except Exception as e:
        sys.stdout.write('FAIL %%.1f %%s\n' %% (s, type(e).__name__))
    sys.stdout.flush()
    time.sleep(0.2)
`, secs)
}

// running is vpnw started in the background.
type running struct {
	cmd  *exec.Cmd
	mu   sync.Mutex
	out  bytes.Buffer
	done chan struct{}
	took time.Duration
}

func (e *env) start(args ...string) *running {
	e.t.Helper()
	r := &running{cmd: exec.Command(vpnw, args...), done: make(chan struct{})}
	r.cmd.Env, r.cmd.Dir = e.vars, e.dir
	pr, pw := io.Pipe()
	r.cmd.Stdout, r.cmd.Stderr = pw, pw
	t0 := time.Now()
	if err := r.cmd.Start(); err != nil {
		e.t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			r.mu.Lock()
			r.out.WriteString(sc.Text() + "\n")
			r.mu.Unlock()
		}
	}()
	go func() {
		r.cmd.Wait()
		r.took = time.Since(t0)
		pw.Close()
		close(r.done)
	}()
	return r
}

func (r *running) output() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.out.String()
}

// waitFor waits until the output has n lines starting with prefix.
func (r *running) waitFor(t *testing.T, prefix string, n int, limit time.Duration) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		c := 0
		for _, l := range strings.Split(r.output(), "\n") {
			if strings.HasPrefix(l, prefix) {
				c++
			}
		}
		if c >= n {
			return
		}
		select {
		case <-r.done:
			t.Fatalf("vpnw ended before %d %q lines:\n%s", n, prefix, r.output())
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatalf("no %d %q lines within %v:\n%s", n, prefix, limit, r.output())
}

// wait waits for vpnw to end, failing the test if it hangs.
func (r *running) wait(t *testing.T, limit time.Duration) int {
	t.Helper()
	select {
	case <-r.done:
		return r.cmd.ProcessState.ExitCode()
	case <-time.After(limit):
		r.cmd.Process.Kill()
		<-r.done
		t.Fatalf("vpnw did not end within %v (it hung):\n%s", limit, r.output())
		return -1
	}
}

// unsettled lists the connections in a trace that were attempted and never
// got an outcome: opened, refused or failed.
func unsettled(t *testing.T, fn string) []string {
	t.Helper()
	seen := map[float64]bool{}
	var order []float64
	for _, ev := range readTrace(t, fn) {
		id, _ := ev["conn"].(float64)
		switch ev["type"] {
		case "connection.attempt":
			seen[id] = false
			order = append(order, id)
		case "connection.open", "connection.error", "policy.deny":
			seen[id] = true
		}
	}
	var out []string
	for _, id := range order {
		if !seen[id] {
			out = append(out, fmt.Sprintf("#%.0f", id))
		}
	}
	return out
}

func count(out, prefix string) int {
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, prefix) {
			n++
		}
	}
	return n
}

// The peer goes silent in the middle of a run. Requests fail within their
// time limit, nothing goes anywhere else, the record shows the failures,
// and vpnw ends when the program does.
func TestLabSilentPeer(t *testing.T) {
	s, r, e, conf := labPeer(t)
	tr := filepath.Join(e.dir, "run.jsonl")
	p := e.start("run", "--wireguard", conf, "--out", tr, "--", "python3", "-c", loop(12))
	p.waitFor(t, "OK", 3, 20*time.Second)
	before := s.Requests.Load()
	r.Silence(true)
	code := p.wait(t, 40*time.Second)
	out := p.output()
	fails := count(out, "FAIL")
	errs := 0
	for _, ev := range readTrace(t, tr) {
		if ev["type"] == "connection.error" {
			errs++
		}
	}
	open := unsettled(t, tr)
	ok := code == 0 && fails > 0 && s.Requests.Load() == before && errs > 0 && p.took < 25*time.Second && len(open) == 0
	labRecord("the peer goes silent mid-run", "requests fail in time, nothing reaches the peer, every connection in the record has an outcome, vpnw ends with the program",
		fmt.Sprintf("%d requests failed, %d connection errors recorded, none left open, vpnw ended after %.0f s", fails, errs, p.took.Seconds()), ok)
	if !ok {
		t.Fatalf("exit %d, %d fails, %d errors recorded, %d new requests at the peer, took %v, no outcome: %v\n%s", code, fails, errs, s.Requests.Load()-before, p.took, open, out)
	}
	t.Logf("\n%s", out)
	b, _ := os.ReadFile(tr)
	t.Logf("trace:\n%s", b)
}

// The peer goes silent, then comes back. Requests fail while it's away and
// succeed again after, without vpnw being restarted.
func TestLabPeerComesBack(t *testing.T) {
	_, r, e, conf := labPeer(t)
	tr := filepath.Join(e.dir, "run.jsonl")
	p := e.start("run", "--wireguard", conf, "--out", tr, "--", "python3", "-c", loop(40))
	p.waitFor(t, "OK", 2, 20*time.Second)
	r.Silence(true)
	p.waitFor(t, "FAIL", 2, 30*time.Second)
	r.Silence(false)
	oks := count(p.output(), "OK")
	p.waitFor(t, "OK", oks+2, 30*time.Second)
	p.cmd.Process.Signal(os.Interrupt)
	p.wait(t, 40*time.Second)
	out := p.output()
	open := unsettled(t, tr)
	labRecord("the peer goes silent, then comes back", "requests fail while it's gone and work again after, with no restart; every connection has an outcome",
		fmt.Sprintf("%d requests failed while it was gone, then worked again; none left open", count(out, "FAIL")), len(open) == 0)
	if len(open) > 0 {
		t.Fatalf("connections with no outcome: %v", open)
	}
	t.Logf("\n%s", out)
}

// Lost handshakes: one lost is retried and the run starts; all of them
// lost and the program never starts.
func TestLabLostHandshakes(t *testing.T) {
	s, r, e, conf := labPeer(t)
	r.DropHandshakes(1)
	t0 := time.Now()
	out, code := e.run("run", "--wireguard", conf, "--", "python3", "-c", pyGet("http://web.tunnel.test/"))
	ok1 := code == 0 && strings.Contains(out, "GOT http://web.tunnel.test/") && r.Handshakes() >= 2
	labRecord("the first handshake is lost", "WireGuard tries again and the run starts",
		fmt.Sprintf("started after %d handshakes, %.1f s", r.Handshakes(), time.Since(t0).Seconds()), ok1)
	if !ok1 {
		t.Fatalf("one handshake lost: exit %d, %d handshakes\n%s", code, r.Handshakes(), out)
	}

	r.DropHandshakes(1000)
	marker := filepath.Join(e.dir, "ran")
	before := s.Requests.Load()
	out, code = e.run("run", "--wireguard", conf, "--", "touch", marker)
	_, err := os.Stat(marker)
	ok2 := code == 123 && err != nil && strings.Contains(out, "no WireGuard handshake") && s.Requests.Load() == before
	labRecord("every handshake is lost", "the program never starts; vpnw exits 123",
		fmt.Sprintf("exit %d, program started: %v", code, err == nil), ok2)
	if !ok2 {
		t.Fatalf("all handshakes lost: exit %d, program ran: %v\n%s", code, err == nil, out)
	}
}

// A network that reroutes the tunnel to an impostor, a WireGuard peer
// without the right key: the handshake can't complete, so nothing is sent,
// and the program never starts.
func TestLabImpostor(t *testing.T) {
	s, r, e, conf := labPeer(t)
	imp := wgPeer(t)
	r.Redirect(imp.Port)
	marker := filepath.Join(e.dir, "ran")
	out, code := e.run("run", "--wireguard", conf, "--", "touch", marker)
	_, err := os.Stat(marker)
	ok := code == 123 && err != nil && imp.Requests.Load() == 0 && s.Requests.Load() == 0
	labRecord("the network reroutes the tunnel to an impostor peer", "no handshake with the impostor; the program never starts",
		fmt.Sprintf("exit %d, program started: %v", code, err == nil), ok)
	if !ok {
		t.Fatalf("impostor: exit %d, program ran: %v\n%s", code, err == nil, out)
	}
}

// The tunnel's DNS server answers with addresses a program must not be sent
// to. Without a policy, those outside the tunnel are refused with that
// reason and nothing on this machine or its network is reached; with
// deny_private, cloud metadata and the private ones are refused before any
// packet is sent.
func TestLabHostileDNS(t *testing.T) {
	_, r, e, conf := labPeer(t)
	host := newServer(t) // 127.0.0.1, where loopback.tunnel.test points
	cases := []struct {
		name, want string
		policy     []string
	}{
		{"loopback.tunnel.test", "127.0.0.1 is outside the tunnel", nil},
		{"lan.tunnel.test", "192.168.1.1 is outside the tunnel", nil},
		{"outside.tunnel.test", "1.1.1.1 is outside the tunnel", nil},
		{"metadata.tunnel.test", "169.254.169.254 is outside the tunnel", nil},
		{"metadata.tunnel.test", "169.254.169.254", []string{"--deny-private", "--default", "allow"}},
		{"loopback.tunnel.test", "127.0.0.1", []string{"--deny-private", "--default", "allow"}},
	}
	for _, c := range cases {
		mode := "trace"
		label := "no policy"
		if c.policy != nil {
			mode, label = "guard", "deny_private"
		}
		url := fmt.Sprintf("http://%s:%d/", c.name, host.port)
		before := r.Forwarded()
		args := append([]string{mode, "--wireguard", conf}, c.policy...)
		out, _ := e.run(append(args, "--", "python3", "-c", pyGet(url))...)
		sent := r.Forwarded() - before
		ok := strings.Contains(out, "FAILED "+url) && strings.Contains(out, c.want) && host.count() == 0
		if c.policy != nil {
			// Refused before anything reaches the tunnel beyond the lookup.
			ok = ok && strings.Contains(out, "deny")
		}
		labRecord(fmt.Sprintf("the tunnel's DNS points %s at %s (%s)", c.name, strings.Fields(c.want)[0], label),
			"refused with the reason; nothing on this machine or its network is reached",
			fmt.Sprintf("refused; %d packets on the tunnel, the lookup included", sent), ok)
		if !ok {
			t.Errorf("%s (%s): host listener saw %d\n%s", c.name, label, host.count(), out)
		}
	}
}

// A slow path, 300 ms each way: it works, only slower.
func TestLabSlowPath(t *testing.T) {
	_, r, e, conf := labPeer(t)
	r.Delay(300 * time.Millisecond)
	out, code := e.run("run", "--wireguard", conf, "--", "python3", "-c", pyGet("http://web.tunnel.test/"))
	ok := code == 0 && strings.Contains(out, "GOT http://web.tunnel.test/")
	labRecord("every packet is delayed 300 ms each way", "it works, only slower", fmt.Sprintf("exit %d", code), ok)
	if !ok {
		t.Fatalf("slow path: exit %d\n%s", code, out)
	}
}

// The peer goes silent in the middle of a download. The program's read
// times out, vpnw ends with it, and the connection is closed in the
// record with the bytes that did arrive.
func TestLabSilentMidTransfer(t *testing.T) {
	_, r, e, conf := labPeer(t)
	r.Delay(2 * time.Millisecond) // slow enough to catch the transfer midway
	tr := filepath.Join(e.dir, "run.jsonl")
	prog := `import urllib.request as u, sys
r = u.urlopen('http://web.tunnel.test/big', timeout=4)
got = 0
try:
    while True:
        b = r.read(65536)
        if not b: break
        got += len(b)
        if got >= 1 << 20 and got < (1 << 20) + 65536:
            sys.stdout.write('HALF\n'); sys.stdout.flush()
    sys.stdout.write('DONE %d\n' % got)
except Exception as e:
    sys.stdout.write('STALLED %d %s\n' % (got, type(e).__name__))
`
	p := e.start("run", "--wireguard", conf, "--out", tr, "--", "python3", "-c", prog)
	p.waitFor(t, "HALF", 1, 30*time.Second)
	r.Silence(true)
	code := p.wait(t, 30*time.Second)
	out := p.output()
	var down float64
	for _, ev := range readTrace(t, tr) {
		if ev["type"] == "connection.close" {
			f, _ := ev["fields"].(map[string]any)
			down, _ = f["bytes_down"].(float64)
		}
	}
	open := unsettled(t, tr)
	ok := code == 0 && strings.Contains(out, "STALLED") && down >= 1<<20 && len(open) == 0
	labRecord("the peer goes silent in the middle of a download", "the program's read times out, vpnw ends with it, the record closes the connection with the bytes that arrived",
		fmt.Sprintf("stalled after %.1f MB, closed in the record", down/(1<<20)), ok)
	if !ok {
		b, _ := os.ReadFile(tr)
		t.Fatalf("exit %d, %v bytes down recorded, no outcome: %v\n%s\n%s", code, down, open, out, b)
	}
}
