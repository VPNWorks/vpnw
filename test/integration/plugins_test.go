// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// These run the built vpnw with real plugins: the built-in Trace and Learn,
// and the test plugins in internal/pluginhost/testdata, installed the way a
// user would install them.

type env struct {
	t    *testing.T
	vars []string
	dir  string
}

// newEnv gives a test its own plugin store, trusted keys, cache and state.
func newEnv(t *testing.T) *env {
	d := t.TempDir()
	return &env{t: t, dir: d, vars: append(os.Environ(),
		"NO_COLOR=1",
		"XDG_DATA_HOME="+filepath.Join(d, "data"),
		"XDG_CONFIG_HOME="+filepath.Join(d, "config"),
		"XDG_STATE_HOME="+filepath.Join(d, "state"),
		"XDG_CACHE_HOME="+cacheHome,
	)}
}

// cacheHome is shared so plugins are compiled once for the whole run.
var cacheHome = filepath.Join(os.TempDir(), "vpnw-it-cache")

func (e *env) run(args ...string) (string, int) {
	e.t.Helper()
	cmd := exec.Command(vpnw, args...)
	cmd.Env = e.vars
	cmd.Dir = e.dir
	out, _ := cmd.CombinedOutput()
	return string(out), cmd.ProcessState.ExitCode()
}

func (e *env) must(args ...string) string {
	e.t.Helper()
	out, code := e.run(args...)
	if code != 0 {
		e.t.Fatalf("vpnw %s: exit %d\n%s", strings.Join(args, " "), code, out)
	}
	return out
}

// testPlugin builds a test plugin into a folder ready for vpnw plugin add.
func testPlugin(t *testing.T, name string) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	src := filepath.Join(filepath.Dir(file), "..", "..", "internal", "pluginhost", "testdata", "plugins", name)
	dir := filepath.Join(t.TempDir(), name)
	os.MkdirAll(dir, 0o755)
	cmd := exec.Command("go", "build", "-buildmode=c-shared", "-trimpath", "-o", filepath.Join(dir, "plugin.wasm"), ".")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", name, err, out)
	}
	man, err := os.ReadFile(filepath.Join(src, "plugin.toml"))
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "plugin.toml"), man, 0o644)
	return dir
}

func pyGet(urls ...string) string {
	var b strings.Builder
	b.WriteString("import urllib.request as u, sys\nbad = 0\n")
	for _, url := range urls {
		// One write per line, so vpnw's console output on stderr can't land
		// in the middle of it.
		fmt.Fprintf(&b, "try:\n    u.urlopen(%q, timeout=3).read()\n    sys.stdout.write(%q)\nexcept Exception as e:\n    sys.stdout.write(%q)\nsys.stdout.flush()\n", url, "GOT "+url+"\n", "FAILED "+url+"\n")
	}
	return b.String()
}

func readTrace(t *testing.T, fn string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(fn)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("bad trace line %q: %v", l, err)
		}
		out = append(out, m)
	}
	return out
}

// The console of trace and guard is the built-in Trace plugin, and its
// settings reach it.
func TestTraceConsoleIsPlugin(t *testing.T) {
	skipIfNoSeal(t)
	e := newEnv(t)
	srv := newServer(t)
	url := fmt.Sprintf("http://localhost:%d/", srv.port)
	out, code := e.run("trace", "--", "python3", "-c", pyGet(url))
	if code != 0 || !strings.Contains(out, "GOT "+url) {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, want := range []string{fmt.Sprintf("→ localhost:%d", srv.port), "open  127.0.0.1 via direct", "summary  1 connection: 1 opened"} {
		if !strings.Contains(out, want) {
			t.Errorf("trace output lacks %q:\n%s", want, out)
		}
	}
	out, _ = e.run("trace", "--set", "trace.level=quiet", "--", "python3", "-c", pyGet(url))
	if strings.Contains(out, "→ localhost") || !strings.Contains(out, "summary  1 connection") {
		t.Errorf("trace.level=quiet should print the summary only:\n%s", out)
	}
	out, code = e.run("trace", "--set", "trace.level=loud", "--", "true")
	if !strings.Contains(out, "level must be all, decisions or quiet") || !strings.Contains(out, "printing events as JSON instead") {
		t.Errorf("a bad console setting should fall back to JSON, exit %d:\n%s", code, out)
	}
	out, code = e.run("run", "--set", "nosuch.x=1", "--", "true")
	if code != 121 || !strings.Contains(out, "plugin nosuch is not used in this run") {
		t.Errorf("--set for an unused plugin: exit %d\n%s", code, out)
	}
}

// Trace, then Learn through the advisor path, then guard with the draft:
// the round trip still works with both as plugins.
func TestLearnRoundTrip(t *testing.T) {
	skipIfNoSeal(t)
	e := newEnv(t)
	srv := newServer(t)
	url := fmt.Sprintf("http://localhost:%d/", srv.port)
	e.must("trace", "-q", "--", "python3", "-c", pyGet(url))
	draft := filepath.Join(e.dir, "draft.toml")
	out := e.must("learn", "--name", "probe", "--ports", "-o", draft)
	if !strings.Contains(out, "learned 1 destinations allowed") || !strings.Contains(out, "wrote "+draft) {
		t.Errorf("learn said:\n%s", out)
	}
	b, _ := os.ReadFile(draft)
	if !strings.Contains(string(b), fmt.Sprintf(`"localhost:%d"`, srv.port)) || !strings.Contains(string(b), "a private address") {
		t.Fatalf("draft:\n%s", b)
	}
	// The draft keeps deny_private on, which refuses localhost; turned off,
	// it allows exactly what was learned.
	os.WriteFile(draft, []byte(strings.Replace(string(b), "deny_private = true", "deny_private = false", 1)), 0o644)
	out, code := e.run("guard", "--policy", draft, "--", "python3", "-c", pyGet(url, "http://127.0.0.2:9/"))
	if code != 0 && code != 120 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "GOT "+url) || !strings.Contains(out, "FAILED http://127.0.0.2:9/") || !strings.Contains(out, "DENY") {
		t.Errorf("guard with the learned policy:\n%s", out)
	}
	// advise runs the same plugin by name and prints to stdout.
	out = e.must("advise", "learn", "--set", "name=again")
	if !strings.Contains(out, `name = "again"`) {
		t.Errorf("advise learn:\n%s", out)
	}
	if out, code := e.run("advise", "trace"); code != 121 || !strings.Contains(out, "advise runs advisor plugins") {
		t.Errorf("advise on an observer: exit %d\n%s", code, out)
	}
}

// A Guard plugin, installed signed, refuses what the policy allowed; when
// it fails it refuses everything after (fail closed), and the run says so.
func TestGuardPlugin(t *testing.T) {
	skipIfNoSeal(t)
	e := newEnv(t)
	srv := newServer(t)
	dir := testPlugin(t, "blocker")

	// Unsigned is refused; signed by a trusted key installs.
	if out, code := e.run("plugin", "add", dir); code != 121 || !strings.Contains(out, "not signed") {
		t.Fatalf("unsigned add: exit %d\n%s", code, out)
	}
	key := filepath.Join(e.dir, "me")
	pub := strings.TrimSpace(e.must("plugin", "keygen", "-o", key))
	pub = strings.Split(pub, "\n")[0]
	e.must("plugin", "sign", "--key", key+".key", dir)
	e.must("plugin", "trust", key+".pub")
	out := e.must("plugin", "add", dir)
	if !strings.Contains(out, "installed blocker 1.0.0 (guard, signed)") {
		t.Errorf("add: %s", out)
	}
	if out := e.must("plugin", "info", "blocker"); !strings.Contains(out, "signed by "+pub) {
		t.Errorf("info:\n%s", out)
	}
	if out := e.must("plugin", "list"); !strings.Contains(out, "blocker") || !strings.Contains(out, "trace") {
		t.Errorf("list:\n%s", out)
	}

	url := fmt.Sprintf("http://localhost:%d/", srv.port)
	trace := filepath.Join(e.dir, "t.jsonl")
	out, code := e.run("guard", "--allow", "localhost", "--allow", "boom.example", "--plugin", "blocker",
		"--set", "blocker.deny=localhost", "--out", trace, "--", "python3", "-c", pyGet(url))
	if code != 120 || !strings.Contains(out, "FAILED "+url) || !strings.Contains(out, "blocked by the test guard: localhost") {
		t.Fatalf("guard plugin deny: exit %d\n%s", code, out)
	}
	if srv.count() != 0 {
		t.Fatal("the server was reached although the guard refused")
	}
	var plugins any
	for _, ev := range readTrace(t, trace) {
		if ev["type"] == "run.start" {
			plugins = ev["fields"].(map[string]any)["plugins"]
		}
	}
	if fmt.Sprint(plugins) != "[blocker trace]" {
		t.Errorf("run.start plugins = %v", plugins)
	}

	// Without the setting it lets localhost through.
	out, code = e.run("guard", "--allow", "localhost", "--plugin", "blocker", "--", "python3", "-c", pyGet(url))
	if code != 0 || !strings.Contains(out, "GOT "+url) {
		t.Fatalf("guard plugin pass: exit %d\n%s", code, out)
	}

	// boom.example makes it panic: that connection and the next are refused.
	out, code = e.run("guard", "--allow", "localhost", "--allow", "boom.example", "--plugin", "blocker", "--out", trace,
		"--", "python3", "-c", pyGet("http://boom.example/", url))
	if code != 120 || !strings.Contains(out, "FAILED "+url) || !strings.Contains(out, "guard plugin blocker stopped") {
		t.Fatalf("guard plugin failure: exit %d\n%s", code, out)
	}
	var sawErr bool
	for _, ev := range readTrace(t, trace) {
		if ev["type"] == "plugin.error" {
			sawErr = strings.Contains(fmt.Sprint(ev["fields"]), "blocker exploded")
		}
	}
	if !sawErr {
		t.Error("no plugin.error event in the trace")
	}

	// A Guard cannot run on the env backend, which cannot enforce.
	if out, code := e.run("run", "--backend", "env", "--plugin", "blocker", "--", "true"); code != 122 {
		t.Errorf("guard plugin on env: exit %d\n%s", code, out)
	}
	e.must("plugin", "remove", "blocker")
	if out, code := e.run("run", "--plugin", "blocker", "--", "true"); code != 121 || !strings.Contains(out, "no plugin") {
		t.Errorf("after remove: exit %d\n%s", code, out)
	}
}

// An Observer that crashes is stopped; the program and its exit code are
// untouched and the failure is reported and recorded.
func TestObserverCrashLeavesRunAlone(t *testing.T) {
	skipIfNoSeal(t)
	e := newEnv(t)
	e.must("plugin", "add", testPlugin(t, "crash"), "--allow-unsigned")
	trace := filepath.Join(e.dir, "t.jsonl")
	out, code := e.run("run", "--plugin", "crash", "--out", trace, "--", "sh", "-c", "echo still here; exit 3")
	if code != 3 || !strings.Contains(out, "still here") || !strings.Contains(out, "observer plugin crash stopped") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	var n int
	for _, ev := range readTrace(t, trace) {
		if ev["type"] == "plugin.error" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d plugin.error events", n)
	}
	// A plugin whose module does not match its manifest never installs.
	if out, code := e.run("plugin", "add", "--allow-unsigned", testPlugin(t, "sneaky")); code != 121 || !strings.Contains(out, `"console" permission`) {
		t.Errorf("sneaky: exit %d\n%s", code, out)
	}
	// Advisors run with advise, not alongside a program.
	e.must("plugin", "add", "--allow-unsigned", testPlugin(t, "echo"))
	if out, code := e.run("run", "--plugin", "echo", "--", "true"); code != 121 || !strings.Contains(out, "vpnw advise echo") {
		t.Errorf("advisor as --plugin: exit %d\n%s", code, out)
	}
}
