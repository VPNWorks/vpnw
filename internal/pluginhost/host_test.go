// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package pluginhost_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/VPNWorks/vpnw/internal/broker"
	"github.com/VPNWorks/vpnw/internal/events"
	"github.com/VPNWorks/vpnw/internal/pluginhost"
	"github.com/VPNWorks/vpnw/plugins/builtin"
)

// The test plugins in testdata/plugins are built once per test run, with
// the same Go toolchain as the tests.
var (
	buildDir  string
	buildMu   sync.Mutex
	built     = map[string]string{}
	cacheDir  string
	repoRoot  string
	sharedCtx = context.Background()
)

func TestMain(m *testing.M) {
	var err error
	buildDir, err = os.MkdirTemp("", "vpnw-plugins-")
	if err != nil {
		panic(err)
	}
	cacheDir = filepath.Join(buildDir, "cache")
	_, file, _, _ := runtime.Caller(0)
	repoRoot = filepath.Join(filepath.Dir(file), "..", "..")
	code := m.Run()
	os.RemoveAll(buildDir)
	os.Exit(code)
}

// plugin returns the folder of a built test plugin: plugin.toml and
// plugin.wasm.
func plugin(t *testing.T, name string) string {
	t.Helper()
	buildMu.Lock()
	defer buildMu.Unlock()
	if dir, ok := built[name]; ok {
		return dir
	}
	src := filepath.Join(repoRoot, "internal", "pluginhost", "testdata", "plugins", name)
	dir := filepath.Join(buildDir, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	args := []string{"build", "-trimpath", "-o", filepath.Join(dir, "plugin.wasm")}
	if name != "plain" {
		args = append(args, "-buildmode=c-shared")
	}
	cmd := exec.Command("go", append(args, ".")...)
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building test plugin %s: %v\n%s", name, err, out)
	}
	man, err := os.ReadFile(filepath.Join(src, "plugin.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plugin.toml"), man, 0o644); err != nil {
		t.Fatal(err)
	}
	built[name] = dir
	return dir
}

func pkg(t *testing.T, name string) *pluginhost.Package {
	t.Helper()
	p, _, err := pluginhost.ReadDir(plugin(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func host(t *testing.T) *pluginhost.Host {
	t.Helper()
	h, err := pluginhost.New(sharedCtx, cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close(sharedCtx) })
	return h
}

func eventJSON(t *testing.T, typ string, conn uint64, f map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(events.Event{V: 1, TS: time.Now(), Type: typ, Run: "r-test", Conn: conn, Fields: f})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// An Observer gets every event in order, its writes reach the console, its
// events are renamed into its own namespace, an event type that is not
// valid is dropped, and Finish runs.
func TestObserverEventsAndFinish(t *testing.T) {
	h := host(t)
	var out, errOut bytes.Buffer
	var logs []string
	var emitted []string
	in, err := h.Load(sharedCtx, pkg(t, "echo"), pluginhost.Options{
		Command: "trace", Settings: map[string]string{"prefix": "> "},
		Stdout: &out, Stderr: &errOut,
		Log:  func(p, l string) { logs = append(logs, p+": "+l) },
		Emit: func(typ string, f map[string]any) { emitted = append(emitted, fmt.Sprintf("%s %v", typ, f["host"])) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	for i, typ := range []string{events.RunStart, events.ConnectionAttempt, events.RunEnd} {
		if err := in.Event(sharedCtx, eventJSON(t, typ, uint64(i), map[string]any{"host": "a.example", "port": 443})); err != nil {
			t.Fatal(err)
		}
	}
	if err := in.Finish(sharedCtx); err != nil {
		t.Fatal(err)
	}
	if want := "> trace:run.start\n> trace:connection.attempt\n> trace:run.end\n"; out.String() != want {
		t.Errorf("stdout %q, want %q", out.String(), want)
	}
	if errOut.String() != "finished after 3 events\n" {
		t.Errorf("stderr %q", errOut.String())
	}
	if len(emitted) != 1 || emitted[0] != "plugin.echo.seen a.example" {
		t.Errorf("emitted %v", emitted)
	}
	if len(logs) < 2 || logs[0] != "echo: started for trace" || !strings.Contains(strings.Join(logs, "\n"), "invalid type") {
		t.Errorf("logs %v", logs)
	}
}

// Init errors stop the load with the plugin's own message.
func TestInitError(t *testing.T) {
	_, err := host(t).Load(sharedCtx, pkg(t, "echo"), pluginhost.Options{Settings: map[string]string{"fail_init": "true"}})
	if err == nil || !strings.Contains(err.Error(), "refusing to start: fail_init is set") {
		t.Fatalf("err = %v", err)
	}
}

// A module that imports a host call its manifest does not permit is refused
// before any of its code runs.
func TestPermissionsCheckedBeforeRunning(t *testing.T) {
	h := host(t)
	p := pkg(t, "sneaky")
	err := h.Check(sharedCtx, p)
	if err == nil || !strings.Contains(err.Error(), `imports vpnw.write but its manifest does not ask for the "console" permission`) {
		t.Fatalf("Check: %v", err)
	}
	if _, err := h.Load(sharedCtx, p, pluginhost.Options{}); err == nil {
		t.Fatal("Load accepted it")
	}
}

// An ordinary WASI program, or something that is not WebAssembly, is not a
// plugin.
func TestNotAPlugin(t *testing.T) {
	h := host(t)
	err := h.Check(sharedCtx, pkg(t, "plain"))
	if err == nil || !strings.Contains(err.Error(), "-buildmode=c-shared") {
		t.Errorf("plain: %v", err)
	}
	p := pkg(t, "crash")
	junk := *p
	junk.Wasm = []byte("#!/bin/sh\necho hi\n")
	if err := h.Check(sharedCtx, &junk); err == nil || !strings.Contains(err.Error(), "not a valid WebAssembly module") {
		t.Errorf("junk: %v", err)
	}
}

// A panic stops the plugin for the rest of the run, with the panic's
// message; the Sink reports it once and drops later events.
func TestPanicStopsPlugin(t *testing.T) {
	in, err := host(t).Load(sharedCtx, pkg(t, "crash"), pluginhost.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var fails []string
	s := pluginhost.NewSink(in, func(name string, err error) {
		mu.Lock()
		fails = append(fails, name+": "+err.Error())
		mu.Unlock()
	})
	for i := 0; i < 5; i++ {
		s.Emit(&events.Event{Type: events.ConnectionAttempt, Run: "r", Conn: uint64(i)})
	}
	dropped, err := s.Close(5 * time.Second)
	if dropped != 0 {
		t.Errorf("dropped %d", dropped)
	}
	if err == nil || !strings.Contains(err.Error(), "assignment to entry in nil map") {
		t.Errorf("err = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(fails) != 1 || !strings.HasPrefix(fails[0], "crash: ") {
		t.Errorf("fails = %v", fails)
	}
	if err := in.Event(sharedCtx, eventJSON(t, events.RunEnd, 0, nil)); err != pluginhost.ErrStopped {
		t.Errorf("after the panic: %v", err)
	}
}

// A plugin that never returns is stopped when its budget runs out.
func TestBudgetStopsSpin(t *testing.T) {
	in, err := host(t).Load(sharedCtx, pkg(t, "spin"), pluginhost.Options{EventBudget: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	t0 := time.Now()
	err = in.Event(sharedCtx, eventJSON(t, events.RunStart, 0, nil))
	if err == nil || !strings.Contains(err.Error(), "ran past its 300ms time budget") {
		t.Fatalf("err = %v", err)
	}
	if d := time.Since(t0); d > 3*time.Second {
		t.Errorf("took %v to stop", d)
	}
	// The loop is really gone: Go's garbage collector can stop the world,
	// which it cannot while compiled plugin code spins uninterruptibly.
	gc := make(chan struct{})
	go func() { runtime.GC(); close(gc) }()
	select {
	case <-gc:
	case <-time.After(5 * time.Second):
		t.Fatal("a garbage collection could not run after the plugin was stopped")
	}
}

// An Observer that falls behind loses events, counted, and never slows the
// event bus.
func TestSlowObserverNeverBlocks(t *testing.T) {
	in, err := host(t).Load(sharedCtx, pkg(t, "slow"), pluginhost.Options{})
	if err != nil {
		t.Fatal(err)
	}
	s := pluginhost.NewSink(in, nil)
	b := events.NewBus("r", nil)
	b.Add(s)
	n := pluginhost.QueueLen + 4000
	t0 := time.Now()
	for i := 0; i < n; i++ {
		b.Emit(events.ConnectionAttempt, 1, "direct", uint64(i), map[string]any{"host": "a.example", "port": 443})
	}
	if d := time.Since(t0); d > 2*time.Second {
		t.Errorf("emitting %d events took %v", n, d)
	}
	dropped, err := s.Close(200 * time.Millisecond)
	if dropped < 3000 {
		t.Errorf("dropped %d, want most of the 4000 over the queue", dropped)
	}
	if err == nil || !strings.Contains(err.Error(), "still working through") {
		t.Errorf("err = %v", err)
	}
}

func guard(t *testing.T, opt pluginhost.Options) *pluginhost.GuardCheck {
	t.Helper()
	in, err := host(t).Load(sharedCtx, pkg(t, "blocker"), opt)
	if err != nil {
		t.Fatal(err)
	}
	g := pluginhost.NewGuard(in, nil)
	t.Cleanup(func() { g.Close() })
	return g
}

func req(host string) broker.GuardRequest {
	return broker.GuardRequest{Run: "r", Conn: 1, Path: "direct", Host: host, Port: 443, Proto: "http-connect"}
}

// A Guard refuses with its reason, lets the rest through, and reports a
// refusal without a reason as a refusal.
func TestGuardDecides(t *testing.T) {
	g := guard(t, pluginhost.Options{Settings: map[string]string{"deny": "evil.example"}})
	if deny, why, err := g.Check(sharedCtx, req("evil.example")); !deny || err != nil || why != "blocked by the test guard: evil.example" {
		t.Errorf("evil: %v %q %v", deny, why, err)
	}
	if deny, _, err := g.Check(sharedCtx, req("good.example")); deny || err != nil {
		t.Errorf("good: %v %v", deny, err)
	}
	if deny, why, err := g.Check(sharedCtx, req("quiet.example")); !deny || err != nil || why != "" {
		t.Errorf("quiet: %v %q %v", deny, why, err)
	}
	// A reason can't draw on the terminal: no escapes, line breaks or
	// reordering marks get through.
	deny, why, err := g.Check(sharedCtx, req("esc.example"))
	if !deny || err != nil || strings.ContainsAny(why, "\x1b\r\n\u202e") || !strings.Contains(why, "?[2K?vpnw") {
		t.Errorf("esc: %v %q %v", deny, why, err)
	}
}

// A hook with the wrong signature is refused at load, never called.
func TestWrongSignatureRefused(t *testing.T) {
	_, err := host(t).Load(sharedCtx, pkg(t, "badsig"), pluginhost.Options{})
	if err == nil || !strings.Contains(err.Error(), "exports vpnw_on_decide with the wrong signature; ABI 1 needs (i32, i32) -> i32") {
		t.Fatalf("err = %v", err)
	}
}

// A burst of connections makes some wait for their turn, but each decision
// gets its own budget: none is refused and the Guard keeps working.
func TestGuardBurst(t *testing.T) {
	g := guard(t, pluginhost.Options{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	refused := 0
	for i := 0; i < 2000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if deny, why, err := g.Check(sharedCtx, req("good.example")); deny || err != nil {
				mu.Lock()
				refused++
				if refused == 1 {
					t.Logf("first refusal: %q %v", why, err)
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if refused > 0 {
		t.Errorf("%d of 2000 refused", refused)
	}
	if deny, _, err := g.Check(sharedCtx, req("good.example")); deny || err != nil {
		t.Errorf("after the burst: %v %v", deny, err)
	}
}

// A Guard that runs out of time, or panics, refuses that connection and
// every connection after it: it fails closed.
func TestGuardFailsClosed(t *testing.T) {
	for _, tc := range []struct{ host, want string }{
		{"slow.example", "time budget"},
		{"boom.example", "blocker exploded on boom.example"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			var reported []string
			in, err := host(t).Load(sharedCtx, pkg(t, "blocker"), pluginhost.Options{DecideBudget: 200 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			g := pluginhost.NewGuard(in, func(n string, err error) { reported = append(reported, err.Error()) })
			defer g.Close()
			t0 := time.Now()
			deny, _, err := g.Check(sharedCtx, req(tc.host))
			if !deny || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("first: deny=%v err=%v", deny, err)
			}
			// slow.example sleeps 2 s; the 200 ms budget covers sleeping.
			if d := time.Since(t0); d > time.Second {
				t.Errorf("the refusal took %v, past the 200ms budget", d)
			}
			deny, _, err = g.Check(sharedCtx, req("good.example"))
			if !deny || err == nil {
				t.Fatalf("after the failure a good host got deny=%v err=%v", deny, err)
			}
			if len(reported) != 1 {
				t.Errorf("reported %d times: %v", len(reported), reported)
			}
		})
	}
}

// Guards are called from many broker goroutines at once; they take turns.
func TestGuardConcurrent(t *testing.T) {
	g := guard(t, pluginhost.Options{Settings: map[string]string{"deny": "evil.example"}, DecideBudget: 5 * time.Second})
	var wg sync.WaitGroup
	errs := make(chan string, 200)
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			h := "good.example"
			if i%2 == 0 {
				h = "evil.example"
			}
			deny, _, err := g.Check(sharedCtx, req(h))
			if err != nil || deny != (i%2 == 0) {
				errs <- fmt.Sprintf("%s: deny=%v err=%v", h, deny, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// An Observer's own events go into the record but never back to it.
func TestOwnEventsNotFedBack(t *testing.T) {
	var out bytes.Buffer
	b := events.NewBus("r", nil)
	mem := &events.Memory{}
	b.Add(mem)
	in, err := host(t).Load(sharedCtx, pkg(t, "echo"), pluginhost.Options{
		Stdout: &out, Emit: func(typ string, f map[string]any) { b.Emit(typ, 0, "", 0, f) },
	})
	if err != nil {
		t.Fatal(err)
	}
	s := pluginhost.NewSink(in, nil)
	b.Add(s)
	b.Emit(events.ConnectionAttempt, 1, "direct", 1, map[string]any{"host": "a.example", "port": 443})
	s.Close(5 * time.Second)
	if strings.Contains(out.String(), "plugin.echo") || !strings.Contains(out.String(), "connection.attempt") {
		t.Errorf("the plugin saw:\n%s", out.String())
	}
	var mine int
	for _, e := range mem.Snapshot() {
		if e.Type == "plugin.echo.seen" {
			mine++
		}
	}
	if mine != 1 {
		t.Errorf("%d plugin.echo.seen events recorded, want 1", mine)
	}
}

// The built-in plugins load through the same host and checks as any other.
func TestBuiltins(t *testing.T) {
	pkgs, err := builtin.Packages()
	if err != nil {
		t.Fatal(err)
	}
	h := host(t)
	names := map[string]bool{}
	for _, p := range pkgs {
		names[p.Manifest.Name] = true
		if err := h.Check(sharedCtx, p); err != nil {
			t.Errorf("%s: %v", p.Manifest.Name, err)
		}
	}
	if !names["trace"] || !names["learn"] || len(names) != 2 {
		t.Errorf("built-ins: %v", names)
	}

	// Learn turns two connections into a draft policy.
	var out bytes.Buffer
	in, err := h.Load(sharedCtx, pkgs[1], pluginhost.Options{Command: "learn", Stdout: &out, Settings: map[string]string{"name": "t"}})
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	for _, e := range [][]byte{
		eventJSON(t, events.ConnectionAttempt, 1, map[string]any{"host": "api.example", "port": 443}),
		eventJSON(t, events.ConnectionOpen, 1, map[string]any{"ip": "93.184.215.14"}),
		eventJSON(t, events.ConnectionAttempt, 2, map[string]any{"host": "evil.example", "port": 443}),
		eventJSON(t, events.PolicyDeny, 2, map[string]any{"rule": "default", "reason": "no"}),
	} {
		if err := in.Event(sharedCtx, e); err != nil {
			t.Fatal(err)
		}
	}
	if err := in.Finish(sharedCtx); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`name = "t"`, `"api.example"`, `#   "evil.example"`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("learn output lacks %q:\n%s", want, out.String())
		}
	}
}

// A second start of the same plugin comes from the compile cache and is
// much quicker than the first.
func TestCompileCache(t *testing.T) {
	dir := t.TempDir()
	p := pkg(t, "crash")
	start := func() time.Duration {
		h, err := pluginhost.New(sharedCtx, dir)
		if err != nil {
			t.Fatal(err)
		}
		defer h.Close(sharedCtx)
		t0 := time.Now()
		in, err := h.Load(sharedCtx, p, pluginhost.Options{})
		if err != nil {
			t.Fatal(err)
		}
		in.Close()
		return time.Since(t0)
	}
	cold, warm := start(), start()
	t.Logf("cold start %v, warm start %v", cold, warm)
	if warm > cold/2 && warm > 200*time.Millisecond {
		t.Errorf("warm start %v is not much quicker than cold %v", warm, cold)
	}
}

// Benchmarks for test/results: what a plugin costs.

func BenchmarkGuardDecide(b *testing.B) {
	t := &testing.T{}
	h, err := pluginhost.New(sharedCtx, cacheDir)
	if err != nil {
		b.Fatal(err)
	}
	defer h.Close(sharedCtx)
	in, err := h.Load(sharedCtx, pkg(t, "blocker"), pluginhost.Options{Settings: map[string]string{"deny": "evil.example"}})
	if err != nil {
		b.Fatal(err)
	}
	g := pluginhost.NewGuard(in, nil)
	defer g.Close()
	r := req("good.example")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if deny, _, err := g.Check(sharedCtx, r); deny || err != nil {
			b.Fatal(deny, err)
		}
	}
}

func BenchmarkObserverEvent(b *testing.B) {
	t := &testing.T{}
	h, err := pluginhost.New(sharedCtx, cacheDir)
	if err != nil {
		b.Fatal(err)
	}
	defer h.Close(sharedCtx)
	pkgs, _ := builtin.Packages()
	in, err := h.Load(sharedCtx, pkgs[0], pluginhost.Options{Settings: map[string]string{"level": "all"}, Stderr: io.Discard})
	if err != nil {
		b.Fatal(err)
	}
	defer in.Close()
	ev := eventJSON(t, events.ConnectionAttempt, 7, map[string]any{"host": "api.example", "port": 443, "proto": "http-connect"})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := in.Event(sharedCtx, ev); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLoad is a warm start: compiled code from the cache, a fresh
// instance, Init.
func BenchmarkLoadWarm(b *testing.B) {
	pkgs, _ := builtin.Packages()
	dir := b.TempDir()
	for i := 0; i < b.N+1; i++ {
		if i == 1 {
			b.ResetTimer()
		}
		h, err := pluginhost.New(sharedCtx, dir)
		if err != nil {
			b.Fatal(err)
		}
		in, err := h.Load(sharedCtx, pkgs[0], pluginhost.Options{})
		if err != nil {
			b.Fatal(err)
		}
		in.Close()
		h.Close(sharedCtx)
	}
}
