// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package pluginhost loads and runs VPN Works plugins: WebAssembly modules
// run by wazero, a pure-Go runtime, inside vpnw's own process.
//
// A plugin gets no files, no network, no environment and no arguments. It
// can reach vpnw only through the host calls in the "vpnw" module, and only
// those its manifest asks for: a module that imports anything else is
// refused before it runs. Plugins decide and observe; they never carry
// traffic.
//
// Failure rules:
//
//   - A plugin that traps, panics or exits is stopped for the rest of the
//     run, the run carries on, and the failure is reported.
//   - A call that runs past its time budget is interrupted and the plugin
//     stopped the same way. The runtime checks for that at every function
//     call and loop, which costs plugin code speed (four to five times, in
//     our measurements) but is the only safe way: code that cannot be
//     interrupted also cannot be paused by Go's garbage collector, and one
//     endless loop would freeze vpnw.
//   - A Guard that fails or runs out of time refuses the connection it was
//     asked about, and every one after it (fail closed).
//   - An Observer that falls behind loses events, never slows the broker;
//     the loss is counted and reported.
package pluginhost

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
)

// MemoryPages caps each plugin's memory: 2048 pages of 64 KiB is 128 MiB.
const MemoryPages = 2048

// Default time budgets for one call into a plugin.
const (
	InitBudget   = 10 * time.Second
	EventBudget  = 5 * time.Second
	FinishBudget = 60 * time.Second
	DecideBudget = 250 * time.Millisecond
)

// Package is a plugin ready to load: its manifest and its module.
type Package struct {
	Manifest    *Manifest
	ManifestSrc []byte
	Wasm        []byte
	// Source is "built-in" or the directory it was installed in.
	Source  string
	Builtin bool
	// Signer is the key that signed it, or "" (built-ins and unsigned).
	Signer string
}

// Options says how one loaded plugin meets the rest of vpnw.
type Options struct {
	Command  string
	Settings map[string]string
	Color    bool
	// Stdout and Stderr receive what the plugin writes, if it has the
	// console permission. Nil discards.
	Stdout, Stderr io.Writer
	// Log receives the plugin's log lines. Nil discards.
	Log func(plugin, line string)
	// Emit adds a plugin's event to the run, if it has events.emit. The
	// type is already "plugin.<name>.<type>".
	Emit func(typ string, fields map[string]any)
	// DecideBudget and EventBudget override the time budgets for one Guard
	// decision and one event; zero is the default.
	DecideBudget time.Duration
	EventBudget  time.Duration
}

// Host runs plugins. One Host serves every plugin of a vpnw command.
type Host struct {
	rt wazero.Runtime

	mu  sync.Mutex
	seq int
	by  map[string]*Instance // module name -> instance, for host calls
}

// New starts a plugin host. cacheDir, if not empty, keeps compiled plugins
// between runs, which cuts a plugin's start from about a second to tens of
// milliseconds; a cache that cannot be opened is skipped.
func New(ctx context.Context, cacheDir string) (*Host, error) {
	cfg := wazero.NewRuntimeConfig().WithCloseOnContextDone(true).WithMemoryLimitPages(MemoryPages)
	if cacheDir != "" {
		if c, err := wazero.NewCompilationCacheWithDir(cacheDir); err == nil {
			cfg = cfg.WithCompilationCache(c)
		}
	}
	h := &Host{rt: wazero.NewRuntimeWithConfig(ctx, cfg), by: map[string]*Instance{}}
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, h.rt); err != nil {
		h.rt.Close(ctx)
		return nil, err
	}
	if err := h.hostModule(ctx, h.rt); err != nil {
		h.rt.Close(ctx)
		return nil, err
	}
	return h, nil
}

// Close stops every plugin and frees the host.
func (h *Host) Close(ctx context.Context) error { return h.rt.Close(ctx) }

func (h *Host) instance(m api.Module) *Instance {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.by[m.Name()]
}

func read(m api.Module, p, n uint32) []byte {
	b, ok := m.Memory().Read(p, n)
	if !ok {
		return nil
	}
	return append([]byte(nil), b...)
}

// Host calls. Each looks up the instance that made it; the permission was
// checked when the module was loaded, and is checked again here.
func (h *Host) hostModule(ctx context.Context, rt wazero.Runtime) error {
	b := rt.NewHostModuleBuilder("vpnw")
	b.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, p, n uint32) {
		if in := h.instance(m); in != nil && in.opt.Log != nil {
			in.opt.Log(in.Name(), clean(strings.TrimRight(string(read(m, p, min(n, 64<<10))), "\n"), 2000))
		}
	}).Export("log")
	b.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, p, n uint32) {
		if in := h.instance(m); in != nil {
			in.errMsg = clean(string(read(m, p, min(n, 4<<10))), 500)
		}
	}).Export("error")
	b.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, p, n uint32) {
		if in := h.instance(m); in != nil {
			in.reason = clean(string(read(m, p, min(n, 1<<10))), 300)
		}
	}).Export("reason")
	b.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, stream, p, n uint32) {
		in := h.instance(m)
		if in == nil || !in.pkg.Manifest.Has(PermConsole) {
			return
		}
		w := in.opt.Stdout
		if stream == 2 {
			w = in.opt.Stderr
		}
		if w != nil {
			w.Write(read(m, p, n))
		}
	}).Export("write")
	b.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, p, n uint32) {
		in := h.instance(m)
		if in == nil || !in.pkg.Manifest.Has(PermEmit) || in.opt.Emit == nil {
			return
		}
		in.emit(read(m, p, min(n, 64<<10)))
	}).Export("emit")
	_, err := b.Instantiate(ctx)
	return err
}

var emitTypeRe = regexp.MustCompile(`^[a-z0-9_]{1,32}(\.[a-z0-9_]{1,32}){0,2}$`)

func (in *Instance) emit(b []byte) {
	var e struct {
		Type   string         `json:"type"`
		Fields map[string]any `json:"fields"`
	}
	if json.Unmarshal(b, &e) != nil || !emitTypeRe.MatchString(e.Type) {
		if in.opt.Log != nil {
			in.opt.Log(in.Name(), "dropped an event with an invalid type")
		}
		return
	}
	f, _ := cleanValue(e.Fields).(map[string]any)
	in.opt.Emit("plugin."+in.Name()+"."+e.Type, f)
}

// The host calls any plugin may import, and the ones that need a permission.
var hostCalls = map[string]string{
	"log": "", "error": "", "reason": "",
	"write": PermConsole,
	"emit":  PermEmit,
}

// Exports every plugin has, and those each type needs.
var (
	baseExports = []string{"_initialize", "vpnw_abi", "vpnw_alloc", "vpnw_init"}
	typeExports = map[string][]string{
		Observer: {"vpnw_on_event"},
		Advisor:  {"vpnw_on_event", "vpnw_finish"},
		Guard:    {"vpnw_on_decide"},
	}
)

// The signature of every export vpnw calls: parameters, then results, all
// i32. A module whose export has another signature is refused, since vpnw
// would read results that are not there.
var exportSigs = map[string][2]int{
	"_initialize":    {0, 0},
	"vpnw_abi":       {0, 1},
	"vpnw_alloc":     {1, 1},
	"vpnw_init":      {2, 1},
	"vpnw_on_event":  {2, 1},
	"vpnw_on_decide": {2, 1},
	"vpnw_finish":    {0, 1},
}

func sigOK(f api.FunctionDefinition, want [2]int) bool {
	ps, rs := f.ParamTypes(), f.ResultTypes()
	if len(ps) != want[0] || len(rs) != want[1] {
		return false
	}
	for _, t := range append(append([]api.ValueType{}, ps...), rs...) {
		if t != api.ValueTypeI32 {
			return false
		}
	}
	return true
}

func sigText(want [2]int) string {
	p := strings.TrimSuffix(strings.Repeat("i32, ", want[0]), ", ")
	if want[1] == 0 {
		return "(" + p + ")"
	}
	return "(" + p + ") -> i32"
}

// check refuses a module that imports something its manifest does not
// permit, or lacks what its type needs.
func check(cm wazero.CompiledModule, m *Manifest) error {
	for _, f := range cm.ImportedFunctions() {
		mod, name, _ := f.Import()
		switch mod {
		case wasi_snapshot_preview1.ModuleName:
			// The WASI system interface, with no files, sockets,
			// environment or arguments behind it.
		case "vpnw":
			perm, ok := hostCalls[name]
			if !ok {
				return fmt.Errorf("imports vpnw.%s, which this vpnw does not have", name)
			}
			if perm != "" && !m.Has(perm) {
				return fmt.Errorf("imports vpnw.%s but its manifest does not ask for the %q permission", name, perm)
			}
		default:
			return fmt.Errorf("imports %s.%s; plugins may only import from vpnw and WASI", mod, name)
		}
	}
	if len(cm.ImportedMemories()) > 0 {
		return errors.New("imports a memory; a plugin brings its own")
	}
	ex := cm.ExportedFunctions()
	for _, want := range append(append([]string{}, baseExports...), typeExports[m.Type]...) {
		if _, ok := ex[want]; !ok {
			if want == "_initialize" {
				return errors.New("is not a WASI library (no _initialize); build it with -buildmode=c-shared")
			}
			return fmt.Errorf("does not export %s, which %s plugin needs; build it with the VPN Works plugin SDK", want, article(m.Type))
		}
	}
	// Every hook vpnw may call, needed or not, must have the right shape.
	for name, sig := range exportSigs {
		if f, ok := ex[name]; ok && !sigOK(f, sig) {
			return fmt.Errorf("exports %s with the wrong signature; ABI %d needs %s", name, ABI, sigText(sig))
		}
	}
	if _, ok := cm.ExportedMemories()["memory"]; !ok {
		return errors.New("exports no memory")
	}
	return nil
}

// Check compiles a package and checks it against its manifest without
// running any of its code.
func (h *Host) Check(ctx context.Context, pkg *Package) error {
	cm, err := h.rt.CompileModule(ctx, pkg.Wasm)
	if err != nil {
		return fmt.Errorf("plugin %s: not a valid WebAssembly module: %v", pkg.Manifest.Name, err)
	}
	defer cm.Close(ctx)
	if err := check(cm, pkg.Manifest); err != nil {
		return fmt.Errorf("plugin %s %v", pkg.Manifest.Name, err)
	}
	return nil
}

// Instance is one running plugin. Calls into it are taken one at a time.
type Instance struct {
	h      *Host
	pkg    *Package
	opt    Options
	mod    api.Module
	name   string
	turn   chan struct{}
	closed atomic.Bool // set by Close; no call starts after it

	dmu    sync.Mutex
	dead   error
	errMsg string
	reason string
	stderr *tail

	alloc, initFn, event, decide, finish api.Function

	cm wazero.CompiledModule
	// deadline is when the call running now must end, in Unix nanoseconds,
	// or 0. A plugin's sleep never runs past it.
	deadline atomic.Int64
}

// Load compiles, checks, starts and initialises a plugin.
func (h *Host) Load(ctx context.Context, pkg *Package, opt Options) (*Instance, error) {
	m := pkg.Manifest
	cm, err := h.rt.CompileModule(ctx, pkg.Wasm)
	if err != nil {
		return nil, fmt.Errorf("plugin %s: not a valid WebAssembly module: %v", m.Name, err)
	}
	if err := check(cm, m); err != nil {
		cm.Close(ctx)
		return nil, fmt.Errorf("plugin %s %v", m.Name, err)
	}
	h.mu.Lock()
	h.seq++
	name := fmt.Sprintf("plugin-%s-%d", m.Name, h.seq)
	in := &Instance{h: h, pkg: pkg, opt: opt, name: name, cm: cm, turn: make(chan struct{}, 1), stderr: &tail{max: 4 << 10}}
	h.by[name] = in
	h.mu.Unlock()

	mc := wazero.NewModuleConfig().WithName(name).WithStartFunctions("_initialize").
		WithSysWalltime().WithSysNanotime().WithNanosleep(in.sleep).WithRandSource(crand.Reader).
		WithStdout(io.Discard).WithStderr(in.stderr)
	ictx, cancel := context.WithTimeout(ctx, InitBudget)
	in.deadline.Store(time.Now().Add(InitBudget).UnixNano())
	mod, err := h.rt.InstantiateModule(ictx, cm, mc)
	in.deadline.Store(0)
	cancel()
	if err != nil {
		h.forget(name)
		cm.Close(context.Background())
		return nil, fmt.Errorf("plugin %s failed to start: %v", m.Name, in.explain(err))
	}
	in.mod = mod
	in.alloc = mod.ExportedFunction("vpnw_alloc")
	in.initFn = mod.ExportedFunction("vpnw_init")
	in.event = mod.ExportedFunction("vpnw_on_event")
	in.decide = mod.ExportedFunction("vpnw_on_decide")
	in.finish = mod.ExportedFunction("vpnw_finish")

	in.turn <- struct{}{}
	res, err := in.call(ctx, InitBudget, mod.ExportedFunction("vpnw_abi"))
	if err == nil && res[0] != ABI {
		err = fmt.Errorf("speaks plugin ABI %d; this vpnw runs ABI %d", uint32(res[0]), ABI)
	}
	if err == nil {
		zone, off := time.Now().Zone()
		cfg, _ := json.Marshal(map[string]any{
			"plugin": m.Name, "command": opt.Command, "settings": nonNil(opt.Settings),
			"color": opt.Color, "tz_offset": off, "tz_name": zone,
		})
		var code uint32
		code, err = in.pass(ctx, InitBudget, in.initFn, cfg)
		if err == nil && code != 0 {
			err = in.pluginErr()
		}
	}
	<-in.turn
	if err != nil {
		in.Close()
		return nil, fmt.Errorf("plugin %s: %v", m.Name, err)
	}
	return in, nil
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func (h *Host) forget(name string) {
	h.mu.Lock()
	delete(h.by, name)
	h.mu.Unlock()
}

// Name is the plugin's name; Manifest its manifest; Package what it was
// loaded from.
func (in *Instance) Name() string        { return in.pkg.Manifest.Name }
func (in *Instance) Manifest() *Manifest { return in.pkg.Manifest }
func (in *Instance) Package() *Package   { return in.pkg }

// ErrStopped is returned for calls into a plugin that already failed.
var ErrStopped = errors.New("stopped after an earlier failure")

// ErrClosed is what a call gets after Close, at the end of a run. It isn't
// the plugin's failure.
var ErrClosed = errors.New("closed at the end of the run")

// sleep is the plugin's only way to pause. The runtime can interrupt
// running code but not a sleep in progress, so a sleep never lasts past the
// end of the current call's budget; the code after it is then interrupted.
func (in *Instance) sleep(ns int64) {
	if dl := in.deadline.Load(); dl != 0 {
		if left := dl - time.Now().UnixNano(); left < ns {
			ns = max(left, 0)
		}
	}
	if ns > 0 {
		time.Sleep(time.Duration(ns))
	}
}

// call runs fn with the turn held. A failure stops the plugin for good.
// Every hook returns one i32, which check made sure of.
func (in *Instance) call(ctx context.Context, budget time.Duration, fn api.Function, args ...uint64) ([]uint64, error) {
	if in.Err() != nil {
		return nil, ErrStopped
	}
	cctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	if dl, ok := cctx.Deadline(); ok {
		in.deadline.Store(dl.UnixNano())
	}
	res, err := fn.Call(cctx, args...)
	in.deadline.Store(0)
	if err == nil && len(res) != 1 {
		err = fmt.Errorf("returned %d values where ABI %d has one", len(res), ABI)
		in.stop(err)
		in.mod.Close(context.Background())
		return nil, err
	}
	if err != nil {
		if cctx.Err() == context.DeadlineExceeded {
			err = fmt.Errorf("ran past its %v time budget", budget)
		} else {
			err = in.explain(err)
		}
		in.stop(err)
		in.mod.Close(context.Background())
		return nil, err
	}
	return res, nil
}

// pass copies data into the plugin and calls fn(ptr, len). A result of 1
// means the plugin reported an error through the error host call.
func (in *Instance) pass(ctx context.Context, budget time.Duration, fn api.Function, data []byte) (uint32, error) {
	res, err := in.call(ctx, budget, in.alloc, uint64(len(data)))
	if err != nil {
		return 0, err
	}
	p := uint32(res[0])
	if !in.mod.Memory().Write(p, data) {
		return 0, in.stop(errors.New("gave a buffer outside its memory"))
	}
	in.errMsg, in.reason = "", ""
	res, err = in.call(ctx, budget, fn, uint64(p), uint64(len(data)))
	if err != nil {
		return 0, err
	}
	return uint32(res[0]), nil
}

// explain turns a trap into one line: the panic message the plugin printed,
// if it printed one, else the first line of the runtime's error.
func (in *Instance) explain(err error) error {
	msg, _, _ := strings.Cut(err.Error(), "\n")
	var ee *sys.ExitError
	if errors.As(err, &ee) {
		msg = fmt.Sprintf("exited with code %d", ee.ExitCode())
	}
	for _, l := range strings.Split(in.stderr.String(), "\n") {
		if l = strings.TrimSpace(l); strings.HasPrefix(l, "panic: ") || strings.HasPrefix(l, "fatal error: ") {
			return errors.New(clean(l, 500))
		}
	}
	return errors.New(clean(msg, 500))
}

// take waits for the plugin's turn. A stopped or closed plugin is refused
// at once.
func (in *Instance) take(ctx context.Context) error {
	if in.Err() != nil {
		return ErrStopped
	}
	if in.closed.Load() {
		return ErrClosed
	}
	select {
	case in.turn <- struct{}{}:
		if in.closed.Load() {
			<-in.turn
			return ErrClosed
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Event hands the plugin one event, as a JSON object.
func (in *Instance) Event(ctx context.Context, ev []byte) error {
	if err := in.take(ctx); err != nil {
		return err
	}
	defer func() { <-in.turn }()
	budget := in.opt.EventBudget
	if budget == 0 {
		budget = EventBudget
	}
	code, err := in.pass(ctx, budget, in.event, ev)
	if err == nil && code != 0 {
		err = in.pluginErr()
	}
	return err
}

func (in *Instance) pluginErr() error {
	msg := in.errMsg
	if msg == "" {
		msg = "reported an error"
	}
	return in.stop(errors.New(msg))
}

// Finish tells the plugin the events are over.
func (in *Instance) Finish(ctx context.Context) error {
	if in.finish == nil {
		return nil
	}
	if err := in.take(ctx); err != nil {
		return err
	}
	defer func() { <-in.turn }()
	res, err := in.call(ctx, FinishBudget, in.finish)
	if err == nil && uint32(res[0]) != 0 {
		err = in.pluginErr()
	}
	return err
}

// DecideWait is how long a Guard request waits for the plugin's turn when
// many connections ask at once. A request that waits longer is refused, but
// the plugin is not stopped: it was busy, not broken.
const DecideWait = 5 * time.Second

// Decide asks a Guard about one connection. Any failure of the plugin is an
// error, which the caller treats as a refusal.
func (in *Instance) Decide(ctx context.Context, req any) (deny bool, reason string, err error) {
	budget := in.opt.DecideBudget
	if budget == 0 {
		budget = DecideBudget
	}
	wctx, cancel := context.WithTimeout(ctx, DecideWait)
	err = in.take(wctx)
	cancel()
	switch {
	case err == ErrStopped || err == ErrClosed:
		return true, "", err
	case err != nil:
		return true, fmt.Sprintf("guard plugin %s was busy: no turn within %v", in.Name(), DecideWait), nil
	}
	defer func() { <-in.turn }()
	b, err := json.Marshal(req)
	if err != nil {
		return true, "", err
	}
	code, err := in.pass(ctx, budget, in.decide, b)
	switch {
	case err != nil:
		return true, "", err
	case code == 0:
		return false, "", nil
	case code == 1:
		return true, in.reason, nil
	default:
		return true, "", in.pluginErr()
	}
}

// Close stops the plugin. It waits for a call in flight to end first,
// which its time budget bounds: closing a module while a call is still
// running in it is a data race.
func (in *Instance) Close() {
	if in.closed.Swap(true) {
		return
	}
	in.turn <- struct{}{}
	defer func() { <-in.turn }()
	if in.mod != nil {
		in.mod.Close(context.Background())
	}
	if in.cm != nil {
		in.cm.Close(context.Background())
	}
	in.h.forget(in.name)
}

// Err is the failure that stopped the plugin, or nil.
func (in *Instance) Err() error {
	in.dmu.Lock()
	defer in.dmu.Unlock()
	return in.dead
}

func (in *Instance) stop(err error) error {
	in.dmu.Lock()
	if in.dead == nil {
		in.dead = err
	}
	in.dmu.Unlock()
	return err
}

// tail keeps the start of what a plugin writes to its own standard error,
// where the Go runtime prints a panic.
type tail struct {
	mu  sync.Mutex
	b   []byte
	max int
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if room := t.max - len(t.b); room > 0 {
		t.b = append(t.b, p[:min(len(p), room)]...)
	}
	return len(p), nil
}

func (t *tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.b)
}

func article(t string) string {
	if t == Observer || t == Advisor {
		return "an " + t
	}
	return "a " + t
}
