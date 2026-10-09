// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/VPNWorks/vpnw/internal/broker"
	"github.com/VPNWorks/vpnw/internal/events"
	"github.com/VPNWorks/vpnw/internal/pluginhost"
	"github.com/VPNWorks/vpnw/internal/process"
	"github.com/VPNWorks/vpnw/plugins/builtin"
)

// sinkGrace is how long an Observer gets, after the run, to work through
// the events still queued for it.
const sinkGrace = 5 * time.Second

func openStore() (*pluginhost.Store, error) {
	b, err := builtin.Packages()
	if err != nil {
		return nil, err
	}
	return pluginhost.DefaultStore(b)
}

func openHost() (*pluginhost.Host, error) {
	return pluginhost.New(context.Background(), pluginhost.CacheDir())
}

var setRe = regexp.MustCompile(`^([a-z][a-z0-9-]*)\.([A-Za-z0-9_.-]+)=(.*)$`)

// parseSets reads --set NAME.KEY=VALUE (or KEY=VALUE when named is false).
func parseSets(sets []string, named bool) (map[string]map[string]string, error) {
	out := map[string]map[string]string{}
	for _, s := range sets {
		if !named {
			k, v, ok := strings.Cut(s, "=")
			if !ok || k == "" {
				return nil, fmt.Errorf("--set %q: give KEY=VALUE", s)
			}
			if out[""] == nil {
				out[""] = map[string]string{}
			}
			out[""][k] = v
			continue
		}
		m := setRe.FindStringSubmatch(s)
		if m == nil {
			return nil, fmt.Errorf("--set %q: give PLUGIN.KEY=VALUE, as in --set trace.level=all", s)
		}
		if out[m[1]] == nil {
			out[m[1]] = map[string]string{}
		}
		out[m[1]][m[2]] = m[3]
	}
	return out, nil
}

// pluginRun holds the plugins of one run, trace or guard.
type pluginRun struct {
	mode     string
	bus      *events.Bus
	stderr   io.Writer
	settings map[string]map[string]string
	verbose  bool

	host   *pluginhost.Host
	store  *pluginhost.Store
	cons   *pluginhost.Sink
	sinks  []*pluginhost.Sink
	guards []*pluginhost.GuardCheck
	used   map[string]bool
	mu     sync.Mutex
	closed bool
}

func (r *pluginRun) open() error {
	if r.host != nil {
		return nil
	}
	st, err := openStore()
	if err != nil {
		return err
	}
	h, err := openHost()
	if err != nil {
		return fmt.Errorf("cannot start the plugin host: %v", err)
	}
	r.store, r.host, r.used = st, h, map[string]bool{}
	return nil
}

func (r *pluginRun) options(name string) pluginhost.Options {
	return pluginhost.Options{
		Command:  r.mode,
		Settings: r.settings[name],
		Color:    colorOK(r.stderr),
		Stdout:   r.stderr, // a run's standard output belongs to the program
		Stderr:   r.stderr,
		Log:      r.log,
		Emit: func(typ string, f map[string]any) {
			r.bus.Emit(typ, 0, "", 0, f)
		},
	}
}

func (r *pluginRun) log(plugin, line string) {
	if r.verbose {
		fmt.Fprintf(r.stderr, "vpnw: [%s] %s\n", plugin, line)
	}
}

// failed reports a plugin that stopped: as an event in the record and, unless
// the console is still there to print that event, straight to stderr.
func (r *pluginRun) failed(kind string) func(string, error) {
	return func(name string, err error) {
		r.bus.Emit(events.PluginError, 0, "", 0, map[string]any{"plugin": name, "type": kind, "error": err.Error()})
		if r.cons == nil || r.cons.Name() == name {
			fmt.Fprintf(r.stderr, "vpnw: %s plugin %s stopped: %v\n", kind, name, err)
		}
	}
}

// console loads the built-in Trace plugin as the run's console output.
func (r *pluginRun) console(set map[string]string) error {
	if err := r.open(); err != nil {
		return err
	}
	r.used["trace"] = true
	pkg, err := r.store.Find("trace")
	if err != nil {
		return err
	}
	opt := r.options("trace")
	opt.Settings = set
	in, err := r.host.Load(context.Background(), pkg, opt)
	if err != nil {
		return err
	}
	r.cons = pluginhost.NewSink(in, r.failed(pluginhost.Observer))
	r.bus.Add(r.cons)
	return nil
}

// attach loads a --plugin: an Observer joins the event bus, a Guard stands
// in front of the broker.
func (r *pluginRun) attach(name string) error {
	if err := r.open(); err != nil {
		return err
	}
	if r.used[name] {
		if name == "trace" {
			return errors.New("trace already prints this run's events; use --set trace.level=all to see them all")
		}
		return fmt.Errorf("--plugin %s is given twice", name)
	}
	pkg, err := r.store.Find(name)
	if err != nil {
		return err
	}
	switch pkg.Manifest.Type {
	case pluginhost.Observer, pluginhost.Guard:
	case pluginhost.Advisor:
		return fmt.Errorf("%s is an advisor plugin; run it on a trace with vpnw advise %s", name, name)
	}
	in, err := r.host.Load(context.Background(), pkg, r.options(name))
	if err != nil {
		return err
	}
	r.used[name] = true
	if pkg.Manifest.Type == pluginhost.Guard {
		r.guards = append(r.guards, pluginhost.NewGuard(in, r.failed(pluginhost.Guard)))
		return nil
	}
	s := pluginhost.NewSink(in, r.failed(pluginhost.Observer))
	r.sinks = append(r.sinks, s)
	r.bus.Add(s)
	return nil
}

// unused refuses --set for a plugin that is not part of the run.
func (r *pluginRun) unused() error {
	for name := range r.settings {
		if !r.used[name] {
			if name == "trace" {
				return errors.New("--set trace.…: this run prints no console (run without -v, or with -q or --json), so there is no trace plugin to set")
			}
			return fmt.Errorf("--set %s.…: plugin %s is not used in this run", name, name)
		}
	}
	return nil
}

func (r *pluginRun) brokerGuards() []broker.Guard {
	var g []broker.Guard
	for _, x := range r.guards {
		g = append(g, x)
	}
	return g
}

func (r *pluginRun) names() []string {
	var n []string
	for name := range r.used {
		n = append(n, name)
	}
	sort.Strings(n)
	return n
}

// close finishes every plugin: Observers get the rest of their events and
// Finish, the console last so it prints the others' reports.
func (r *pluginRun) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.host == nil {
		r.closed = true
		return
	}
	r.closed = true
	for _, g := range r.guards {
		g.Close()
	}
	for _, s := range r.sinks {
		if n, _ := s.Close(sinkGrace); n > 0 {
			fmt.Fprintf(r.stderr, "vpnw: observer plugin %s fell behind and missed %d events\n", s.Name(), n)
		}
	}
	if r.cons != nil {
		if n, _ := r.cons.Close(sinkGrace); n > 0 {
			fmt.Fprintf(r.stderr, "vpnw: the console fell behind and left out %d events (the saved trace has them all)\n", n)
		}
	}
	r.host.Close(context.Background())
}

// readTraces reads events from trace files ("last" is the last saved trace).
func readTraces(from []string) ([]events.Event, error) {
	if len(from) == 0 {
		from = []string{"last"}
	}
	var all []events.Event
	for _, fn := range from {
		if fn == "last" {
			dir, err := stateDir()
			if err != nil {
				return nil, err
			}
			fn = filepath.Join(dir, "last.jsonl")
		}
		f, err := os.Open(fn)
		if err != nil {
			return nil, fmt.Errorf("cannot read trace %s: %v", fn, err)
		}
		evs, err := events.Read(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %v", fn, err)
		}
		all = append(all, evs...)
	}
	return all, nil
}

// advise runs an Advisor plugin over traces and returns what it wrote to
// standard output.
func advise(name string, from []string, set map[string]string, command string, stderr io.Writer) ([]byte, error) {
	evs, err := readTraces(from)
	if err != nil {
		return nil, err
	}
	st, err := openStore()
	if err != nil {
		return nil, err
	}
	pkg, err := st.Find(name)
	if err != nil {
		return nil, err
	}
	if pkg.Manifest.Type != pluginhost.Advisor {
		return nil, fmt.Errorf("%s is %s plugin; advise runs advisor plugins (see vpnw plugin list)", name, article(pkg.Manifest.Type))
	}
	h, err := openHost()
	if err != nil {
		return nil, fmt.Errorf("cannot start the plugin host: %v", err)
	}
	ctx := context.Background()
	defer h.Close(ctx)
	var out bytes.Buffer
	in, err := h.Load(ctx, pkg, pluginhost.Options{Command: command, Settings: set, Color: colorOK(stderr), Stdout: &out, Stderr: stderr})
	if err != nil {
		return nil, err
	}
	defer in.Close()
	for i := range evs {
		b, err := jsonEvent(&evs[i])
		if err != nil {
			return nil, err
		}
		if err := in.Event(ctx, b); err != nil {
			return nil, fmt.Errorf("plugin %s stopped: %v", name, err)
		}
	}
	if err := in.Finish(ctx); err != nil {
		return nil, fmt.Errorf("plugin %s stopped: %v", name, err)
	}
	return out.Bytes(), nil
}

func jsonEvent(e *events.Event) ([]byte, error) { return json.Marshal(e) }

func article(t string) string {
	if t == "observer" || t == "advisor" {
		return "an " + t
	}
	return "a " + t
}

func learnCmd(args []string, stdout, stderr io.Writer) int {
	var from multi
	var name, outFile string
	var ports, wild bool
	fs := flag.NewFlagSet("vpnw learn", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Var(&from, "from", "")
	fs.StringVar(&name, "name", "", "")
	fs.StringVar(&outFile, "o", "", "")
	fs.BoolVar(&ports, "ports", false, "")
	fs.BoolVar(&wild, "wildcards", false, "")
	if err := fs.Parse(args); err != nil {
		return fail(stderr, process.ExitConfig, "%v; usage: vpnw learn [--from last|FILE] [--name NAME] [--ports] [--wildcards] [-o FILE]", err)
	}
	from = append(from, fs.Args()...)
	set := map[string]string{"name": name}
	if ports {
		set["ports"] = "true"
	}
	if wild {
		set["wildcards"] = "true"
	}
	if outFile != "" {
		set["summary"] = "true"
	}
	out, err := advise("learn", from, set, "learn", stderr)
	if err != nil {
		return fail(stderr, process.ExitConfig, "%v", err)
	}
	return writeAdvice(out, outFile, stdout, stderr)
}

func writeAdvice(out []byte, outFile string, stdout, stderr io.Writer) int {
	if outFile == "" {
		stdout.Write(out)
		return 0
	}
	if err := os.WriteFile(outFile, out, 0o644); err != nil {
		return fail(stderr, process.ExitConfig, "%v", err)
	}
	fmt.Fprintf(stderr, "vpnw: wrote %s\n", outFile)
	return 0
}

func adviseCmd(args []string, stdout, stderr io.Writer) int {
	const use = "usage: vpnw advise PLUGIN [--from last|FILE]... [--set KEY=VALUE]... [-o FILE]"
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return fail(stderr, process.ExitConfig, use)
	}
	name := args[0]
	var from, sets multi
	var outFile string
	fs := flag.NewFlagSet("vpnw advise", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Var(&from, "from", "")
	fs.Var(&sets, "set", "")
	fs.StringVar(&outFile, "o", "", "")
	if err := fs.Parse(args[1:]); err != nil {
		return fail(stderr, process.ExitConfig, "%v; %s", err, use)
	}
	from = append(from, fs.Args()...)
	set, err := parseSets(sets, false)
	if err != nil {
		return fail(stderr, process.ExitConfig, "%v", err)
	}
	out, err := advise(name, from, set[""], "advise", stderr)
	if err != nil {
		return fail(stderr, process.ExitConfig, "%v", err)
	}
	return writeAdvice(out, outFile, stdout, stderr)
}
