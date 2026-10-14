// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
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
	"unicode/utf8"

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
	files    map[string]string // --plugin-file NAME=PATH
	folders  map[string]string // --plugin-folder NAME=PATH
	opened   []*os.File
	dirs     []pluginhost.Folder
	tunnel   *pluginhost.TunnelPlugin

	host   *pluginhost.Host
	store  *pluginhost.Store
	cons   *pluginhost.Sink
	sinks  []*pluginhost.Sink
	guards []*pluginhost.GuardCheck
	used   map[string]bool
	mans   map[string]*pluginhost.Manifest // of the plugins used
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
	r.store, r.host, r.used, r.mans = st, h, map[string]bool{}, map[string]*pluginhost.Manifest{}
	return nil
}

func (r *pluginRun) options(name string) pluginhost.Options {
	return pluginhost.Options{
		Run:      r.bus.Run(),
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
	r.mans["trace"] = pkg.Manifest
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
		if r.tunnel != nil && r.tunnel.Name() == name {
			return fmt.Errorf("%s is a tunnel plugin and already the path, with --tunnel %s", name, name)
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
	case pluginhost.Tunnel:
		if r.mode == "exit" {
			return fmt.Errorf("%s is a tunnel plugin; tunnel plugins hand a run its WireGuard configs, with vpnw run, trace or guard --tunnel %s", name, name)
		}
		return fmt.Errorf("%s is a tunnel plugin; use it as the path, with --tunnel %s", name, name)
	}
	in, err := r.load(name, pkg)
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

// load starts a plugin with what its manifest asks for: its file, its
// folder.
func (r *pluginRun) load(name string, pkg *pluginhost.Package) (*pluginhost.Instance, error) {
	r.mans[name] = pkg.Manifest
	opt := r.options(name)
	if pkg.Manifest.Has(pluginhost.PermFile) {
		f, fn, err := r.openFile(name)
		if err != nil {
			return nil, err
		}
		opt.File, opt.FileName = f, fn
	} else if _, ok := r.files[name]; ok {
		return nil, fmt.Errorf("--plugin-file %s=…: plugin %s doesn't ask for a file (file.write)", name, name)
	}
	if pkg.Manifest.Has(pluginhost.PermFolder) {
		d, dn, err := r.openFolder(name)
		if err != nil {
			r.dropFile(opt)
			return nil, err
		}
		opt.Folder, opt.FolderName = d, dn
	} else if _, ok := r.folders[name]; ok {
		r.dropFile(opt)
		return nil, fmt.Errorf("--plugin-folder %s=…: plugin %s doesn't ask for a folder (folder.read)", name, name)
	}
	in, err := r.host.Load(context.Background(), pkg, opt)
	if err != nil {
		r.dropFile(opt)
		return nil, err
	}
	return in, nil
}

// dropFile removes the file opened for a plugin that never started, so no
// empty file is left behind.
func (r *pluginRun) dropFile(opt pluginhost.Options) {
	if f, ok := opt.File.(*os.File); ok {
		r.opened = r.opened[:len(r.opened)-1]
		f.Close()
		os.Remove(opt.FileName)
	}
}

// tunnelSource loads a tunnel plugin to hand the run its WireGuard configs.
func (r *pluginRun) tunnelSource(name string) (*pluginhost.TunnelPlugin, error) {
	if err := r.open(); err != nil {
		return nil, err
	}
	pkg, err := r.store.Find(name)
	if err != nil {
		return nil, err
	}
	if pkg.Manifest.Type != pluginhost.Tunnel {
		return nil, fmt.Errorf("--tunnel %s: %s is %s plugin; --tunnel takes a tunnel plugin, such as the built-in rotate", name, name, article(pkg.Manifest.Type))
	}
	in, err := r.load(name, pkg)
	if err != nil {
		return nil, err
	}
	r.used[name] = true
	r.tunnel = pluginhost.NewTunnel(in)
	return r.tunnel, nil
}

// openFolder opens the folder a plugin with the folder.read permission
// reads: --plugin-folder NAME=PATH, or ~/.config/vpnw/NAME.
func (r *pluginRun) openFolder(name string) (pluginhost.Folder, string, error) {
	dir, given := r.folders[name]
	if !given {
		dir = filepath.Join(r.store.ConfigDir, name)
	}
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	d, err := pluginhost.OpenFolder(dir)
	if err != nil {
		if !given && errors.Is(err, os.ErrNotExist) {
			return nil, "", fmt.Errorf("plugin %s reads the files in a folder, and %s doesn't exist; make it, or give another with --plugin-folder %s=PATH", name, dir, name)
		}
		return nil, "", fmt.Errorf("plugin %s's folder: %v", name, err)
	}
	r.dirs = append(r.dirs, d)
	return d, dir, nil
}

// openFile creates the file a plugin with the file.write permission writes
// to: new, never an existing one, readable by the user alone.
func (r *pluginRun) openFile(name string) (*os.File, string, error) {
	fn, given := r.files[name]
	if !given {
		dir, err := stateDir()
		if err != nil {
			return nil, "", fmt.Errorf("plugin %s needs a file: %v; give one with --plugin-file %s=PATH", name, err, name)
		}
		dir = filepath.Join(dir, name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, "", fmt.Errorf("plugin %s needs a file: %v", name, err)
		}
		fn = filepath.Join(dir, r.bus.Run()+"."+name)
	}
	if abs, err := filepath.Abs(fn); err == nil {
		fn = abs
	}
	f, err := os.OpenFile(fn, os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, "", fmt.Errorf("plugin %s's file %s exists already; vpnw never writes over one", name, fn)
		}
		return nil, "", fmt.Errorf("plugin %s's file: %v", name, err)
	}
	r.opened = append(r.opened, f)
	return f, fn, nil
}

func parsePluginFiles(list []string) (map[string]string, error) {
	return parseNamed("--plugin-file", list)
}

func parsePluginFolders(list []string) (map[string]string, error) {
	return parseNamed("--plugin-folder", list)
}

// parseNamed reads repeated NAME=PATH options.
func parseNamed(flag string, list []string) (map[string]string, error) {
	out := map[string]string{}
	for _, s := range list {
		name, fn, ok := strings.Cut(s, "=")
		if !ok || name == "" || fn == "" {
			return nil, fmt.Errorf("%s %q: give NAME=PATH", flag, s)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("%s %s is given twice", flag, name)
		}
		out[name] = fn
	}
	return out, nil
}

// unused refuses --set for a plugin that is not part of the run.
func (r *pluginRun) unused() error {
	for name := range r.files {
		if !r.used[name] {
			return fmt.Errorf("--plugin-file %s=…: plugin %s is not used in this run", name, name)
		}
		if m := r.mans[name]; m != nil && !m.Has(pluginhost.PermFile) {
			return fmt.Errorf("--plugin-file %s=…: plugin %s doesn't ask for a file (file.write)", name, name)
		}
	}
	for name := range r.folders {
		if !r.used[name] {
			return fmt.Errorf("--plugin-folder %s=…: plugin %s is not used in this run", name, name)
		}
		if m := r.mans[name]; m != nil && !m.Has(pluginhost.PermFolder) {
			return fmt.Errorf("--plugin-folder %s=…: plugin %s doesn't ask for a folder (folder.read)", name, name)
		}
	}
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
	if r.tunnel != nil {
		r.tunnel.Close()
	}
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
	for _, f := range r.opened {
		f.Sync()
		f.Close()
	}
	for _, d := range r.dirs {
		d.Close()
	}
}

// tracePath names a trace file: "last" is the last saved trace.
func tracePath(fn string) (string, error) {
	if fn != "last" {
		return fn, nil
	}
	dir, err := stateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "last.jsonl"), nil
}

// readTraces reads events from trace files ("last" is the last saved trace).
func readTraces(from []string) ([]events.Event, error) {
	if len(from) == 0 {
		from = []string{"last"}
	}
	var all []events.Event
	for _, fn := range from {
		fn, err := tracePath(fn)
		if err != nil {
			return nil, err
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

// maxLine is the longest line an Advisor with input = "lines" is handed.
const maxLine = 4 << 20

// feedLines hands an Advisor every line of its input files, as it is: as
// JSON text when the line is valid UTF-8, as base64 when it is not.
func feedLines(ctx context.Context, in *pluginhost.Instance, from []string) error {
	if len(from) == 0 {
		return errors.New("give the files to read")
	}
	for _, name := range from {
		fn, err := tracePath(name)
		if err != nil {
			return err
		}
		f, err := os.Open(fn)
		if err != nil {
			return fmt.Errorf("cannot read %s: %v", fn, err)
		}
		r := bufio.NewReaderSize(f, 64<<10)
		for n := 1; ; n++ {
			line, err := r.ReadSlice('\n')
			if err == bufio.ErrBufferFull {
				long := append([]byte(nil), line...)
				for err == bufio.ErrBufferFull && len(long) <= maxLine {
					line, err = r.ReadSlice('\n')
					long = append(long, line...)
				}
				if len(long) > maxLine {
					f.Close()
					return fmt.Errorf("%s:%d: a line longer than %d bytes", name, n, maxLine)
				}
				line = long
			}
			if len(line) == 0 && err == io.EOF {
				break
			}
			if err != nil && err != io.EOF {
				f.Close()
				return fmt.Errorf("cannot read %s: %v", fn, err)
			}
			partial := err == io.EOF
			text := bytes.TrimSuffix(line, []byte("\n"))
			m := map[string]any{"file": name, "line": n}
			if utf8.Valid(text) {
				m["text"] = string(text)
			} else {
				m["b64"] = text
			}
			if partial {
				m["partial"] = true
			}
			b, _ := json.Marshal(m)
			if err := in.Event(ctx, b); err != nil {
				f.Close()
				return err
			}
			if partial {
				break
			}
		}
		f.Close()
	}
	return nil
}

// advise runs an Advisor plugin over traces and returns what it wrote to
// standard output, even when it fails.
func advise(name string, from []string, set map[string]string, command string, stderr io.Writer) ([]byte, error) {
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
	var evs []events.Event
	if pkg.Manifest.Input != pluginhost.InputLines {
		if evs, err = readTraces(from); err != nil {
			return nil, err
		}
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
	if pkg.Manifest.Input == pluginhost.InputLines {
		if err := feedLines(ctx, in, from); err != nil {
			if in.Err() != nil {
				return out.Bytes(), fmt.Errorf("plugin %s stopped: %v", name, err)
			}
			return out.Bytes(), err
		}
	}
	for i := range evs {
		b, err := jsonEvent(&evs[i])
		if err != nil {
			return nil, err
		}
		if err := in.Event(ctx, b); err != nil {
			return out.Bytes(), fmt.Errorf("plugin %s stopped: %v", name, err)
		}
	}
	if err := in.Finish(ctx); err != nil {
		return out.Bytes(), fmt.Errorf("plugin %s stopped: %v", name, err)
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

// verifyCmd checks a ledger with the built-in ledger-verify plugin. With no
// trace given, it also reads the saved "last" trace, which holds the
// checkpoint copies when the ledger is from the last run. Exit codes: 0 the
// ledger is intact, 1 it isn't (changed or cut short), 121 usage.
func verifyCmd(args []string, stdout, stderr io.Writer) int {
	const use = "usage: vpnw verify LEDGER [TRACE]... [--head HASH]"
	var head string
	fs := flag.NewFlagSet("vpnw verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&head, "head", "", "")
	files, err := parseAnywhere(fs, args)
	if err != nil {
		return fail(stderr, process.ExitConfig, "%v; %s", err, use)
	}
	if len(files) == 0 {
		return fail(stderr, process.ExitConfig, use)
	}
	if len(files) == 1 {
		if fn, err := tracePath("last"); err == nil {
			if _, err := os.Stat(fn); err == nil {
				files = append(files, "last")
			}
		}
	}
	set := map[string]string{}
	if head != "" {
		set["head"] = head
	}
	out, err := advise("ledger-verify", files, set, "verify", stderr)
	stdout.Write(out)
	if err != nil {
		if len(out) == 0 {
			return fail(stderr, process.ExitConfig, "%v", err)
		}
		return 1
	}
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
		stdout.Write(out)
		return fail(stderr, process.ExitConfig, "%v", err)
	}
	return writeAdvice(out, outFile, stdout, stderr)
}
