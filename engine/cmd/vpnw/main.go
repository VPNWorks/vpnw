// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Command vpnw gives one program its own network path, policy and record.
//
//	vpnw run   [options] -- command [args...]   run through a chosen path
//	vpnw trace [options] -- command [args...]   ... and print every connection
//	vpnw guard [options] -- command [args...]   ... and enforce a policy
//	vpnw learn [--from FILE] [options]          turn a trace into a policy
//	vpnw doctor                                 check what this machine supports
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"vpnw.com/vpnw/internal/broker"
	"vpnw.com/vpnw/internal/config"
	"vpnw.com/vpnw/internal/events"
	"vpnw.com/vpnw/internal/learn"
	"vpnw.com/vpnw/internal/path"
	"vpnw.com/vpnw/internal/policy"
	"vpnw.com/vpnw/internal/process"
	"vpnw.com/vpnw/internal/version"
)

const usage = `vpnw %s: a network path, a policy and a record for one program.

Usage:
  vpnw run   [options] -- command [args...]   run a program through a chosen path
  vpnw trace [options] -- command [args...]   run it and print every connection
  vpnw guard [options] -- command [args...]   run it under a policy, enforced
  vpnw learn [options]                        turn a trace into a policy
  vpnw doctor                                 check what this machine supports
  vpnw version

Options for run, trace and guard:
  --policy FILE       policy file ([policy], and optionally paths)
  --config FILE       file with [network] and [paths.NAME] tables
  --via NAME          use a named path from --config or --policy
  --direct            connect from this machine (the default)
  --proxy URL         use a proxy: socks5://, socks5h:// or http://host:port,
                      or one reached over TLS: https:// or socks5+tls://.
                      Give it again for a list of exits, used in order: when
                      one stops answering, connections move to the next
  --ca FILE           certificates to trust for a proxy over TLS (private CA)
  --token-file FILE   read the token for a proxy over TLS from FILE
  --dns local|remote  where names are resolved, for --proxy
  --allow RULE        allow a host, *.domain, address or CIDR (repeatable)
  --deny RULE         deny one (repeatable)
  --deny-private      deny loopback, private and link-local addresses
  --default allow|deny  what happens when no rule matches
  --out FILE          also write the events to FILE as JSON lines
  --json              print events as JSON lines instead of text
  -v, --verbose       print more (run: decisions; guard: allowed connections too)
  -q, --quiet         print only errors
  --no-save           do not keep this trace as "last"
  --backend sealed|env  sealed (Linux, enforced) or env (proxy settings only)
  --allow-unix-sockets  sealed: let the program create Unix sockets (off by
                      default, so it cannot reach a local service such as
                      the Docker socket and ask it to connect for it)
  --no-deny-exit      guard: keep the program's exit code even when a
                      connection was denied (otherwise 0 becomes 120)

Exit codes: the program's own, or 120 denied (guard), 121 usage or
configuration, 122 enforcement unavailable, 123 path unavailable,
124 vpnw failure, 126 cannot run, 127 not found.
`

func main() {
	if len(os.Args) > 1 && os.Args[1] == process.SandboxArg {
		os.Exit(process.SandboxMain(os.Args[2:]))
	}
	os.Exit(realMain(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func realMain(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, usage, version.Version)
		return process.ExitConfig
	}
	switch args[0] {
	case "run", "trace", "guard":
		return runCmd(args[0], args[1:], stdin, stdout, stderr)
	case "learn":
		return learnCmd(args[1:], stdout, stderr)
	case "doctor":
		return doctorCmd(stdout)
	case "version", "--version", "-V":
		fmt.Fprintf(stdout, "vpnw %s (%s/%s, %s)\n", version.Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return 0
	case "help", "-h", "--help":
		fmt.Fprintf(stdout, usage, version.Version)
		return 0
	}
	fmt.Fprintf(stderr, "vpnw: unknown command %q; see vpnw help\n", args[0])
	return process.ExitConfig
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

type runOpts struct {
	policyFile, configFile, via, dns, def, out, backend              string
	caFile, tokenFile                                                string
	direct, denyPrivate, jsonOut, verbose, quiet, noSave, noDenyExit bool
	allowUnix                                                        bool
	allow, deny, proxy                                               multi
}

func fail(stderr io.Writer, code int, format string, a ...any) int {
	fmt.Fprintf(stderr, "vpnw: "+format+"\n", a...)
	return code
}

func runCmd(mode string, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var o runOpts
	fs := flag.NewFlagSet("vpnw "+mode, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.policyFile, "policy", "", "")
	fs.StringVar(&o.configFile, "config", "", "")
	fs.StringVar(&o.via, "via", "", "")
	fs.BoolVar(&o.direct, "direct", false, "")
	fs.Var(&o.proxy, "proxy", "")
	fs.StringVar(&o.caFile, "ca", "", "")
	fs.StringVar(&o.tokenFile, "token-file", "", "")
	fs.StringVar(&o.dns, "dns", "", "")
	fs.Var(&o.allow, "allow", "")
	fs.Var(&o.deny, "deny", "")
	fs.BoolVar(&o.denyPrivate, "deny-private", false, "")
	fs.StringVar(&o.def, "default", "", "")
	fs.StringVar(&o.out, "out", "", "")
	fs.BoolVar(&o.jsonOut, "json", false, "")
	fs.BoolVar(&o.verbose, "verbose", false, "")
	fs.BoolVar(&o.verbose, "v", false, "")
	fs.BoolVar(&o.quiet, "quiet", false, "")
	fs.BoolVar(&o.quiet, "q", false, "")
	fs.BoolVar(&o.noSave, "no-save", false, "")
	fs.StringVar(&o.backend, "backend", "", "")
	fs.BoolVar(&o.noDenyExit, "no-deny-exit", false, "")
	fs.BoolVar(&o.allowUnix, "allow-unix-sockets", false, "")
	if err := fs.Parse(args); err != nil {
		return fail(stderr, process.ExitConfig, "%v; see vpnw help", err)
	}
	argv := fs.Args()
	if len(argv) > 0 && argv[0] == "--" {
		argv = argv[1:]
	}
	if len(argv) == 0 {
		return fail(stderr, process.ExitConfig, "%s needs a command after --, as in: vpnw %s -- curl https://example.com", mode, mode)
	}

	// Configuration.
	var files []*config.File
	for _, fn := range []string{o.configFile, o.policyFile} {
		if fn == "" {
			continue
		}
		f, err := config.Load(fn)
		if err != nil {
			return fail(stderr, process.ExitConfig, "%v", err)
		}
		files = append(files, f)
	}
	cfg, err := config.Merge(files...)
	if err != nil {
		return fail(stderr, process.ExitConfig, "%v", err)
	}
	if o.policyFile != "" && files[len(files)-1].Policy == nil {
		return fail(stderr, process.ExitConfig, "%s has no [policy] table", o.policyFile)
	}

	// Policy.
	var pol *policy.Policy
	flagPolicy := len(o.allow) > 0 || len(o.deny) > 0 || o.denyPrivate || o.def != ""
	switch {
	case flagPolicy && cfg.Policy != nil:
		return fail(stderr, process.ExitConfig, "give the policy either as a file or as --allow/--deny flags, not both")
	case flagPolicy:
		if o.def != "" && o.def != "allow" && o.def != "deny" {
			return fail(stderr, process.ExitConfig, "--default must be allow or deny")
		}
		pol, err = policy.FromFlags(o.allow, o.deny, o.denyPrivate, o.def)
	case cfg.Policy != nil:
		// Name the policy after the file that holds [policy], not after
		// whichever file came first.
		name := ""
		for _, f := range files {
			if f.Policy != nil {
				name = f.Name
				if name == "" {
					name = filepath.Base(f.Source)
				}
			}
		}
		pol, err = policy.New(cfg.Policy, name)
	}
	if err != nil {
		return fail(stderr, process.ExitConfig, "policy: %v", err)
	}
	if mode == "guard" && pol == nil {
		return fail(stderr, process.ExitConfig, "guard needs a policy: --policy FILE, or --allow/--deny rules")
	}

	// Path.
	var p path.Path
	chosen := 0
	for _, b := range []bool{o.direct, len(o.proxy) > 0, o.via != ""} {
		if b {
			chosen++
		}
	}
	if chosen > 1 {
		return fail(stderr, process.ExitConfig, "choose one of --direct, --proxy and --via")
	}
	switch {
	case o.direct:
		p = &path.Direct{}
	case len(o.proxy) > 0:
		if o.dns != "" && o.dns != "local" && o.dns != "remote" {
			err = errors.New("--dns must be local or remote")
			break
		}
		p, err = path.Build("proxy", o.proxy, path.Options{DNS: o.dns, CAFile: o.caFile, TokenFile: o.tokenFile})
	case o.via != "":
		if o.via == "direct" {
			p = &path.Direct{}
			break
		}
		ps, ok := cfg.Paths[o.via]
		if !ok {
			names := cfg.PathNames()
			hint := "no named paths are defined; add a [paths." + o.via + "] table to --config"
			if len(names) > 0 {
				hint = "known paths: " + strings.Join(names, ", ")
			}
			return fail(stderr, process.ExitConfig, "unknown path %q (%s)", o.via, hint)
		}
		p, err = path.FromSpec(ps)
	case cfg.Network != nil:
		p, err = path.FromSpec(cfg.Network)
	default:
		p = &path.Direct{}
	}
	if err != nil {
		return fail(stderr, process.ExitConfig, "%v", err)
	}
	if o.dns != "" && len(o.proxy) == 0 {
		return fail(stderr, process.ExitConfig, "--dns applies to --proxy only; set dns in the path's table")
	}
	if (o.caFile != "" || o.tokenFile != "") && len(o.proxy) == 0 {
		return fail(stderr, process.ExitConfig, "--ca and --token-file apply to --proxy only; set ca_file and token_file in the path's table")
	}
	if pol != nil && p.RemoteDNS() {
		if err := pol.CheckRemoteDNS(p.ID()); err != nil {
			return fail(stderr, process.ExitConfig, "%v", err)
		}
	}

	// Backend.
	var be process.Backend
	switch o.backend {
	case "", "sealed":
		be = &process.Sealed{}
		if o.backend == "" && runtime.GOOS != "linux" {
			be = &process.Env{}
		}
	case "env":
		be = &process.Env{}
	default:
		return fail(stderr, process.ExitConfig, "--backend must be sealed or env")
	}
	if pol != nil && !be.Enforced() {
		return fail(stderr, process.ExitNoEnforcement, "a policy needs the sealed backend, which blocks traffic that ignores proxy settings; the env backend cannot enforce it")
	}
	if !be.Enforced() && !o.quiet {
		fmt.Fprintln(stderr, "vpnw: env backend: programs that ignore proxy settings are neither routed nor traced")
	}

	// Path health: never fall back to direct if the chosen path is down.
	{
		ctx, cancel := contextTimeout(5 * time.Second)
		err := p.Health(ctx)
		cancel()
		if err != nil {
			return fail(stderr, process.ExitPath, "path %q is not usable: %v", p.ID(), err)
		}
	}

	// Events.
	runID := newRunID()
	bus := events.NewBus(runID, nil)
	var closers []func() error
	level := events.Decisions
	switch {
	case o.quiet:
		level = -1
	case mode == "trace":
		level = events.All
	case mode == "run" && !o.verbose:
		level = -1
	case o.verbose && mode == "guard":
		level = events.Decisions
	}
	if level >= 0 {
		if o.jsonOut {
			bus.Add(events.NewJSONL(stderr))
		} else {
			t := events.NewText(stderr, level)
			t.Color = colorOK(stderr)
			t.ShowAllows = o.verbose
			t.Local = true
			bus.Add(t)
		}
	}
	outs := []string{}
	if o.out != "" {
		outs = append(outs, o.out)
	}
	if cfg.Trace != nil && cfg.Trace.Enabled && cfg.Trace.Out != "" && cfg.Trace.Out != o.out {
		outs = append(outs, cfg.Trace.Out)
	}
	if !o.noSave {
		if dir, err := stateDir(); err == nil {
			if os.MkdirAll(dir, 0o700) == nil {
				outs = append(outs, filepath.Join(dir, "last.jsonl"))
			}
		}
	}
	for _, fn := range outs {
		f, err := os.OpenFile(fn, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return fail(stderr, process.ExitConfig, "cannot write %s: %v", fn, err)
		}
		j := events.NewJSONL(f)
		bus.Add(j)
		closers = append(closers, j.Close)
	}
	defer func() {
		for _, c := range closers {
			c()
		}
	}()

	l, err := be.Listen()
	if err != nil {
		return fail(stderr, process.ExitInternal, "cannot open the broker: %v", err)
	}
	defer be.Close()
	br := &broker.Broker{Policy: pol, Path: p, Resolver: path.SystemResolver{}, Bus: bus}
	if env, ok := be.(*process.Env); ok {
		br.Token = env.Token
	}
	go br.Serve(l)

	start := map[string]any{
		"mode": mode, "backend": be.Name(), "enforced": be.Enforced(), "version": version.Version,
		"path_kind": p.Kind(), "path": p.Describe(), "remote_dns": p.RemoteDNS(),
	}
	if pol != nil {
		start["policy"] = pol.Summary()
	}
	if be.Enforced() {
		start["unix_sockets"] = map[bool]string{true: "allowed", false: "blocked"}[o.allowUnix]
	}
	bus.Emit(events.RunStart, 0, p.ID(), 0, start)

	spec := process.Spec{Argv: argv, Env: os.Environ(), Stdin: stdin, Stdout: stdout, Stderr: stderr, RunID: runID, PathID: p.ID(), AllowUnix: o.allowUnix}
	if f, ok := stdin.(*os.File); ok && f == os.Stdin {
		spec.Stdin = os.Stdin
	}
	pid, err := be.Start(spec)
	if err != nil {
		code := process.ExitInternal
		var se *process.StartError
		if errors.As(err, &se) {
			code = se.Code
		}
		fmt.Fprintf(stderr, "vpnw: %v\n", err)
		bus.Emit(events.RunEnd, 0, p.ID(), 0, map[string]any{"error": err.Error(), "code": code})
		return code
	}
	br.SetPID(pid)
	pf := map[string]any{"cmd": filepath.Base(argv[0]), "args": len(argv) - 1}
	if s, ok := be.(*process.Sealed); ok && len(s.Interfaces) > 0 {
		pf["interfaces"] = s.Interfaces
	}
	bus.Emit(events.ProcessStart, pid, p.ID(), 0, pf)

	sigs := make(chan os.Signal, 16)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2)
	tty := isTerminal(os.Stdin)
	go func() {
		for s := range sigs {
			// A terminal already delivers Ctrl-C and Ctrl-\ to the whole
			// foreground group, workload included.
			if tty && (s == syscall.SIGINT || s == syscall.SIGQUIT) {
				continue
			}
			be.Signal(s)
		}
	}()

	res, werr := be.Wait()
	signal.Stop(sigs)
	close(sigs)
	ef := map[string]any{"code": res.Code, "ms": res.Ended.Sub(res.Started).Milliseconds()}
	if res.Signal != "" {
		ef["signal"] = res.Signal
	}
	bus.Emit(events.ProcessExit, pid, p.ID(), 0, ef)
	br.Shutdown(2 * time.Second)
	st := br.Stats()
	bus.Emit(events.RunEnd, 0, p.ID(), 0, map[string]any{
		"connections": st.Connections, "opened": st.Opened, "allowed": st.Allowed, "denied": st.Denied, "failed": st.Failed,
		"bytes_up": st.BytesUp, "bytes_down": st.BytesDown, "code": res.Code,
	})
	if werr != nil {
		fmt.Fprintf(stderr, "vpnw: %v\n", werr)
		return process.ExitInternal
	}
	if pol != nil && st.Denied > 0 && res.Code == 0 && !o.noDenyExit {
		return process.ExitDenied
	}
	return res.Code
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
	if len(from) == 0 {
		from = multi{"last"}
	}
	var all []events.Event
	for _, fn := range from {
		if fn == "last" {
			dir, err := stateDir()
			if err != nil {
				return fail(stderr, process.ExitConfig, "%v", err)
			}
			fn = filepath.Join(dir, "last.jsonl")
		}
		f, err := os.Open(fn)
		if err != nil {
			return fail(stderr, process.ExitConfig, "cannot read trace %s: %v", fn, err)
		}
		evs, err := events.Read(f)
		f.Close()
		if err != nil {
			return fail(stderr, process.ExitConfig, "%s: %v", fn, err)
		}
		all = append(all, evs...)
	}
	res := learn.FromEvents(all, learn.Options{Name: name, Ports: ports, Wildcards: wild, Now: time.Now()})
	if outFile != "" {
		if err := os.WriteFile(outFile, []byte(res.TOML), 0o644); err != nil {
			return fail(stderr, process.ExitConfig, "%v", err)
		}
		fmt.Fprintf(stderr, "vpnw: wrote %s: %d destinations allowed, %d left out\n", outFile, len(res.Allowed), len(res.Denied))
		return 0
	}
	io.WriteString(stdout, res.TOML)
	return 0
}

func doctorCmd(stdout io.Writer) int {
	fmt.Fprintf(stdout, "vpnw %s on %s/%s\n", version.Version, runtime.GOOS, runtime.GOARCH)
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		fmt.Fprintf(stdout, "  kernel           %s\n", strings.TrimSpace(string(b)))
	}
	if b, err := os.ReadFile("/proc/sys/user/max_user_namespaces"); err == nil {
		fmt.Fprintf(stdout, "  user namespaces  up to %s\n", strings.TrimSpace(string(b)))
	}
	if err := process.Check(); err != nil {
		fmt.Fprintf(stdout, "  sealed backend   NOT AVAILABLE: %v\n", err)
		fmt.Fprintln(stdout, "  guard            refuses to run here; run and trace work with --backend env (proxy-aware programs only)")
		return process.ExitNoEnforcement
	}
	fmt.Fprintln(stdout, "  sealed backend   ok: a test namespace came up with loopback only")
	fmt.Fprintln(stdout, "  guard            available: inside the sandbox, traffic that ignores proxy settings has no route out")
	fmt.Fprintln(stdout, "  routed programs  those that honor HTTP_PROXY/HTTPS_PROXY/ALL_PROXY: curl, wget, git, pip,")
	fmt.Fprintln(stdout, "                   Python urllib/requests/httpx, Go net/http, and Node.js 22.21+ or 24.5+,")
	fmt.Fprintln(stdout, "                   which honor them when NODE_USE_ENV_PROXY=1 (vpnw sets it)")
	fmt.Fprintln(stdout, "  unix sockets     blocked inside the sandbox by a seccomp filter, so a program cannot ask a")
	fmt.Fprintln(stdout, "                   local service such as Docker to connect for it (--allow-unix-sockets lifts it)")
	return 0
}

func stateDir() (string, error) {
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "vpnw"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("cannot find a home directory for the last trace; use --out")
	}
	return filepath.Join(home, ".local", "state", "vpnw"), nil
}

func newRunID() string {
	var b [3]byte
	rand.Read(b[:])
	return "r-" + hex.EncodeToString(b[:])
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func colorOK(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	return ok && isTerminal(f)
}

func contextTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
