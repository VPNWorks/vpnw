// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Command vpnw-exit runs a VPN Works exit, the far end of the tunnel: fixed
// exit addresses for agents, CI jobs and apps, each request checked again
// with the client's own policy, and a record that joins the client's.
//
//	vpnw-exit serve   take clients' requests over TLS
//	vpnw-exit check   check a configuration file
//	vpnw-exit token   make a token for a new client
//	vpnw-exit decide  say what the exit would do with some requests
//	vpnw-exit join    match an Agent's records with exits' records
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"vpnw.com/vpnw/internal/events"
	"vpnw.com/vpnw/internal/exit"
	"vpnw.com/vpnw/internal/exit/server"
	"vpnw.com/vpnw/internal/path"
)

const usage = `vpnw-exit %s: the far end of the tunnel, with the policy checked again.

Usage:
  vpnw-exit serve  --config FILE [--out FILE] [--json] [-v] [-q]
  vpnw-exit check  --config FILE
  vpnw-exit token  [--from FILE]
  vpnw-exit decide --config FILE --client NAME [--dns FILE] [--json] HOST:PORT...
  vpnw-exit join   --agent FILE... --exit FILE... [--json]
  vpnw-exit version

serve    takes HTTP CONNECT and SOCKS5 requests over TLS. A client is known
         by its token, and each request is decided with that client's own
         policy before anything is dialed. Allowed requests leave from the
         client's fixed source address. Every step goes into the record,
         with the client's run and connection IDs.
check    reads a configuration file with its policy files, certificate and
         key, and says what each client may do.
token    makes a token for a new client and prints the token_sha256 line for
         the configuration; --from FILE hashes a token kept in FILE.
decide   says what the exit would do with requests from one client, without
         connecting anywhere.
join     matches an Agent's records with exits' records on the run and
         connection IDs, and lists every connection that does not join up.

Options:
  --config FILE   the exit's configuration
  --out FILE      serve: also write the record to FILE as JSON lines
  --json          serve: the record as JSON lines on standard error;
                  decide and join: the result as JSON
  -v, --verbose   serve: print every step, not only refusals and errors
  -q, --quiet     serve: print only the start and the summary
  --client NAME   decide: the client whose policy decides
  --dns FILE      decide: answer DNS from FILE, a JSON object of names and
                  address lists, instead of this machine's resolver
  --agent FILE    join: an Agent's record (vpnw --out), repeatable
  --exit FILE     join: an exit's record (vpnw-exit serve --out), repeatable

Exit codes: 0, or 120 when decide refused a request or join found a
connection that does not join up, 121 usage or input error, 122 not possible
on this machine (the listener or a source address), 124 any other failure.
`

const (
	exitFound       = 120
	exitConfig      = 121
	exitUnavailable = 122
	exitFailure     = 124
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, usage, exit.Version)
		return exitConfig
	}
	switch args[0] {
	case "serve":
		return serveCmd(ctx, args[1:], stderr)
	case "check":
		return checkCmd(args[1:], stdout, stderr)
	case "token":
		return tokenCmd(args[1:], stdout, stderr)
	case "decide":
		return decideCmd(args[1:], stdout, stderr)
	case "join":
		return joinCmd(args[1:], stdout, stderr)
	case "version", "--version", "-V":
		fmt.Fprintf(stdout, "vpnw-exit %s (%s/%s, %s)\n", exit.Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return 0
	case "help", "-h", "--help":
		fmt.Fprintf(stdout, usage, exit.Version)
		return 0
	}
	fmt.Fprintf(stderr, "vpnw-exit: unknown command %q; see vpnw-exit help\n", args[0])
	return exitConfig
}

func fail(stderr io.Writer, code int, format string, a ...any) int {
	fmt.Fprintf(stderr, "vpnw-exit: "+format+"\n", a...)
	return code
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

type opts struct {
	config, out, client, dns, from string
	agent, exits                   multi
	jsonOut, verbose, quiet        bool
}

func newFlags(name string, o *opts) *flag.FlagSet {
	fs := flag.NewFlagSet("vpnw-exit "+name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.config, "config", "", "")
	fs.StringVar(&o.out, "out", "", "")
	fs.StringVar(&o.client, "client", "", "")
	fs.StringVar(&o.dns, "dns", "", "")
	fs.StringVar(&o.from, "from", "", "")
	fs.Var(&o.agent, "agent", "")
	fs.Var(&o.exits, "exit", "")
	fs.BoolVar(&o.jsonOut, "json", false, "")
	fs.BoolVar(&o.verbose, "verbose", false, "")
	fs.BoolVar(&o.verbose, "v", false, "")
	fs.BoolVar(&o.quiet, "quiet", false, "")
	fs.BoolVar(&o.quiet, "q", false, "")
	return fs
}

func loadConfig(o *opts) (*exit.Config, error) {
	if o.config == "" {
		return nil, errors.New("--config FILE is required")
	}
	return exit.LoadConfig(o.config)
}

func loadCert(c *exit.Config) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(c.CertFile(), c.KeyFile())
	if err != nil {
		return cert, fmt.Errorf("%s: certificate %s and key %s: %v", c.File, c.CertFile(), c.KeyFile(), err)
	}
	return cert, nil
}

func newRunID() string {
	var b [3]byte
	rand.Read(b[:])
	return "x-" + hex.EncodeToString(b[:])
}

func serveCmd(parent context.Context, args []string, stderr io.Writer) int {
	var o opts
	fs := newFlags("serve", &o)
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		if err == nil {
			err = fmt.Errorf("unexpected argument %q", fs.Arg(0))
		}
		return fail(stderr, exitConfig, "serve: %v", err)
	}
	cfg, err := loadConfig(&o)
	if err != nil {
		return fail(stderr, exitConfig, "%v", err)
	}
	cert, err := loadCert(cfg)
	if err != nil {
		return fail(stderr, exitConfig, "%v", err)
	}
	// Every source address must be this machine's, or nothing could leave
	// from it.
	for _, a := range cfg.Sources() {
		l, err := net.Listen("tcp", net.JoinHostPort(a.String(), "0"))
		if err != nil {
			return fail(stderr, exitUnavailable, "source address %s is not on this machine: %v", a, err)
		}
		l.Close()
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fail(stderr, exitUnavailable, "cannot listen on %s: %v", cfg.Listen, err)
	}
	defer ln.Close()

	bus := events.NewBus(newRunID(), nil)
	switch {
	case o.jsonOut:
		bus.Add(events.NewJSONL(stderr))
	case !o.quiet:
		level := events.Decisions
		if o.verbose {
			level = events.All
		}
		t := server.NewText(stderr, level)
		t.Local = true
		bus.Add(t)
	}
	if o.out != "" {
		f, err := os.OpenFile(o.out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return fail(stderr, exitConfig, "cannot write %s: %v", o.out, err)
		}
		j := events.NewJSONL(f)
		bus.Add(j)
		defer j.Close()
	}
	for _, w := range cfg.Warnings {
		fmt.Fprintf(stderr, "vpnw-exit: warning: %s\n", w)
	}
	s := &server.Server{
		Config:   cfg,
		TLS:      &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		Resolver: path.SystemResolver{},
		Bus:      bus,
	}
	var sources []string
	for _, a := range cfg.Sources() {
		sources = append(sources, a.String())
	}
	bus.Emit(events.RunStart, 0, cfg.Name, 0, map[string]any{"mode": "exit", "version": exit.Version, "listen": ln.Addr().String(),
		"clients": len(cfg.Clients), "sources": sources})
	fmt.Fprintf(stderr, "vpnw-exit: %s listening on %s for %d clients\n", cfg.Name, ln.Addr(), len(cfg.Clients))

	ctx, stop := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	served := make(chan error, 1)
	go func() { served <- s.Serve(ln) }()
	code := 0
	select {
	case <-ctx.Done():
	case err := <-served:
		if err != nil {
			fmt.Fprintf(stderr, "vpnw-exit: %v\n", err)
			code = exitFailure
		}
	}
	ln.Close()
	s.Shutdown(2 * time.Second)
	st := s.Stats()
	bus.Emit(events.RunEnd, 0, cfg.Name, 0, map[string]any{"connections": st.Connections, "opened": st.Opened, "denied": st.Denied,
		"failed": st.Failed, "auth_denied": st.AuthDenied, "tls_failed": st.TLSFailed, "health_checks": st.Health,
		"bytes_up": st.BytesUp, "bytes_down": st.BytesDown})
	return code
}

func checkCmd(args []string, stdout, stderr io.Writer) int {
	var o opts
	fs := newFlags("check", &o)
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		if err == nil {
			err = fmt.Errorf("unexpected argument %q", fs.Arg(0))
		}
		return fail(stderr, exitConfig, "check: %v", err)
	}
	cfg, err := loadConfig(&o)
	if err != nil {
		return fail(stderr, exitConfig, "%v", err)
	}
	cert, err := loadCert(cfg)
	if err != nil {
		return fail(stderr, exitConfig, "%v", err)
	}
	until := ""
	if len(cert.Certificate) > 0 {
		if c, err := parseLeaf(cert.Certificate[0]); err == nil {
			until = ", valid until " + c.Format("2006-01-02")
		}
	}
	fmt.Fprintf(stdout, "%s: exit %s on %s, %d clients, %d pools; certificate %s%s.\n", cfg.File, cfg.Name, cfg.Listen,
		len(cfg.Clients), len(cfg.Pools), cfg.CertFile(), until)
	for _, cl := range cfg.Clients {
		fmt.Fprintf(stdout, "  %s\n", cl.Describe())
	}
	for _, w := range cfg.Warnings {
		fmt.Fprintf(stdout, "warning: %s\n", w)
	}
	return 0
}

func tokenCmd(args []string, stdout, stderr io.Writer) int {
	var o opts
	fs := newFlags("token", &o)
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		if err == nil {
			err = fmt.Errorf("unexpected argument %q", fs.Arg(0))
		}
		return fail(stderr, exitConfig, "token: %v", err)
	}
	if o.from != "" {
		b, err := os.ReadFile(o.from)
		if err != nil {
			return fail(stderr, exitConfig, "token: %v", err)
		}
		tok := strings.TrimSpace(string(b))
		if tok == "" {
			return fail(stderr, exitConfig, "token: %s is empty", o.from)
		}
		fmt.Fprintf(stdout, "token_sha256 = %q\n", exit.HashHex(tok))
		return 0
	}
	tok, err := exit.NewToken()
	if err != nil {
		return fail(stderr, exitFailure, "token: %v", err)
	}
	fmt.Fprintf(stdout, "token: %s\ntoken_sha256 = %q\n", tok, exit.HashHex(tok))
	fmt.Fprintln(stderr, "vpnw-exit: give the token to the client, in a token file; put the token_sha256 line in the client's table. The exit never keeps the token itself.")
	return 0
}

// mapDNS answers from a fixed table.
type mapDNS map[string][]net.IP

func (m mapDNS) LookupIP(_ context.Context, host string) ([]net.IP, error) {
	if ips, ok := m[host]; ok && len(ips) > 0 {
		return ips, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func readDNS(name string) (mapDNS, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	var raw map[string][]string
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("%s: want a JSON object of names and address lists: %v", name, err)
	}
	m := mapDNS{}
	for h, list := range raw {
		for _, s := range list {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, fmt.Errorf("%s: %q for %s is not an address", name, s, h)
			}
			m[h] = append(m[h], ip)
		}
	}
	return m, nil
}

type decision struct {
	Target  string   `json:"target"`
	Outcome string   `json:"outcome"`
	Rule    string   `json:"rule,omitempty"`
	Text    string   `json:"text,omitempty"`
	Reason  string   `json:"reason,omitempty"`
	Error   string   `json:"error,omitempty"`
	Addrs   []string `json:"addrs,omitempty"`
	Source  string   `json:"source,omitempty"`
}

func decideCmd(args []string, stdout, stderr io.Writer) int {
	var o opts
	fs := newFlags("decide", &o)
	if err := fs.Parse(args); err != nil {
		return fail(stderr, exitConfig, "decide: %v", err)
	}
	cfg, err := loadConfig(&o)
	if err != nil {
		return fail(stderr, exitConfig, "%v", err)
	}
	if o.client == "" {
		return fail(stderr, exitConfig, "decide: --client NAME is required")
	}
	cl := cfg.Client(o.client)
	if cl == nil {
		var names []string
		for _, c := range cfg.Clients {
			names = append(names, c.Name)
		}
		return fail(stderr, exitConfig, "decide: no client %q in %s (clients: %s)", o.client, cfg.File, strings.Join(names, ", "))
	}
	if fs.NArg() == 0 {
		return fail(stderr, exitConfig, "decide: give at least one HOST:PORT")
	}
	var res path.Resolver = path.SystemResolver{}
	if o.dns != "" {
		m, err := readDNS(o.dns)
		if err != nil {
			return fail(stderr, exitConfig, "decide: %v", err)
		}
		res = m
	}
	src, _ := cl.SourceFor("")
	refused := 0
	enc := json.NewEncoder(stdout)
	for _, arg := range fs.Args() {
		host, ps, err := net.SplitHostPort(arg)
		if err != nil {
			return fail(stderr, exitConfig, "decide: %q: want HOST:PORT", arg)
		}
		port, err := strconv.Atoi(ps)
		if err != nil {
			return fail(stderr, exitConfig, "decide: %q: bad port", arg)
		}
		lookup := func(h string) ([]net.IP, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return res.LookupIP(ctx, h)
		}
		p := cl.Decide(host, port, lookup)
		d := decision{Target: arg, Outcome: p.Outcome, Rule: p.Rule, Text: p.Text, Reason: p.Reason, Error: p.Error, Addrs: p.Addrs}
		switch p.Outcome {
		case "dial":
			d.Outcome, d.Source = "allow", src.String()
		case "denied":
			refused++
		}
		if o.jsonOut {
			enc.Encode(d)
			continue
		}
		switch d.Outcome {
		case "allow":
			rule := p.Rule
			if p.Text != "" {
				rule += " " + strconv.Quote(p.Text)
			}
			fmt.Fprintf(stdout, "allow   %s  from %s  (%s)\n", arg, src, rule)
		case "denied":
			fmt.Fprintf(stdout, "DENY    %s  %s: %s\n", arg, p.Rule, p.Reason)
		default:
			fmt.Fprintf(stdout, "failed  %s  %s\n", arg, p.Error)
		}
	}
	if refused > 0 {
		return exitFound
	}
	return 0
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func readEvents(names []string) ([]events.Event, error) {
	var all []events.Event
	for _, n := range names {
		f, err := os.Open(n)
		if err != nil {
			return nil, err
		}
		evs, err := events.Read(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %v", n, err)
		}
		all = append(all, evs...)
	}
	return all, nil
}

func joinCmd(args []string, stdout, stderr io.Writer) int {
	var o opts
	fs := newFlags("join", &o)
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		if err == nil {
			err = fmt.Errorf("unexpected argument %q", fs.Arg(0))
		}
		return fail(stderr, exitConfig, "join: %v", err)
	}
	if len(o.agent) == 0 || len(o.exits) == 0 {
		return fail(stderr, exitConfig, "join: give at least one --agent FILE and one --exit FILE")
	}
	agent, err := readEvents(o.agent)
	if err != nil {
		return fail(stderr, exitConfig, "join: %v", err)
	}
	exits, err := readEvents(o.exits)
	if err != nil {
		return fail(stderr, exitConfig, "join: %v", err)
	}
	r := exit.Join(agent, exits)
	if o.jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", " ")
		enc.Encode(r)
	} else {
		fmt.Fprintf(stdout, "Agent records: %s (%s), %s: %d reached an exit and %d stopped at the Agent.\n",
			plural(len(r.AgentRuns), "run"), strings.Join(r.AgentRuns, ", "), plural(r.AgentConns, "connection"), r.ViaExit, r.Local)
		fmt.Fprintf(stdout, "Exit records: %s; %s, %d of them from other clients or runs.\n",
			strings.Join(r.ExitRuns, ", "), plural(r.ExitConns, "connection"), r.Other)
		fmt.Fprintf(stdout, "Joined: %d of the %d connections that reached an exit.\n", r.Joined, r.ViaExit)
		for _, row := range r.Rows {
			mark := "  "
			if !row.OK {
				mark = "! "
			}
			id := "no run ID"
			if row.Run != "" {
				id = row.Run + "/" + strconv.FormatUint(row.Conn, 10)
			}
			fmt.Fprintf(stdout, "%s%s  %s  %s  Agent: %s; exit: %s\n", mark, id, row.Target, row.Exit, row.Agent, row.AtExit)
		}
		for _, p := range r.Problems {
			fmt.Fprintf(stdout, "does not join: %s\n", p)
		}
	}
	if !r.OK() {
		return exitFound
	}
	return 0
}
