// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Command vpnw-scope learns least-privilege access for a VPN from its
// traffic, shows what a draft would block, and writes the rules for the
// gateway.
//
//	vpnw-scope record  record new connections at this gateway (Linux)
//	vpnw-scope learn   draft rules from recorded flows
//	vpnw-scope replay  show what a draft would block
//	vpnw-scope export  write the draft as nftables rules or AllowedIPs
//	vpnw-scope check   check a people file and a draft
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"vpnw.com/vpnw/internal/scope"
)

const usage = `vpnw-scope %s: least-privilege VPN access, learned from traffic.

Usage:
  vpnw-scope record --people FILE [--group N] [--out FILE] [--duration D]
  vpnw-scope learn  --people FILE --flows FILE... [options] [-o FILE]
  vpnw-scope replay --people FILE --draft FILE --flows FILE... [options]
  vpnw-scope export --people FILE --draft FILE [--format nft|allowedips] [options]
  vpnw-scope check  --people FILE [--draft FILE]
  vpnw-scope version

record   listens on this Linux gateway for new connections from the VPN
         range and writes one JSON line per connection. It adds an nftables
         table that logs them to an NFLOG group, and removes it on exit.
learn    drafts rules: a group rule for what every active member of a group
         used on two or more days, personal rules for the rest, and a review
         list for what was used too rarely to allow without a decision.
replay   decides recorded flows under a draft and says what it would block.
export   writes the draft as an nftables script for the gateway, or as
         AllowedIPs lines for WireGuard clients.

Options:
  --people FILE       who is behind each VPN address, and their groups
  --wg-dump FILE      output of "wg show all dump", to resolve wireguard_keys
  --flows FILE        flows as JSON lines, from record ("-" is stdin)
  --conntrack FILE    flows from "conntrack -E -o timestamp" output
  --from DATE         first day to use, as YYYY-MM-DD in UTC
  --to DATE           last day to use, included
  --min-days N        learn: days of use needed to allow something (default 2)
  --group-share F     learn: share of a group's active members needed for a
                      group rule, from 0 to 1 (default 1: all of them)
  --draft FILE        the reviewed draft
  --top N             replay: how many blocked destinations to list (default 20)
  --json              replay: one JSON line per flow with its verdict
  --fail-on-deny      replay: exit with 120 if anything would be blocked
  --format F          export: nft (default) or allowedips
  --watch             export: count and log what would be refused, refuse nothing
  --drop              export: drop refused packets instead of rejecting them
  --log-group N       export: log refused packets to NFLOG group N
  --table NAME        export: nftables table name (default vpnw_scope)
  -o FILE             write the result to FILE instead of standard output

Exit codes: 0, or 120 when replay --fail-on-deny found something blocked,
121 usage or input error, 122 recording not possible here, 124 failure.
`

const (
	exitDenied      = 120
	exitConfig      = 121
	exitUnavailable = 122
	exitFailure     = 124
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, usage, scope.Version)
		return exitConfig
	}
	switch args[0] {
	case "record":
		return recordCmd(args[1:], stdout, stderr)
	case "learn":
		return learnCmd(args[1:], stdin, stdout, stderr)
	case "replay":
		return replayCmd(args[1:], stdin, stdout, stderr)
	case "export":
		return exportCmd(args[1:], stdout, stderr)
	case "check":
		return checkCmd(args[1:], stdout, stderr)
	case "version", "--version", "-V":
		fmt.Fprintf(stdout, "vpnw-scope %s (%s/%s, %s)\n", scope.Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return 0
	case "help", "-h", "--help":
		fmt.Fprintf(stdout, usage, scope.Version)
		return 0
	}
	fmt.Fprintf(stderr, "vpnw-scope: unknown command %q; see vpnw-scope help\n", args[0])
	return exitConfig
}

func fail(stderr io.Writer, code int, format string, a ...any) int {
	fmt.Fprintf(stderr, "vpnw-scope: "+format+"\n", a...)
	return code
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

type opts struct {
	people, wgDump, draft, from, to, out, format, table string
	flows, conntrack                                    multi
	minDays, top, logGroup                              int
	groupShare                                          float64
	jsonOut, failOnDeny, watch, drop                    bool
}

func newFlags(name string, o *opts) *flag.FlagSet {
	fs := flag.NewFlagSet("vpnw-scope "+name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.people, "people", "", "")
	fs.StringVar(&o.wgDump, "wg-dump", "", "")
	fs.StringVar(&o.draft, "draft", "", "")
	fs.StringVar(&o.from, "from", "", "")
	fs.StringVar(&o.to, "to", "", "")
	fs.StringVar(&o.out, "o", "", "")
	fs.StringVar(&o.format, "format", "nft", "")
	fs.StringVar(&o.table, "table", "", "")
	fs.Var(&o.flows, "flows", "")
	fs.Var(&o.conntrack, "conntrack", "")
	fs.IntVar(&o.minDays, "min-days", 2, "")
	fs.IntVar(&o.top, "top", 20, "")
	fs.IntVar(&o.logGroup, "log-group", 0, "")
	fs.Float64Var(&o.groupShare, "group-share", 1, "")
	fs.BoolVar(&o.jsonOut, "json", false, "")
	fs.BoolVar(&o.failOnDeny, "fail-on-deny", false, "")
	fs.BoolVar(&o.watch, "watch", false, "")
	fs.BoolVar(&o.drop, "drop", false, "")
	return fs
}

func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return nil
}

func loadPeople(o *opts) (*scope.People, error) {
	if o.people == "" {
		return nil, errors.New("--people FILE is required")
	}
	src, err := os.ReadFile(o.people)
	if err != nil {
		return nil, err
	}
	p, err := scope.ParsePeople(string(src), o.people)
	if err != nil {
		return nil, err
	}
	if o.wgDump != "" {
		dump, err := os.ReadFile(o.wgDump)
		if err != nil {
			return nil, err
		}
		if err := p.ResolveKeys(string(dump), o.wgDump); err != nil {
			return nil, err
		}
	}
	if u := p.Unresolved(); len(u) > 0 {
		return nil, fmt.Errorf("%s: no address yet for %s; give the WireGuard dump with --wg-dump", o.people, strings.Join(u, ", "))
	}
	return p, nil
}

func loadDraft(o *opts, p *scope.People) (*scope.Draft, error) {
	if o.draft == "" {
		return nil, errors.New("--draft FILE is required")
	}
	src, err := os.ReadFile(o.draft)
	if err != nil {
		return nil, err
	}
	return scope.ParseDraft(string(src), o.draft, p)
}

// window turns --from and --to into [from, to).
func window(o *opts) (from, to time.Time, err error) {
	if o.from != "" {
		if from, err = time.Parse("2006-01-02", o.from); err != nil {
			return from, to, fmt.Errorf("--from %q: want YYYY-MM-DD", o.from)
		}
	}
	if o.to != "" {
		if to, err = time.Parse("2006-01-02", o.to); err != nil {
			return from, to, fmt.Errorf("--to %q: want YYYY-MM-DD", o.to)
		}
		to = to.AddDate(0, 0, 1)
	}
	if !from.IsZero() && !to.IsZero() && !from.Before(to) {
		return from, to, errors.New("--to is before --from")
	}
	return from, to, nil
}

// eachFlow reads every --flows and --conntrack file in order.
func eachFlow(o *opts, stdin io.Reader, fn func(scope.Flow) error) (int, error) {
	if len(o.flows) == 0 && len(o.conntrack) == 0 {
		return 0, errors.New("give at least one --flows or --conntrack file")
	}
	total := 0
	open := func(name string) (io.ReadCloser, error) {
		if name == "-" {
			return io.NopCloser(stdin), nil
		}
		return os.Open(name)
	}
	for _, name := range o.flows {
		f, err := open(name)
		if err != nil {
			return total, err
		}
		st, err := scope.ReadFlows(f, name, fn)
		f.Close()
		total += st.Flows
		if err != nil {
			return total, err
		}
	}
	for _, name := range o.conntrack {
		f, err := open(name)
		if err != nil {
			return total, err
		}
		st, err := scope.ReadConntrack(f, name, fn)
		f.Close()
		total += st.Flows
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func output(o *opts, stdout io.Writer, text string) error {
	if o.out == "" || o.out == "-" {
		_, err := io.WriteString(stdout, text)
		return err
	}
	return os.WriteFile(o.out, []byte(text), 0o644)
}

func learnCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var o opts
	fs := newFlags("learn", &o)
	if err := parse(fs, args); err != nil {
		return fail(stderr, exitConfig, "learn: %v", err)
	}
	if o.minDays < 1 {
		return fail(stderr, exitConfig, "learn: --min-days must be 1 or more")
	}
	if o.groupShare <= 0 || o.groupShare > 1 {
		return fail(stderr, exitConfig, "learn: --group-share must be above 0 and at most 1")
	}
	p, err := loadPeople(&o)
	if err != nil {
		return fail(stderr, exitConfig, "%v", err)
	}
	from, to, err := window(&o)
	if err != nil {
		return fail(stderr, exitConfig, "learn: %v", err)
	}
	l := scope.NewLearner(p, scope.LearnOptions{From: from, To: to, MinDays: o.minDays, GroupShare: o.groupShare})
	start := time.Now()
	if _, err := eachFlow(&o, stdin, func(f scope.Flow) error { l.Add(f); return nil }); err != nil {
		return fail(stderr, exitConfig, "%v", err)
	}
	d := l.Draft()
	if err := output(&o, stdout, d.String()); err != nil {
		return fail(stderr, exitFailure, "%v", err)
	}
	fmt.Fprintf(stderr, "vpnw-scope: learned from %s of %s flows in %s: %s.\n",
		scope.Comma(l.Stats.InWindow), scope.Comma(l.Stats.Flows), time.Since(start).Round(time.Millisecond), d.Describe())
	return 0
}

type verdictLine struct {
	T       string `json:"t"`
	Proto   string `json:"proto"`
	Src     string `json:"src"`
	Dst     string `json:"dst"`
	Port    uint16 `json:"port"`
	Verdict string `json:"verdict"`
	Person  string `json:"person,omitempty"`
	Rule    string `json:"rule,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

func replayCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var o opts
	fs := newFlags("replay", &o)
	if err := parse(fs, args); err != nil {
		return fail(stderr, exitConfig, "replay: %v", err)
	}
	p, err := loadPeople(&o)
	if err != nil {
		return fail(stderr, exitConfig, "%v", err)
	}
	d, err := loadDraft(&o, p)
	if err != nil {
		return fail(stderr, exitConfig, "%v", err)
	}
	from, to, err := window(&o)
	if err != nil {
		return fail(stderr, exitConfig, "replay: %v", err)
	}
	pol := scope.Compile(d, p)
	r := scope.NewReplay(pol)
	enc := json.NewEncoder(stdout)
	_, err = eachFlow(&o, stdin, func(f scope.Flow) error {
		if (!from.IsZero() && f.Time.Before(from)) || (!to.IsZero() && !f.Time.Before(to)) {
			return nil
		}
		v := r.Add(f)
		if o.jsonOut {
			return enc.Encode(verdictLine{T: f.Time.UTC().Format(time.RFC3339Nano), Proto: f.Proto.String(), Src: f.Src.String(),
				Dst: f.Dst.String(), Port: f.Port, Verdict: v.Outcome.String(), Person: v.Person, Rule: v.Rule, Reason: v.Reason})
		}
		return nil
	})
	if err != nil {
		return fail(stderr, exitConfig, "%v", err)
	}
	if !o.jsonOut {
		fmt.Fprint(stdout, replayText(r, o.top))
	}
	if o.failOnDeny && r.Denied > 0 {
		return exitDenied
	}
	return 0
}

func replayText(r *scope.Replay, top int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Replayed %s flows: %s allowed, %s would be blocked", scope.Comma(r.Flows), scope.Comma(r.Allowed), scope.Comma(r.Denied))
	if r.NotVPN > 0 {
		fmt.Fprintf(&b, ", %s not from the VPN range", scope.Comma(r.NotVPN))
	}
	b.WriteString(".\n")
	keys := r.DeniedKeys()
	if len(keys) == 0 {
		b.WriteString("Nothing would be blocked.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "\nWould be blocked (%s destinations):\n", scope.Comma(len(keys)))
	for i, dk := range keys {
		if top > 0 && i == top {
			fmt.Fprintf(&b, "  ... and %s more\n", scope.Comma(len(keys)-top))
			break
		}
		who := dk.Person
		if who == "" {
			who = dk.Src.String() + " (no one)"
		}
		fmt.Fprintf(&b, "  %-10s %-22s %6s\n", who, dk.Key.String(), scope.Comma(dk.Count))
	}
	return b.String()
}

func exportCmd(args []string, stdout, stderr io.Writer) int {
	var o opts
	fs := newFlags("export", &o)
	if err := parse(fs, args); err != nil {
		return fail(stderr, exitConfig, "export: %v", err)
	}
	p, err := loadPeople(&o)
	if err != nil {
		return fail(stderr, exitConfig, "%v", err)
	}
	d, err := loadDraft(&o, p)
	if err != nil {
		return fail(stderr, exitConfig, "%v", err)
	}
	var text string
	switch o.format {
	case "nft":
		if o.watch && o.drop {
			return fail(stderr, exitConfig, "export: --watch refuses nothing, so --drop does not apply")
		}
		text, err = scope.ExportNft(d, p, scope.NftOptions{Table: o.table, Drop: o.drop, Watch: o.watch,
			LogGroup: o.logGroup, Source: filepath.Base(o.draft) + " and " + filepath.Base(o.people)})
		if err != nil {
			return fail(stderr, exitConfig, "export: %v", err)
		}
	case "allowedips":
		text = scope.ExportAllowedIPs(d, p)
	default:
		return fail(stderr, exitConfig, "export: --format %q: want nft or allowedips", o.format)
	}
	if err := output(&o, stdout, text); err != nil {
		return fail(stderr, exitFailure, "%v", err)
	}
	return 0
}

func checkCmd(args []string, stdout, stderr io.Writer) int {
	var o opts
	fs := newFlags("check", &o)
	if err := parse(fs, args); err != nil {
		return fail(stderr, exitConfig, "check: %v", err)
	}
	p, err := loadPeople(&o)
	if err != nil {
		return fail(stderr, exitConfig, "%v", err)
	}
	addrs := 0
	for _, per := range p.List {
		addrs += len(per.Addrs)
	}
	fmt.Fprintf(stdout, "%s: %d people, %d addresses, %d groups, VPN range %s.\n", o.people, len(p.List), addrs, len(p.GroupOrder), p.VPNNet)
	if o.draft != "" {
		d, err := loadDraft(&o, p)
		if err != nil {
			return fail(stderr, exitConfig, "%v", err)
		}
		if _, err := scope.ExportNft(d, p, scope.NftOptions{}); err != nil {
			return fail(stderr, exitConfig, "%v", err)
		}
		fmt.Fprintf(stdout, "%s: %s.\n", o.draft, d.Describe())
	}
	return 0
}

func stderrf(w io.Writer, format string, a ...any) { fmt.Fprintf(w, format, a...) }
