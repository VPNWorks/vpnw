// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Command vpnw-lab is a test bench for VPN apps: it runs an app inside a
// private test network, keeps a probe sending traffic, breaks things on a
// timetable, and says whether anything left outside the tunnel.
//
//	vpnw-lab run      run one scenario for one app (Linux)
//	vpnw-lab verdict  decide recorded runs again
//	vpnw-lab list     list the scenarios and the apps
//	vpnw-lab client   a stand-in VPN client, which the bench starts (Linux)
//	vpnw-lab probe    the probe, which the bench starts
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"vpnw.com/vpnw/internal/lab"
	"vpnw.com/vpnw/internal/lab/probe"
	"vpnw.com/vpnw/internal/lab/wire"
	"vpnw.com/vpnw/internal/lab/world"
)

const usage = `vpnw-lab %s: a test bench for VPN apps.

Usage:
  vpnw-lab run     --app NAME --scenario NAME [--seed N] [options] [-o FILE]
  vpnw-lab verdict [--json] FILE...
  vpnw-lab list
  vpnw-lab client  --mode MODE --resolv FILE [options]
  vpnw-lab probe   --run ID --resolv FILE [--direct] [--proxy URL] [options]
  vpnw-lab version

run      builds a private test network in network namespaces (Linux, needs
         user namespaces, nftables and the TUN driver), starts the app under
         test on its device with a probe that sends a DNS query, a TCP
         connection and a UDP datagram every 50 ms, breaks things on the
         scenario's timetable, and says whether anything left the device
         outside the tunnel. Observers on the far side record every arrival
         with its source address.
verdict  reads recordings made by run and decides each again: pass, leak or
         no traffic, which probes leaked, and when.
list     lists the scenarios and the apps.
client   runs a stand-in VPN client on a TUN device. run starts it.
probe    runs the probe. run starts it.

Options for run:
  --app NAME          the app under test (vpnw-lab list shows them)
  --scenario NAME     the scenario (vpnw-lab list shows them)
  --seed N            seed for the timetable's jitter (default 1)
  --fault-for D       how long the fault lasts, such as 5s (default: the
                      scenario's own)
  --interval D        the probe's interval (default 50ms)
  --vpnw FILE         the vpnw executable, for the Agent's apps (default: next
                      to vpnw-lab, then on PATH)
  --keep DIR          keep the run's files in DIR: the client's and the
                      probe's logs and the device's DNS setting
  -o FILE             write the run's recording to FILE (JSON Lines)
  --json              print the verdict as JSON
  -v                  print each step as it happens

Exit codes: 0 pass; 120 a leak was found; 121 usage or input error, with
the file and line; 122 not possible on this machine; 124 any other failure,
a run that carried no traffic included.
`

const (
	exitLeak        = 120
	exitConfig      = 121
	exitUnavailable = 122
	exitFailure     = 124
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, usage, lab.Version)
		return exitConfig
	}
	switch args[0] {
	case "run":
		return runCmd(args[1:], stdout, stderr)
	case "verdict":
		return verdictCmd(args[1:], stdin, stdout, stderr)
	case "list":
		return listCmd(stdout)
	case "client":
		return clientCmd(args[1:], stderr)
	case "probe":
		return probeCmd(args[1:], stdout, stderr)
	case "version", "--version", "-V":
		fmt.Fprintf(stdout, "vpnw-lab %s (%s/%s, %s)\n", lab.Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return 0
	case "help", "-h", "--help":
		fmt.Fprintf(stdout, usage, lab.Version)
		return 0
	}
	fmt.Fprintf(stderr, "vpnw-lab: unknown command %q; see vpnw-lab help\n", args[0])
	return exitConfig
}

func fail(stderr io.Writer, code int, format string, a ...any) int {
	fmt.Fprintf(stderr, "vpnw-lab: "+format+"\n", a...)
	return code
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("vpnw-lab "+name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
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

// exitFor is the exit code for a verdict.
func exitFor(v *lab.Verdict) int {
	switch v.Status {
	case lab.Leak:
		return exitLeak
	case lab.NoTraffic:
		return exitFailure
	}
	return 0
}

func printVerdict(w io.Writer, v *lab.Verdict, asJSON bool) {
	if asJSON {
		b, _ := json.Marshal(v.Report())
		fmt.Fprintf(w, "%s\n", b)
		return
	}
	fmt.Fprint(w, v.Text())
}

func verdictCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlags("verdict")
	asJSON := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return fail(stderr, exitConfig, "verdict: %v", err)
	}
	if fs.NArg() == 0 {
		return fail(stderr, exitConfig, "verdict: give one or more recordings (\"-\" is standard input)")
	}
	code := 0
	for _, name := range fs.Args() {
		var r io.Reader = stdin
		if name != "-" {
			f, err := os.Open(name)
			if err != nil {
				return fail(stderr, exitConfig, "%v", err)
			}
			defer f.Close()
			r = f
		}
		rec, err := lab.ReadRecording(r, name)
		if err != nil {
			return fail(stderr, exitConfig, "%v", err)
		}
		v := lab.Decide(rec)
		printVerdict(stdout, v, *asJSON)
		switch c := exitFor(v); {
		case c == exitLeak:
			code = exitLeak
		case c != 0 && code == 0:
			code = c
		}
	}
	return code
}

func listCmd(stdout io.Writer) int {
	fmt.Fprintln(stdout, "Scenarios:")
	for _, s := range lab.Scenarios {
		fmt.Fprintf(stdout, "  %-15s %s", s.Name, s.Title)
		steps := s.Timetable(1, 0)
		fmt.Fprintf(stdout, " (about %s)\n", lab.Seconds(lab.Duration(steps)))
		if s.On != "" {
			fmt.Fprintf(stdout, "  %-15s   on:  %s\n", "", s.On)
		}
		if s.Off != "" {
			fmt.Fprintf(stdout, "  %-15s   off: %s\n", "", s.Off)
		}
	}
	fmt.Fprintln(stdout, "\nApps:")
	for _, a := range lab.Apps {
		fmt.Fprintf(stdout, "  %-15s %s: %s\n", a.Name, a.Title, a.What)
	}
	return 0
}

func probeCmd(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("probe")
	var o probe.Options
	var epoch, until, target, logFile, proxy string
	var tcpPort, udpPort, dnsPort uint
	fs.StringVar(&o.Run, "run", "", "")
	fs.DurationVar(&o.Interval, "interval", 50*time.Millisecond, "")
	fs.StringVar(&epoch, "epoch", "", "")
	fs.StringVar(&until, "until", "", "")
	fs.StringVar(&o.Resolv, "resolv", "", "")
	fs.StringVar(&target, "target", world.Observer.String(), "")
	fs.UintVar(&tcpPort, "tcp-port", world.TCPPort, "")
	fs.UintVar(&udpPort, "udp-port", world.UDPPort, "")
	fs.UintVar(&dnsPort, "dns-port", world.DNSPort, "")
	fs.BoolVar(&o.Direct, "direct", false, "")
	fs.StringVar(&proxy, "proxy", "", "")
	fs.StringVar(&logFile, "log", "", "")
	if err := parse(fs, args); err != nil {
		return fail(stderr, exitConfig, "probe: %v", err)
	}
	parseTime := func(flag, s string) (time.Time, error) {
		if s == "" {
			return time.Time{}, nil
		}
		t, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			return t, fmt.Errorf("--%s %q: want a time such as 2026-10-05T21:00:00Z", flag, s)
		}
		return t, nil
	}
	var err error
	if o.Epoch, err = parseTime("epoch", epoch); err != nil {
		return fail(stderr, exitConfig, "probe: %v", err)
	}
	if o.Epoch.IsZero() {
		o.Epoch = time.Now()
	}
	if o.Until, err = parseTime("until", until); err != nil {
		return fail(stderr, exitConfig, "probe: %v", err)
	}
	if o.Target, err = netip.ParseAddr(target); err != nil || !o.Target.Is4() {
		return fail(stderr, exitConfig, "probe: --target %q: want an IPv4 address", target)
	}
	for _, p := range []uint{tcpPort, udpPort, dnsPort} {
		if p == 0 || p > 65535 {
			return fail(stderr, exitConfig, "probe: ports must be from 1 to 65535")
		}
	}
	o.TCPPort, o.UDPPort, o.DNSPort = uint16(tcpPort), uint16(udpPort), uint16(dnsPort)
	if o.Direct && o.Resolv == "" {
		return fail(stderr, exitConfig, "probe: --direct needs --resolv FILE, the device's DNS setting")
	}
	if proxy == "env" {
		proxy = os.Getenv("ALL_PROXY")
		if proxy == "" {
			proxy = os.Getenv("all_proxy")
		}
		if proxy == "" {
			return fail(stderr, exitConfig, "probe: --proxy env, but ALL_PROXY is not set")
		}
	}
	o.Proxy = proxy
	if err := wire.CheckRun(o.Run); err != nil {
		return fail(stderr, exitConfig, "probe: --run: %v", err)
	}
	if o.Interval <= 0 {
		return fail(stderr, exitConfig, "probe: --interval must be above 0")
	}
	if !o.Direct && o.Proxy == "" {
		return fail(stderr, exitConfig, "probe: nothing to send: give --direct, --proxy URL, or both")
	}
	if o.Proxy != "" {
		if _, err := probe.ParseProxy(o.Proxy); err != nil {
			return fail(stderr, exitConfig, "probe: %v", err)
		}
	}
	out := stdout
	if logFile != "" && logFile != "-" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return fail(stderr, exitFailure, "probe: %v", err)
		}
		defer f.Close()
		out = f
	}
	stop := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; close(stop) }()
	if _, err := probe.Run(o, out, stop); err != nil {
		return fail(stderr, exitFailure, "probe: %v", err)
	}
	return 0
}
