// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"vpnw.com/vpnw/internal/lab"
	"vpnw.com/vpnw/internal/lab/bench"
	"vpnw.com/vpnw/internal/lab/client"
	"vpnw.com/vpnw/internal/lab/world"
	"vpnw.com/vpnw/internal/testnet"
)

func runCmd(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("run")
	var appName, scenario, vpnw, keep, out string
	var seed int64
	var faultFor, interval time.Duration
	var asJSON, verbose bool
	fs.StringVar(&appName, "app", "", "")
	fs.StringVar(&scenario, "scenario", "", "")
	fs.Int64Var(&seed, "seed", 1, "")
	fs.DurationVar(&faultFor, "fault-for", 0, "")
	fs.DurationVar(&interval, "interval", 50*time.Millisecond, "")
	fs.StringVar(&vpnw, "vpnw", "", "")
	fs.StringVar(&keep, "keep", "", "")
	fs.StringVar(&out, "o", "", "")
	fs.BoolVar(&asJSON, "json", false, "")
	fs.BoolVar(&verbose, "v", false, "")
	if err := parse(fs, args); err != nil {
		return fail(stderr, exitConfig, "run: %v", err)
	}
	if appName == "" || scenario == "" {
		return fail(stderr, exitConfig, "run: give --app NAME and --scenario NAME; vpnw-lab list shows them")
	}
	app, err := lab.FindApp(appName)
	if err != nil {
		return fail(stderr, exitConfig, "run: %v", err)
	}
	sc, err := lab.FindScenario(scenario)
	if err != nil {
		return fail(stderr, exitConfig, "run: %v", err)
	}
	if seed < 0 {
		return fail(stderr, exitConfig, "run: --seed must be 0 or more")
	}
	if faultFor < 0 || faultFor > 10*time.Minute {
		return fail(stderr, exitConfig, "run: --fault-for must be from 0 to 10m")
	}
	if interval < 10*time.Millisecond || interval > 10*time.Second {
		return fail(stderr, exitConfig, "run: --interval must be from 10ms to 10s")
	}
	self, err := os.Executable()
	if err != nil {
		return fail(stderr, exitFailure, "run: %v", err)
	}
	if app.Agent {
		if vpnw, err = findVPNW(vpnw, self); err != nil {
			return fail(stderr, exitConfig, "run: %v", err)
		}
	}
	// The world needs root in a user namespace of its own; the command runs
	// itself again inside one.
	if err := testnet.Reexec(); err != nil {
		return fail(stderr, exitUnavailable, "run: %v; the bench needs unprivileged user namespaces", err)
	}
	if err := world.Check(); err != nil {
		return fail(stderr, exitUnavailable, "run: %v", err)
	}
	dir := keep
	if dir == "" {
		if dir, err = os.MkdirTemp("", "vpnw-lab-"); err != nil {
			return fail(stderr, exitFailure, "run: %v", err)
		}
		defer os.RemoveAll(dir)
	}
	cfg := bench.Config{App: app, Scenario: sc, Seed: seed, FaultFor: faultFor, Interval: interval, Self: self, VPNW: vpnw, Dir: dir}
	if verbose {
		cfg.Progress = func(s string) { fmt.Fprintf(stderr, "vpnw-lab: %s\n", s) }
	}
	res, err := bench.Run(cfg)
	if err != nil {
		return fail(stderr, exitFailure, "run: %v", err)
	}
	if out != "" {
		f, err := os.Create(out)
		if err != nil {
			return fail(stderr, exitFailure, "run: %v", err)
		}
		_, err = res.Recording.WriteTo(f)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return fail(stderr, exitFailure, "run: %v", err)
		}
	}
	printVerdict(stdout, res.Verdict, asJSON)
	if !asJSON {
		fmt.Fprintf(stdout, "  ran %s; %s in all, building the world and starting the app included\n",
			lab.Seconds(lab.Duration(res.Steps)), lab.Seconds(res.Took))
	}
	return exitFor(res.Verdict)
}

// findVPNW finds the Agent's executable: the flag, then next to vpnw-lab,
// then on PATH.
func findVPNW(flagged, self string) (string, error) {
	if flagged != "" {
		if _, err := os.Stat(flagged); err != nil {
			return "", fmt.Errorf("--vpnw: %v", err)
		}
		return filepath.Abs(flagged)
	}
	next := filepath.Join(filepath.Dir(self), "vpnw")
	if _, err := os.Stat(next); err == nil {
		return next, nil
	}
	if p, err := exec.LookPath("vpnw"); err == nil {
		return filepath.Abs(p)
	}
	return "", errors.New("the Agent's apps need the vpnw executable: give --vpnw FILE")
}

func clientCmd(args []string, stderr io.Writer) int {
	fs := newFlags("client")
	var mode, server, addr, dns, homeDNS, homeNet, logFile string
	var o client.Options
	fs.StringVar(&mode, "mode", "", "")
	fs.StringVar(&server, "server", netip.AddrPortFrom(world.ServerAddr, world.TunnelPort).String(), "")
	fs.StringVar(&o.Dev, "dev", world.DeviceLink, "")
	fs.StringVar(&o.Tun, "tun", world.TunnelDev, "")
	fs.StringVar(&addr, "addr", netip.PrefixFrom(world.TunnelAddr, world.TunnelNet.Bits()).String(), "")
	fs.StringVar(&dns, "dns", world.TunnelPeer.String(), "")
	fs.StringVar(&homeDNS, "home-dns", world.RouterAddr.String(), "")
	fs.StringVar(&homeNet, "home-net", world.HomeNet.String(), "")
	fs.StringVar(&o.Resolv, "resolv", "", "")
	fs.StringVar(&logFile, "log", "", "")
	fs.DurationVar(&o.Keepalive, "keepalive", 0, "")
	fs.DurationVar(&o.DeadAfter, "dead-after", 0, "")
	fs.DurationVar(&o.Retry, "retry", 0, "")
	fs.DurationVar(&o.Settle, "settle", 0, "")
	if err := parse(fs, args); err != nil {
		return fail(stderr, exitConfig, "client: %v", err)
	}
	var err error
	if o.Mode, err = client.FindMode(mode); err != nil {
		return fail(stderr, exitConfig, "client: %v", err)
	}
	if o.Resolv == "" {
		return fail(stderr, exitConfig, "client: give --resolv FILE, the device's DNS setting")
	}
	if o.Server, err = netip.ParseAddrPort(server); err != nil || !o.Server.Addr().Is4() {
		return fail(stderr, exitConfig, "client: --server %q: want an IPv4 address and port", server)
	}
	for _, p := range []struct {
		flag, val string
		dst       *netip.Addr
	}{{"dns", dns, &o.DNS}, {"home-dns", homeDNS, &o.HomeDNS}} {
		if *p.dst, err = netip.ParseAddr(p.val); err != nil || !p.dst.Is4() {
			return fail(stderr, exitConfig, "client: --%s %q: want an IPv4 address", p.flag, p.val)
		}
	}
	if o.Addr, err = netip.ParsePrefix(addr); err != nil || !o.Addr.Addr().Is4() {
		return fail(stderr, exitConfig, "client: --addr %q: want an IPv4 address with a prefix", addr)
	}
	if o.HomeNet, err = netip.ParsePrefix(homeNet); err != nil || !o.HomeNet.Addr().Is4() {
		return fail(stderr, exitConfig, "client: --home-net %q: want an IPv4 range", homeNet)
	}
	var log io.Writer = stderr
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return fail(stderr, exitFailure, "client: %v", err)
		}
		defer f.Close()
		log = f
	}
	stop := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; close(stop) }()
	if err := client.Run(o, log, stop); err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			return fail(stderr, exitUnavailable, "client: %v (it needs root, or CAP_NET_ADMIN in its network namespace)", err)
		}
		return fail(stderr, exitFailure, "client: %v", err)
	}
	return 0
}
