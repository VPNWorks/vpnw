// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"io"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"vpnw.com/vpnw/internal/scope"
	"vpnw.com/vpnw/internal/scope/record"
)

func recordCmd(args []string, stdout, stderr io.Writer) int {
	var o opts
	var group int
	var duration time.Duration
	var noInstall bool
	fs := newFlags("record", &o)
	fs.StringVar(&o.out, "out", "", "")
	fs.IntVar(&group, "group", 100, "")
	fs.DurationVar(&duration, "duration", 0, "")
	fs.BoolVar(&noInstall, "no-install", false, "")
	if err := parse(fs, args); err != nil {
		return fail(stderr, exitConfig, "record: %v", err)
	}
	if group < 1 || group > 65535 {
		return fail(stderr, exitConfig, "record: --group must be from 1 to 65535")
	}
	p, err := loadPeople(&o)
	if err != nil {
		return fail(stderr, exitConfig, "%v", err)
	}
	w := stdout
	if o.out != "" && o.out != "-" {
		f, err := os.OpenFile(o.out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return fail(stderr, exitFailure, "record: %v", err)
		}
		defer f.Close()
		w = f
	}
	l, err := record.Listen(uint16(group))
	if err != nil {
		return fail(stderr, exitUnavailable, "record: %v (recording needs root or CAP_NET_ADMIN on the gateway)", err)
	}
	defer l.Close()
	if !noInstall {
		if err := record.Install(p.VPNNet, uint16(group)); err != nil {
			return fail(stderr, exitUnavailable, "record: %v", err)
		}
		defer record.Remove()
	}
	var stop atomic.Bool
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; stop.Store(true) }()
	fw := scope.NewFlowWriter(w)
	start := time.Now()
	n := 0
	for !stop.Load() && (duration == 0 || time.Since(start) < duration) {
		l.SetDeadline(time.Now().Add(250 * time.Millisecond))
		flows, err := l.Read()
		if err != nil {
			fw.Flush()
			return fail(stderr, exitFailure, "record: %v", err)
		}
		for _, f := range flows {
			fw.Write(f)
			n++
		}
		if len(flows) > 0 {
			fw.Flush()
		}
	}
	fw.Flush()
	stderrf(stderr, "vpnw-scope: recorded %s new connections from %s in %s", scope.Comma(n), p.VPNNet, time.Since(start).Round(time.Second))
	if l.Skipped > 0 {
		stderrf(stderr, " (%s packets skipped: not IPv4 tcp or udp)", scope.Comma(l.Skipped))
	}
	stderrf(stderr, ".\n")
	return 0
}
