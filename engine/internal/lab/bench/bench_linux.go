// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package bench runs one scenario for one app in a fresh test world: it
// starts the app and the probe on the device, carries out the timetable,
// and puts the bench's steps, the app's own log, the probe's log and the
// observers' arrivals into one recording, with the verdict.
package bench

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"vpnw.com/vpnw/internal/lab"
	"vpnw.com/vpnw/internal/lab/world"
)

// Config is one run.
type Config struct {
	App      lab.App
	Scenario lab.Scenario
	Seed     int64
	FaultFor time.Duration // a positive value replaces the scenario's fault length
	Interval time.Duration // the probe's interval; 50 ms when zero
	Self     string        // the vpnw-lab executable, for the client and the probe
	VPNW     string        // the vpnw executable, for the Agent's apps
	Dir      string        // the run's directory, created if missing
	Run      string        // the run's id; a random one when empty
	Env      []string      // more environment for the processes the bench starts
	UpWait   time.Duration // how long a client may take to bring its tunnel up; 10 s when zero
	Progress func(string)  // told about each step, if set
}

// Result is a finished run.
type Result struct {
	Recording *lab.Recording
	Verdict   *lab.Verdict
	Steps     []lab.Step    // the timetable as planned
	Setup     time.Duration // from the start of the world's building to the start step
	Took      time.Duration // the whole run, building and teardown included
}

// NewRunID returns a random run id such as "r-3f9a1c".
func NewRunID() string {
	var b [3]byte
	rand.Read(b[:])
	return "r-" + hex.EncodeToString(b[:])
}

// proc is a process the bench started, with one goroutine waiting for it.
type proc struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func (p *proc) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// waitFor waits for the process to end and kills it after limit.
func (p *proc) waitFor(limit time.Duration) {
	select {
	case <-p.done:
	case <-time.After(limit):
		p.cmd.Process.Kill()
		<-p.done
	}
}

type run struct {
	c         Config
	w         *world.World
	events    []lab.Event
	app       *proc
	probe     *proc
	clientLog string
	probeLog  string
	epoch     time.Time
	until     time.Time
}

func (r *run) progress(format string, a ...any) {
	if r.c.Progress != nil {
		r.c.Progress(fmt.Sprintf(format, a...))
	}
}

func (r *run) record(e lab.Event) {
	if e.T.IsZero() {
		e.T = time.Now()
	}
	r.events = append(r.events, e)
}

// Run runs one scenario for one app.
func Run(c Config) (*Result, error) {
	begin := time.Now()
	if c.Interval <= 0 {
		c.Interval = 50 * time.Millisecond
	}
	if c.Run == "" {
		c.Run = NewRunID()
	}
	if c.Self == "" {
		return nil, errors.New("the bench needs the vpnw-lab executable")
	}
	if c.App.Agent && c.VPNW == "" {
		return nil, fmt.Errorf("app %s needs the vpnw executable", c.App.Name)
	}
	if err := os.MkdirAll(c.Dir, 0o755); err != nil {
		return nil, err
	}
	r := &run{c: c, clientLog: filepath.Join(c.Dir, "client.jsonl"), probeLog: filepath.Join(c.Dir, "probe.jsonl")}
	steps := c.Scenario.Timetable(c.Seed, c.FaultFor)
	w, err := world.Build(filepath.Join(c.Dir, "device"))
	if err != nil {
		return nil, fmt.Errorf("building the test world: %w", err)
	}
	r.w = w
	defer func() {
		r.stopAll()
		w.Close()
	}()
	r.progress("world built in %s", time.Since(begin).Round(time.Millisecond))

	lead := 200 * time.Millisecond
	if c.App.Agent {
		lead = 700 * time.Millisecond
	}
	if !c.App.Agent {
		if err := r.startClient(); err != nil {
			return nil, err
		}
		if c.UpWait <= 0 {
			c.UpWait = 10 * time.Second
		}
		if err := r.waitUp(c.UpWait); err != nil {
			return nil, err
		}
	}
	r.epoch = time.Now().Add(lead)
	r.until = r.epoch.Add(lab.Duration(steps))
	if c.App.Agent {
		if err := r.startAgent(); err != nil {
			return nil, err
		}
	} else if err := r.startProbe(); err != nil {
		return nil, err
	}
	// The start is the epoch the plan and the probe's ticks count from.
	time.Sleep(time.Until(r.epoch))
	r.record(lab.Event{T: r.epoch, Ev: lab.EvStep, Step: lab.StepStart})
	setup := time.Since(begin)
	r.progress("%s, %s (seed %d): started", c.App.Name, c.Scenario.Name, c.Seed)
	fault := c.Scenario.Name
	for _, s := range steps[1:] {
		time.Sleep(time.Until(r.epoch.Add(s.At)))
		began := time.Now()
		switch s.Name {
		case lab.StepFaultOn:
			err = r.fault(true)
		case lab.StepFaultOff:
			err = r.fault(false)
		}
		if err != nil {
			return nil, fmt.Errorf("%s at %s: %w", s.Name, lab.Seconds(s.At), err)
		}
		// A step's time is when its action began, so the change it makes
		// comes at that time or after; the note says how long the action
		// took.
		e := lab.Event{T: began, Ev: lab.EvStep, Step: s.Name}
		if s.Name != lab.StepStop {
			e.Fault = fault
			e.Note = "took " + lab.Millis(time.Since(began))
		}
		r.record(e)
		r.progress("%s %s", s.Name, e.Fault)
	}
	if r.probe != nil {
		r.probe.waitFor(3 * time.Second)
	}
	// Probes still on their way get a moment to arrive.
	time.Sleep(500 * time.Millisecond)
	r.stopApp()
	rec, err := r.recording()
	if err != nil {
		return nil, err
	}
	res := &Result{Recording: rec, Verdict: lab.Decide(rec), Steps: steps, Setup: setup}
	r.stopAll()
	w.Close()
	res.Took = time.Since(begin)
	return res, nil
}

// start starts a command on the device.
func (r *run) start(cmd *exec.Cmd, what string) (*proc, error) {
	if err := r.w.Device.Start(cmd); err != nil {
		return nil, fmt.Errorf("starting %s: %w", what, err)
	}
	p := &proc{cmd: cmd, done: make(chan struct{})}
	go func() { cmd.Wait(); close(p.done) }()
	return p, nil
}

func (r *run) output(name string) (*os.File, error) {
	return os.OpenFile(filepath.Join(r.c.Dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
}

func (r *run) env() []string {
	return append(append(os.Environ(), "XDG_STATE_HOME="+filepath.Join(r.c.Dir, "state")), r.c.Env...)
}

// startClient starts the stand-in client on the device, logging to the
// run's client log.
func (r *run) startClient() error {
	out, err := r.output("client.out")
	if err != nil {
		return err
	}
	defer out.Close()
	cmd := exec.Command(r.c.Self, "client", "--mode", r.c.App.Name, "--resolv", r.w.Resolv, "--log", r.clientLog)
	cmd.Stdout, cmd.Stderr, cmd.Env = out, out, r.env()
	if r.app, err = r.start(cmd, "the client"); err != nil {
		return err
	}
	r.record(lab.Event{Ev: lab.EvApp, State: "started", Note: r.c.App.Name})
	return nil
}

func (r *run) probeArgs() []string {
	return []string{r.c.Self, "probe", "--run", r.c.Run, "--interval", r.c.Interval.String(),
		"--epoch", r.epoch.UTC().Format(time.RFC3339Nano), "--until", r.until.UTC().Format(time.RFC3339Nano),
		"--resolv", r.w.Resolv, "--log", r.probeLog, "--direct"}
}

func (r *run) startProbe() error {
	out, err := r.output("probe.out")
	if err != nil {
		return err
	}
	defer out.Close()
	cmd := exec.Command(r.c.Self, r.probeArgs()[1:]...)
	cmd.Stdout, cmd.Stderr, cmd.Env = out, out, r.env()
	r.probe, err = r.start(cmd, "the probe")
	return err
}

// startAgent starts the Agent on the device with the probe as its
// workload: sealed under vpnw guard, or with proxy settings only under
// vpnw run --backend env. Its path is the SOCKS5 proxy at the VPN server.
func (r *run) startAgent() error {
	args := []string{"guard", "--default", "allow"}
	if r.c.App.Name == "agent-env" {
		args = []string{"run", "--backend", "env"}
	}
	args = append(args, "--proxy", "socks5h://"+world.ServerAddr.String()+":"+strconv.Itoa(world.ProxyPort), "--no-save", "-q", "--")
	args = append(append(args, r.probeArgs()...), "--proxy", "env")
	out, err := r.output("agent.out")
	if err != nil {
		return err
	}
	defer out.Close()
	cmd := exec.Command(r.c.VPNW, args...)
	cmd.Stdout, cmd.Stderr, cmd.Env = out, out, r.env()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if r.app, err = r.start(cmd, "the Agent"); err != nil {
		return err
	}
	r.record(lab.Event{Ev: lab.EvApp, State: "started", Note: r.c.App.Name})
	return nil
}

// waitUp waits until the client says its tunnel is up.
func (r *run) waitUp(limit time.Duration) error {
	deadline := time.Now().Add(limit)
	for {
		b, _ := os.ReadFile(r.clientLog)
		if bytes.Contains(b, []byte(`"state":"up"`)) {
			return nil
		}
		if r.app.exited() {
			out, _ := os.ReadFile(filepath.Join(r.c.Dir, "client.out"))
			return fmt.Errorf("the client stopped before its tunnel came up: %s", strings.TrimSpace(string(out)))
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the client's tunnel did not come up within %s", limit)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (r *run) fault(on bool) error {
	w := r.w
	switch r.c.Scenario.Name {
	case lab.FaultServerSilent:
		if on {
			return w.SetServerFault(world.ServerSilent)
		}
		return w.SetServerFault("")
	case lab.FaultServerGone:
		return w.SetServerFault(world.ServerGone)
	case lab.FaultAppKilled:
		if on {
			r.kill()
			return nil
		}
		if r.c.App.Agent {
			return r.startAgent()
		}
		return r.startClient()
	case lab.FaultLinkDrop:
		if on {
			return w.LinkDown()
		}
		return w.LinkUp()
	case lab.FaultRoutePush:
		return w.PushRoute(on)
	case lab.FaultDNSChange:
		if on {
			return w.SetDNS(world.RouterDNS2)
		}
		return w.SetDNS(world.RouterAddr)
	}
	return fmt.Errorf("no fault for scenario %q", r.c.Scenario.Name)
}

// kill kills the app as a crash would: the client alone, or the Agent with
// everything it runs.
func (r *run) kill() {
	if r.app == nil {
		return
	}
	if r.c.App.Agent {
		syscall.Kill(-r.app.cmd.Process.Pid, syscall.SIGKILL)
	} else {
		r.app.cmd.Process.Kill()
	}
	<-r.app.done
	r.record(lab.Event{Ev: lab.EvApp, State: "killed", Note: r.c.App.Name})
	r.app = nil
}

// stopApp stops the app cleanly at the end of the run.
func (r *run) stopApp() {
	if r.app == nil {
		return
	}
	if r.c.App.Agent {
		// The Agent ends when its workload, the probe, does.
		select {
		case <-r.app.done:
		case <-time.After(3 * time.Second):
		}
	}
	r.app.cmd.Process.Signal(syscall.SIGTERM)
	r.app.waitFor(5 * time.Second)
	r.record(lab.Event{Ev: lab.EvApp, State: "stopped", Note: r.c.App.Name})
	r.app = nil
}

// stopAll makes sure nothing the bench started outlives the run.
func (r *run) stopAll() {
	for _, p := range []*proc{r.app, r.probe} {
		if p != nil && !p.exited() {
			if r.c.App.Agent && p == r.app {
				syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
			}
			p.cmd.Process.Kill()
			<-p.done
		}
	}
	r.app, r.probe = nil, nil
}

// recording puts the run's events together, in time order.
func (r *run) recording() (*lab.Recording, error) {
	events := append([]lab.Event(nil), r.events...)
	read := func(path string, keep string) error {
		f, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = lab.ReadEvents(f, filepath.Base(path), func(e lab.Event) error {
			if e.Ev == keep {
				events = append(events, e)
			}
			return nil
		})
		return err
	}
	if err := read(r.clientLog, lab.EvClient); err != nil {
		return nil, err
	}
	if err := read(r.probeLog, lab.EvSent); err != nil {
		return nil, err
	}
	events = append(events, r.w.Arrivals(r.c.Run)...)
	sort.SliceStable(events, func(i, j int) bool { return events[i].T.Before(events[j].T) })
	h := world.Header(r.c.Run, r.c.App.Name, r.c.Scenario.Name, r.c.Seed, int(r.c.Interval/time.Millisecond))
	h.T = r.epoch
	for _, e := range events {
		if e.Ev == lab.EvStep && e.Step == lab.StepStart {
			h.T = e.T
		}
	}
	return &lab.Recording{Header: h, Events: events}, nil
}
