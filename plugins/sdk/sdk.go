// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package sdk is how a VPN Works plugin is written in Go.
//
// A plugin is a WebAssembly module that vpnw loads and runs in a sandbox. It
// cannot open files or sockets. It talks to vpnw only through the hooks it
// registers here and the few host calls below, each of which its manifest
// (plugin.toml) must ask for.
//
// A minimal Observer:
//
//	package main
//
//	import "github.com/VPNWorks/vpnw/plugins/sdk"
//
//	func init() {
//		sdk.Register(sdk.Plugin{
//			OnEvent: func(e *sdk.Event) error {
//				if e.Type == "policy.deny" {
//					sdk.Stderr("denied: " + e.Str("reason") + "\n")
//				}
//				return nil
//			},
//		})
//	}
//
//	func main() {}
//
// Build it with
//
//	GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o plugin.wasm .
//
// Register is called from init, not main: vpnw starts a plugin as a library
// (a WASI reactor), so main never runs.
package sdk

import (
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

// ABI is the plugin interface version this package speaks. vpnw refuses a
// plugin built for an ABI it does not know.
const ABI = 1

// Event is one event from the run, as vpnw records it. Events describe
// decisions, never payloads: no application data, URL paths or headers.
type Event struct {
	V      int            `json:"v"`
	TS     time.Time      `json:"ts"`
	Type   string         `json:"type"`
	Run    string         `json:"run"`
	PID    int            `json:"pid,omitempty"`
	Path   string         `json:"path,omitempty"`
	Conn   uint64         `json:"conn,omitempty"`
	Fields map[string]any `json:"fields,omitempty"`
	// Raw is the event exactly as vpnw sent it, one JSON object.
	Raw []byte `json:"-"`
}

// Str returns a string field, or "".
func (e *Event) Str(k string) string {
	s, _ := e.Fields[k].(string)
	return s
}

// Int returns a numeric field, or 0.
func (e *Event) Int(k string) int64 {
	switch v := e.Fields[k].(type) {
	case float64:
		return int64(v)
	case json.Number:
		n, _ := v.Int64()
		return n
	case string:
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	}
	return 0
}

// Request is one connection a Guard is asked about. The policy has already
// allowed it; a Guard can only refuse it.
type Request struct {
	Run   string `json:"run"`
	Conn  uint64 `json:"conn"`
	PID   int    `json:"pid,omitempty"`
	Path  string `json:"path"`
	Host  string `json:"host,omitempty"` // empty when the program asked for an address
	IP    string `json:"ip,omitempty"`   // the address asked for, when there was no name
	Port  int    `json:"port"`
	Proto string `json:"proto"` // "http-connect", "http" or "socks5"
}

// Config is what vpnw tells a plugin when it starts.
type Config struct {
	// Plugin is this plugin's name from its manifest.
	Plugin string `json:"plugin"`
	// Command is the vpnw command running: "run", "trace", "guard" or "advise".
	Command string `json:"command"`
	// Settings are the plugin's own settings, given with --set NAME.KEY=VALUE.
	Settings map[string]string `json:"settings"`
	// Color is true when the console is a terminal that shows colour.
	Color bool `json:"color"`
	// TZOffset and TZName are the local time zone (a plugin has none).
	TZOffset int    `json:"tz_offset"`
	TZName   string `json:"tz_name"`
}

// Zone returns the local time zone vpnw passed in.
func (c *Config) Zone() *time.Location {
	if c.TZName == "" && c.TZOffset == 0 {
		return time.UTC
	}
	return time.FixedZone(c.TZName, c.TZOffset)
}

// Plugin holds the hooks a plugin implements. Which ones vpnw calls depends
// on the type in the manifest:
//
//	observer  OnEvent for every event of a run, then Finish
//	advisor   OnEvent for every event of the traces it is given, then Finish,
//	          where it writes its advice with Stdout
//	guard     OnDecide for every connection the policy allowed
//
// Init is called first for every type. Any hook may be nil.
type Plugin struct {
	Init     func(c *Config) error
	OnEvent  func(e *Event) error
	OnDecide func(r *Request) (deny bool, reason string)
	Finish   func() error
	// RawEvents hands OnEvent the event as JSON in Event.Raw only, without
	// decoding it into the other fields. Decoding JSON is a large share of
	// a plugin's time, so a plugin that decodes events its own way should
	// not pay for it twice.
	RawEvents bool
}

var registered *Plugin

// Register installs the plugin's hooks. Call it once, from init.
func Register(p Plugin) {
	registered = &p
}

// Stdout writes to vpnw's standard output. Needs the "console" permission.
func Stdout(s string) { write(1, []byte(s)) }

// Stderr writes to vpnw's standard error. Needs the "console" permission.
func Stderr(s string) { write(2, []byte(s)) }

// Log writes a line to vpnw's plugin log, shown with --verbose. Always
// allowed.
func Log(s string) { logLine([]byte(s)) }

// Emit adds an event to the run's record. vpnw names it
// "plugin.<plugin>.<typ>" so it can never pass for one of vpnw's own events.
// Needs the "events.emit" permission.
func Emit(typ string, fields map[string]any) {
	b, err := json.Marshal(struct {
		Type   string         `json:"type"`
		Fields map[string]any `json:"fields,omitempty"`
	}{typ, fields})
	if err != nil {
		return
	}
	emit(b)
}

// The hook bodies, shared by the WebAssembly exports and the tests.

func doInit(b []byte) error {
	if registered == nil {
		return errors.New("the plugin never called sdk.Register")
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return err
	}
	if c.Settings == nil {
		c.Settings = map[string]string{}
	}
	if registered.Init != nil {
		return registered.Init(&c)
	}
	return nil
}

func doEvent(b []byte) error {
	if registered == nil || registered.OnEvent == nil {
		return nil
	}
	if registered.RawEvents {
		return registered.OnEvent(&Event{Raw: b})
	}
	var e Event
	if err := json.Unmarshal(b, &e); err != nil {
		return err
	}
	e.Raw = b
	return registered.OnEvent(&e)
}

func doDecide(b []byte) (bool, string, error) {
	if registered == nil || registered.OnDecide == nil {
		return false, "", nil
	}
	var r Request
	if err := json.Unmarshal(b, &r); err != nil {
		return true, "", err
	}
	deny, reason := registered.OnDecide(&r)
	return deny, reason, nil
}

func doFinish() error {
	if registered == nil || registered.Finish == nil {
		return nil
	}
	return registered.Finish()
}
