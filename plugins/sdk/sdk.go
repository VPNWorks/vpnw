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
	// Client is the exit's client the connection came from, when the Guard
	// runs at an exit (vpnw exit serve); "" in a run.
	Client string `json:"client,omitempty"`
}

// Config is what vpnw tells a plugin when it starts.
type Config struct {
	// Plugin is this plugin's name from its manifest.
	Plugin string `json:"plugin"`
	// Command is the vpnw command running: "run", "trace", "guard",
	// "advise", or "exit" at an exit (vpnw exit serve).
	Command string `json:"command"`
	// Settings are the plugin's own settings, given with --set NAME.KEY=VALUE.
	Settings map[string]string `json:"settings"`
	// Color is true when the console is a terminal that shows colour.
	Color bool `json:"color"`
	// TZOffset and TZName are the local time zone (a plugin has none).
	TZOffset int    `json:"tz_offset"`
	TZName   string `json:"tz_name"`
	// Run is the run's identifier in run, trace, guard and exit; "" in
	// advise.
	Run string `json:"run"`
	// File is the path of the file vpnw opened for this plugin, if its
	// manifest asks for "file.write" and the command opened one; "" if not.
	// The plugin can only append to it, with FileWrite.
	File string `json:"file"`
	// Folder is the path of the folder vpnw opened for this plugin, if its
	// manifest asks for "folder.read" and the command opened one; "" if not.
	// The plugin can only list it and read the files in it, with FolderList
	// and FolderRead.
	Folder string `json:"folder"`
}

// TunnelRequest is what vpnw asks a tunnel plugin: a WireGuard config to
// bring a tunnel up with.
type TunnelRequest struct {
	Run string `json:"run"`
	// Reason is why vpnw asks:
	//
	//	start    the run is starting; no tunnel is up yet
	//	due      the config in use (Current) was kept as long as asked
	//	failed   the tunnel of Config didn't come up, or, when Config is
	//	         Current, the tunnel in use stopped answering
	//	refused  vpnw refused Config: not a WireGuard config, a shell hook,
	//	         no DNS server, ...
	Reason string `json:"reason"`
	// Current is the config in use, "" before one is up.
	Current string `json:"current"`
	// Config is the config a failure or a refusal is about, and Error what
	// went wrong with it.
	Config string `json:"config"`
	Error  string `json:"error"`
}

// TunnelConfig is a WireGuard config a tunnel plugin hands to vpnw.
type TunnelConfig struct {
	// Name is how the record names it: a file name, say. Printable, at most
	// 128 characters.
	Name string
	// Config is the config in the wg-quick format, at most 64 KiB. vpnw
	// checks it as it checks a --wireguard file.
	Config string
	// Keep is how long vpnw uses it before asking again; 0 is until it
	// stops working. vpnw keeps a config at least 5 seconds. Handing back
	// the config in use keeps it.
	Keep time.Duration
}

// NoConfig is OnTunnel's error when it has no config to give: vpnw records
// why, keeps the tunnel in use if there is one, and doesn't stop the plugin.
func NoConfig(why string) error { return noConfig(why) }

type noConfig string

func (n noConfig) Error() string { return string(n) }

// Line is one line of an Advisor's input, for an Advisor whose manifest says
// input = "lines": the file it came from (as the user named it), its line
// number from 1, and its bytes exactly as they are, without the newline.
type Line struct {
	File string `json:"file"`
	N    int    `json:"line"`
	Text []byte `json:"-"`
	// Partial is true for a last line that has no newline at its end.
	Partial bool `json:"partial,omitempty"`
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
//	tunnel    OnTunnel when vpnw needs a WireGuard config
//
// Init is called first for every type. Any hook may be nil.
type Plugin struct {
	Init     func(c *Config) error
	OnEvent  func(e *Event) error
	OnDecide func(r *Request) (deny bool, reason string)
	// OnTunnel hands vpnw a config. It returns NoConfig(why) when it has
	// none to give; any other error stops the plugin.
	OnTunnel func(r *TunnelRequest) (*TunnelConfig, error)
	Finish   func() error
	// OnLine replaces OnEvent for an Advisor whose manifest says
	// input = "lines": it gets every line of its input files as it is.
	OnLine func(l *Line) error
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

// ErrNoFile is FileWrite's error when vpnw has no file open for the plugin,
// the write is too big (over 1 MiB) or the file is full (1 GiB), or the
// write itself failed; vpnw's plugin log (--verbose) says which.
var ErrNoFile = errors.New("vpnw could not write the plugin's file")

// FileWrite appends b to the plugin's file. Needs the "file.write"
// permission. Writes go straight to the file, so what was written is there
// even if vpnw is killed.
func FileWrite(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if fileWrite(b) != 0 {
		return ErrNoFile
	}
	return nil
}

// FileSync asks vpnw to flush the plugin's file to disk. Needs the
// "file.write" permission.
func FileSync() error {
	if fileSync() != 0 {
		return ErrNoFile
	}
	return nil
}

// FolderEntry is one file in the plugin's folder.
type FolderEntry struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// ErrNoFolder is the error of FolderList and FolderRead when vpnw has no
// folder open for the plugin, or the listing or the read failed; vpnw's
// plugin log (--verbose) says why.
var ErrNoFolder = errors.New("vpnw could not read the plugin's folder")

// folderFailed is what the folder host calls return when they fail.
const folderFailed = 0xFFFFFFFF

// FolderList lists the regular files directly in the plugin's folder, in
// name order, with their sizes. Needs the "folder.read" permission.
func FolderList() ([]FolderEntry, error) {
	b, err := fetch(4096, folderList)
	if err != nil {
		return nil, err
	}
	var list []FolderEntry
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	return list, nil
}

// FolderRead reads one file of the plugin's folder: a name from
// FolderList, of a file of at most 1 MiB. Needs the "folder.read"
// permission.
func FolderRead(name string) ([]byte, error) {
	return fetch(16<<10, func(buf []byte) uint32 { return folderRead(name, buf) })
}

// fetch calls a host call that fills buf when what it gives fits, and
// otherwise says how big it is; it tries again with a buffer that big.
func fetch(size int, call func(buf []byte) uint32) ([]byte, error) {
	buf := make([]byte, size)
	for range 4 {
		n := call(buf)
		switch {
		case n == folderFailed:
			return nil, ErrNoFolder
		case int(n) <= len(buf):
			return buf[:n], nil
		}
		buf = make([]byte, n)
	}
	return nil, ErrNoFolder
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
	if registered != nil && registered.OnLine != nil {
		var w struct {
			File    string  `json:"file"`
			N       int     `json:"line"`
			Text    *string `json:"text"`
			B64     []byte  `json:"b64"`
			Partial bool    `json:"partial"`
		}
		if err := json.Unmarshal(b, &w); err != nil {
			return err
		}
		l := &Line{File: w.File, N: w.N, Partial: w.Partial, Text: w.B64}
		if w.Text != nil {
			l.Text = []byte(*w.Text)
		}
		return registered.OnLine(l)
	}
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

// doTunnel runs OnTunnel. It returns the offer as vpnw reads it, or none
// and why.
func doTunnel(b []byte) (offer []byte, none bool, why string, err error) {
	if registered == nil || registered.OnTunnel == nil {
		return nil, true, "this plugin hands over no configs", nil
	}
	var r TunnelRequest
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, false, "", err
	}
	c, err := registered.OnTunnel(&r)
	var nc noConfig
	switch {
	case errors.As(err, &nc):
		return nil, true, string(nc), nil
	case err != nil:
		return nil, false, "", err
	case c == nil:
		return nil, true, "", nil
	}
	keep := int64(c.Keep / time.Second)
	if c.Keep > 0 && keep == 0 {
		keep = 1
	}
	offer, err = json.Marshal(struct {
		Name   string `json:"name"`
		Config string `json:"config"`
		Keep   int64  `json:"keep,omitempty"`
	}{c.Name, c.Config, keep})
	return offer, false, "", err
}
