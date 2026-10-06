// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build js && wasm

// Command exit-wasm runs VPN Works Exit's own decision code in the browser
// demo: the exit's configuration reader, a client's policy through the
// Agent's request plan (what the exit decides before it dials), the source
// address a client leaves from, and the join of an Agent's record with an
// exit's. The page replays a recorded run; every decision and every count
// it shows that is not a recording comes from these calls.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"path"
	"strconv"
	"syscall/js"

	"vpnw.com/vpnw/internal/config"
	"vpnw.com/vpnw/internal/events"
	"vpnw.com/vpnw/internal/exit"
	"vpnw.com/vpnw/internal/version"
)

func main() {
	js.Global().Set("vpnwExit", js.ValueOf(map[string]any{
		"version":      exit.Version,
		"agentVersion": version.Version,
		"parse":        js.FuncOf(parseFn),
		"decide":       js.FuncOf(decideFn),
		"join":         js.FuncOf(joinFn),
	}))
	select {}
}

func out(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"ok":false,"error":"` + err.Error() + `"}`
	}
	return string(b)
}

type failure struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

func fail(err error) any { return out(failure{Error: err.Error()}) }

// load reads the exit's configuration file name from files, a JSON object
// of file names and contents that stands for the exit's folder (a page has
// no files of its own): the configuration and the client policy files it
// names.
func load(name, filesJSON string) (*exit.Config, error) {
	var files map[string]string
	if err := json.Unmarshal([]byte(filesJSON), &files); err != nil {
		return nil, errors.New("files: " + err.Error())
	}
	text, ok := files[name]
	if !ok {
		return nil, errors.New(name + ": no such file")
	}
	loader := func(name string) (*config.File, error) {
		src, ok := files[path.Base(name)]
		if !ok {
			return nil, errors.New(path.Base(name) + ": no such file")
		}
		return config.ParseFile(path.Base(name), src)
	}
	return exit.ParseConfig(text, name, loader)
}

type clientInfo struct {
	Name     string   `json:"name"`
	Describe string   `json:"describe"`
	Sources  []string `json:"sources"`
	Source   string   `json:"source"`
	Pool     string   `json:"pool,omitempty"`
	Default  string   `json:"default"`
	Allow    int      `json:"allow"`
	Deny     int      `json:"deny"`
	Private  bool     `json:"denyPrivate"`
}

// parseFn reads an exit's configuration. args: name, filesJSON.
func parseFn(_ js.Value, args []js.Value) any {
	c, err := load(args[0].String(), args[1].String())
	if err != nil {
		return fail(err)
	}
	var r struct {
		OK       bool         `json:"ok"`
		Name     string       `json:"name"`
		Listen   string       `json:"listen"`
		Clients  []clientInfo `json:"clients"`
		Warnings []string     `json:"warnings"`
	}
	r.OK, r.Name, r.Listen, r.Warnings = true, c.Name, c.Listen, c.Warnings
	for _, cl := range c.Clients {
		ci := clientInfo{Name: cl.Name, Describe: cl.Describe(), Default: cl.Policy.Default.String(),
			Allow: len(cl.Policy.Allow), Deny: len(cl.Policy.Deny), Private: cl.Policy.DenyPrivate}
		for _, a := range cl.Addresses() {
			ci.Sources = append(ci.Sources, a.String())
		}
		src, _ := cl.SourceFor("")
		ci.Source = src.String()
		if cl.Pool != nil {
			ci.Pool = cl.Pool.Name
		}
		r.Clients = append(r.Clients, ci)
	}
	return out(r)
}

type decision struct {
	OK       bool     `json:"ok"`
	Outcome  string   `json:"outcome"` // "allow", "denied" or "failed"
	Rule     string   `json:"rule,omitempty"`
	Text     string   `json:"text,omitempty"`
	Reason   string   `json:"reason,omitempty"`
	Error    string   `json:"error,omitempty"`
	LookedUp bool     `json:"lookedUp"`
	Addrs    []string `json:"addrs,omitempty"`
	Source   string   `json:"source,omitempty"`
}

// decideFn says what the exit does with one request from a client, before
// it dials. args: name, filesJSON (as for parseFn), client, target
// ("host:port"), dnsJSON (an object of names and their addresses; any other
// name does not resolve).
func decideFn(_ js.Value, args []js.Value) any {
	c, err := load(args[0].String(), args[1].String())
	if err != nil {
		return fail(err)
	}
	cl := c.Client(args[2].String())
	if cl == nil {
		return fail(errors.New("no client " + strconv.Quote(args[2].String())))
	}
	host, ps, err := net.SplitHostPort(args[3].String())
	if err != nil {
		return fail(errors.New("write the destination as host:port"))
	}
	port, err := strconv.Atoi(ps)
	if err != nil {
		return fail(errors.New("the port must be a number"))
	}
	var dns map[string][]string
	if err := json.Unmarshal([]byte(args[4].String()), &dns); err != nil {
		return fail(errors.New("dns: " + err.Error()))
	}
	lookup := func(h string) ([]net.IP, error) {
		var ips []net.IP
		for _, a := range dns[h] {
			if ip := net.ParseIP(a); ip != nil {
				ips = append(ips, ip)
			}
		}
		if len(ips) == 0 {
			return nil, errors.New("no such host")
		}
		return ips, nil
	}
	p := cl.Decide(host, port, lookup)
	d := decision{OK: true, Outcome: p.Outcome, Rule: p.Rule, Text: p.Text, Reason: p.Reason, Error: p.Error, LookedUp: p.LookedUp, Addrs: p.Addrs}
	if p.Outcome == "dial" {
		d.Outcome = "allow"
		src, _ := cl.SourceFor("")
		d.Source = src.String()
	}
	return out(d)
}

// joinFn matches an Agent's records with exits' records. args: agentJSONL,
// exitJSONL (several records may be joined end to end).
func joinFn(_ js.Value, args []js.Value) any {
	a, err := events.Read(bytes.NewReader([]byte(args[0].String())))
	if err != nil {
		return fail(errors.New("Agent records: " + err.Error()))
	}
	x, err := events.Read(bytes.NewReader([]byte(args[1].String())))
	if err != nil {
		return fail(errors.New("exit records: " + err.Error()))
	}
	r := exit.Join(a, x)
	var res struct {
		OK bool `json:"ok"`
		exit.JoinReport
		Complete bool `json:"complete"`
	}
	res.OK, res.JoinReport, res.Complete = true, r, r.OK()
	return out(res)
}
