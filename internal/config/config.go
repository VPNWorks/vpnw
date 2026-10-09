// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// File is one validated configuration file.
//
//	version = 1
//	name = "research"
//
//	[network]            # the path this file uses by default
//	type = "proxy"
//	url  = "socks5://127.0.0.1:1080"
//
//	[paths.office]       # named paths, chosen with --via office
//	type = "proxy"
//	url  = "socks5://10.0.0.2:1080"
//	dns  = "remote"
//
//	[policy]
//	default      = "deny"
//	deny_private = true
//	allow = ["github.com", "*.githubusercontent.com"]
//
//	[trace]
//	enabled = true
//	format  = "jsonl"
//	out     = "trace.jsonl"
type File struct {
	Source  string
	Version int
	Name    string
	Network *PathSpec
	Paths   map[string]*PathSpec
	Policy  *PolicySpec
	Trace   *TraceSpec
}

// PathSpec describes one network path.
type PathSpec struct {
	Name string // "network" for [network], otherwise the name in [paths.NAME]
	Type string // "direct" or "proxy"
	URL  string // for proxy: socks5://, socks5h://, http://, https:// or socks5+tls://
	// URLs is a list of exits, used in order with failover, instead of URL.
	URLs []string
	DNS  string // "local" or "remote"; defaults: direct=local, proxy=remote
	// CAFile holds the certificates to trust for a proxy reached over TLS,
	// and TokenFile the token sent as its password. Relative names start
	// from the folder of File, the file this path was read from.
	CAFile    string
	TokenFile string
	// WGConfig is the wg-quick file of a WireGuard path.
	WGConfig string
	File     string
	Line     int
}

// PolicySpec is the [policy] table as written.
type PolicySpec struct {
	Default        string // "allow", "deny" or "" (implied)
	DenyPrivate    bool
	DenyPrivateSet bool
	Allow          []string
	Deny           []string
	Line           int
}

// TraceSpec is the [trace] table.
type TraceSpec struct {
	Enabled bool
	Format  string // "text" or "jsonl"
	Out     string
}

var pathName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

var schema = map[string][]string{
	"":        {"version", "name"},
	"network": {"name", "type", "url", "urls", "dns", "ca_file", "token_file", "config"},
	"path":    {"type", "url", "urls", "dns", "ca_file", "token_file", "config"},
	"policy":  {"default", "deny_private", "allow", "deny"},
	"trace":   {"enabled", "format", "out"},
}

// Load reads and validates a file from disk.
func Load(path string) (*File, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, &Error{File: path, Msg: "cannot read the file: " + errText(err)}
	}
	if st.IsDir() {
		return nil, &Error{File: path, Msg: "is a directory, not a configuration file"}
	}
	if st.Size() > MaxSize {
		return nil, &Error{File: path, Msg: fmt.Sprintf("file is larger than %d bytes", MaxSize)}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, &Error{File: path, Msg: "cannot read the file: " + errText(err)}
	}
	return ParseFile(path, string(b))
}

func errText(err error) string {
	if pe, ok := err.(*os.PathError); ok {
		return pe.Err.Error()
	}
	return err.Error()
}

// ParseFile parses and validates src; name is used in error messages.
func ParseFile(name, src string) (*File, error) {
	doc, err := Parse(src)
	if err != nil {
		if e, ok := err.(*Error); ok {
			e.File = name
		}
		return nil, err
	}
	f, err := fromDoc(doc)
	if err != nil {
		if e, ok := err.(*Error); ok {
			e.File = name
		}
		return nil, err
	}
	f.Source = name
	if f.Network != nil {
		f.Network.File = name
	}
	for _, p := range f.Paths {
		p.File = name
	}
	return f, nil
}

func fromDoc(doc *Doc) (*File, error) {
	f := &File{Paths: map[string]*PathSpec{}}
	root := doc.Tables[""]
	if err := checkKeys(root, "", ""); err != nil {
		return nil, err
	}
	v, ok := root.Keys["version"]
	if !ok {
		return nil, &Error{Line: 1, Msg: "missing version = 1 at the top of the file"}
	}
	if v.Kind != KInt {
		return nil, &Error{Line: v.Line, Msg: "version must be a number"}
	}
	if v.Int != 1 {
		return nil, &Error{Line: v.Line, Msg: fmt.Sprintf("unsupported version %d; this engine reads version 1", v.Int)}
	}
	f.Version = 1
	if n, ok := root.Keys["name"]; ok {
		s, err := wantString(n, "name")
		if err != nil {
			return nil, err
		}
		f.Name = s
	}
	for _, tname := range doc.Order {
		if tname == "" {
			continue
		}
		t := doc.Tables[tname]
		switch {
		case tname == "network":
			if err := checkKeys(t, "network", tname); err != nil {
				return nil, err
			}
			ps, err := pathFrom(t, "network")
			if err != nil {
				return nil, err
			}
			f.Network = ps
		case tname == "paths":
			if len(t.Keys) > 0 {
				return nil, &Error{Line: t.Line, Msg: "put each path in its own table, such as [paths.office]"}
			}
		case strings.HasPrefix(tname, "paths."):
			name := strings.TrimPrefix(tname, "paths.")
			if !pathName.MatchString(name) {
				return nil, &Error{Line: t.Line, Msg: fmt.Sprintf("path name %q must be lowercase letters, digits, - or _ (up to 32)", name)}
			}
			if name == "direct" || name == "network" {
				return nil, &Error{Line: t.Line, Msg: fmt.Sprintf("%q is a reserved path name", name)}
			}
			if err := checkKeys(t, "path", tname); err != nil {
				return nil, err
			}
			ps, err := pathFrom(t, name)
			if err != nil {
				return nil, err
			}
			f.Paths[name] = ps
		case tname == "policy":
			if err := checkKeys(t, "policy", tname); err != nil {
				return nil, err
			}
			ps, err := policyFrom(t)
			if err != nil {
				return nil, err
			}
			f.Policy = ps
		case tname == "trace":
			if err := checkKeys(t, "trace", tname); err != nil {
				return nil, err
			}
			ts, err := traceFrom(t)
			if err != nil {
				return nil, err
			}
			f.Trace = ts
		default:
			known := []string{"network", "paths.NAME", "policy", "trace"}
			return nil, &Error{Line: t.Line, Msg: fmt.Sprintf("unknown table [%s]%s; known tables: %s", tname, suggest(tname, []string{"network", "policy", "trace"}), strings.Join(known, ", "))}
		}
	}
	return f, nil
}

func checkKeys(t *Table, kind, label string) error {
	allowed := schema[kind]
	for _, k := range t.Order {
		ok := false
		for _, a := range allowed {
			if a == k {
				ok = true
				break
			}
		}
		if !ok {
			where := "the top level"
			if label != "" {
				where = "[" + label + "]"
			}
			return &Error{Line: t.Keys[k].Line, Msg: fmt.Sprintf("unknown key %q in %s%s", k, where, suggest(k, allowed))}
		}
	}
	return nil
}

// suggest returns a "did you mean" hint for close misspellings.
func suggest(got string, options []string) string {
	best, bestD := "", 3
	for _, o := range options {
		if d := editDistance(got, o); d < bestD {
			best, bestD = o, d
		}
	}
	if best == "" {
		return ""
	}
	return fmt.Sprintf(" (did you mean %q?)", best)
}

func editDistance(a, b string) int {
	if len(a) > 64 || len(b) > 64 {
		return 99
	}
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

func wantString(v *Value, key string) (string, error) {
	if v.Kind != KString {
		return "", &Error{Line: v.Line, Msg: fmt.Sprintf("%s must be a string in quotes, not a %s", key, v.Kind)}
	}
	return v.Str, nil
}

func wantBool(v *Value, key string) (bool, error) {
	if v.Kind != KBool {
		return false, &Error{Line: v.Line, Msg: fmt.Sprintf("%s must be true or false, not a %s", key, v.Kind)}
	}
	return v.Bool, nil
}

func wantStrings(v *Value, key string) ([]string, error) {
	if v.Kind != KArray {
		return nil, &Error{Line: v.Line, Msg: fmt.Sprintf("%s must be a list of strings, such as [\"github.com\"]", key)}
	}
	out := make([]string, 0, len(v.Arr))
	for _, e := range v.Arr {
		if e.Kind != KString {
			return nil, &Error{Line: v.Line, Msg: fmt.Sprintf("%s must hold strings only", key)}
		}
		out = append(out, e.Str)
	}
	return out, nil
}

func pathFrom(t *Table, name string) (*PathSpec, error) {
	ps := &PathSpec{Name: name, Line: t.Line}
	if nv, ok := t.Keys["name"]; ok {
		n, err := wantString(nv, "name")
		if err != nil {
			return nil, err
		}
		if !pathName.MatchString(n) || n == "direct" {
			return nil, &Error{Line: nv.Line, Msg: fmt.Sprintf("path name %q must be lowercase letters, digits, - or _ (up to 32), and not \"direct\"", n)}
		}
		ps.Name = n
	}
	tv, ok := t.Keys["type"]
	if !ok {
		return nil, &Error{Line: t.Line, Msg: fmt.Sprintf("[%s] needs type = \"direct\" or type = \"proxy\"", t.Name)}
	}
	s, err := wantString(tv, "type")
	if err != nil {
		return nil, err
	}
	switch s {
	case "direct", "proxy", "wireguard":
		ps.Type = s
	default:
		return nil, &Error{Line: tv.Line, Msg: fmt.Sprintf("unknown path type %q; use \"direct\", \"proxy\" or \"wireguard\"", s)}
	}
	if cv, ok := t.Keys["config"]; ok {
		c, err := wantString(cv, "config")
		if err != nil {
			return nil, err
		}
		if ps.Type != "wireguard" {
			return nil, &Error{Line: cv.Line, Msg: "config is the wg-quick file of a wireguard path"}
		}
		if c == "" {
			return nil, &Error{Line: cv.Line, Msg: "config is empty"}
		}
		ps.WGConfig = c
	}
	if ps.Type == "wireguard" {
		if ps.WGConfig == "" {
			return nil, &Error{Line: t.Line, Msg: fmt.Sprintf("[%s] is a wireguard path and needs config = \"wg0.conf\", a wg-quick file", t.Name)}
		}
		for _, k := range []string{"url", "urls", "ca_file", "token_file"} {
			if v, ok := t.Keys[k]; ok {
				return nil, &Error{Line: v.Line, Msg: fmt.Sprintf("a wireguard path has no %s; its peer and keys are in the config file", k)}
			}
		}
	}
	if uv, ok := t.Keys["url"]; ok {
		u, err := wantString(uv, "url")
		if err != nil {
			return nil, err
		}
		if ps.Type == "direct" {
			return nil, &Error{Line: uv.Line, Msg: "a direct path has no url"}
		}
		ps.URL = u
	}
	if uv, ok := t.Keys["urls"]; ok {
		if ps.Type == "direct" {
			return nil, &Error{Line: uv.Line, Msg: "a direct path has no urls"}
		}
		if ps.URL != "" {
			return nil, &Error{Line: uv.Line, Msg: "give either url (one proxy) or urls (a list of exits), not both"}
		}
		l, err := wantStrings(uv, "urls")
		if err != nil {
			return nil, err
		}
		if len(l) == 0 {
			return nil, &Error{Line: uv.Line, Msg: "urls is empty; list the exits in the order to use them"}
		}
		ps.URLs = l
	}
	if ps.Type == "proxy" && ps.URL == "" && ps.URLs == nil {
		return nil, &Error{Line: t.Line, Msg: fmt.Sprintf("[%s] is a proxy path and needs url = \"socks5://host:port\", \"http://host:port\" or \"https://host:port\", or urls = [...] for a list of exits", t.Name)}
	}
	for _, k := range []string{"ca_file", "token_file"} {
		v, ok := t.Keys[k]
		if !ok {
			continue
		}
		s, err := wantString(v, k)
		if err != nil {
			return nil, err
		}
		if ps.Type == "direct" {
			return nil, &Error{Line: v.Line, Msg: fmt.Sprintf("a direct path has no %s", k)}
		}
		if s == "" {
			return nil, &Error{Line: v.Line, Msg: fmt.Sprintf("%s is empty", k)}
		}
		if k == "ca_file" {
			ps.CAFile = s
		} else {
			ps.TokenFile = s
		}
	}
	if dv, ok := t.Keys["dns"]; ok {
		d, err := wantString(dv, "dns")
		if err != nil {
			return nil, err
		}
		switch {
		case ps.Type == "wireguard" && (d == "tunnel" || d == "local"):
		case ps.Type == "wireguard":
			return nil, &Error{Line: dv.Line, Msg: "dns for a wireguard path is \"tunnel\" (the config's DNS servers, through the tunnel) or \"local\""}
		case d == "local", d == "remote":
		default:
			return nil, &Error{Line: dv.Line, Msg: "dns must be \"local\" or \"remote\""}
		}
		if ps.Type == "direct" && d == "remote" {
			return nil, &Error{Line: dv.Line, Msg: "a direct path always resolves names locally"}
		}
		ps.DNS = d
	}
	if ps.DNS == "" {
		switch ps.Type {
		case "direct":
			ps.DNS = "local"
		case "proxy":
			ps.DNS = "remote"
		}
		// A wireguard path decides from its config: through the tunnel when
		// it names DNS servers.
	}
	return ps, nil
}

// PolicyFromTable reads the policy keys (default, deny_private, allow and
// deny) of any table with the same rules as [policy]. Other keys are left to
// the caller. Exit uses it for policies written inside a client's table.
func PolicyFromTable(t *Table) (*PolicySpec, error) { return policyFrom(t) }

func policyFrom(t *Table) (*PolicySpec, error) {
	ps := &PolicySpec{Line: t.Line}
	if v, ok := t.Keys["default"]; ok {
		s, err := wantString(v, "default")
		if err != nil {
			return nil, err
		}
		if s != "allow" && s != "deny" {
			return nil, &Error{Line: v.Line, Msg: "default must be \"allow\" or \"deny\""}
		}
		ps.Default = s
	}
	if v, ok := t.Keys["deny_private"]; ok {
		b, err := wantBool(v, "deny_private")
		if err != nil {
			return nil, err
		}
		ps.DenyPrivate, ps.DenyPrivateSet = b, true
	}
	if v, ok := t.Keys["allow"]; ok {
		l, err := wantStrings(v, "allow")
		if err != nil {
			return nil, err
		}
		ps.Allow = l
	}
	if v, ok := t.Keys["deny"]; ok {
		l, err := wantStrings(v, "deny")
		if err != nil {
			return nil, err
		}
		ps.Deny = l
	}
	return ps, nil
}

func traceFrom(t *Table) (*TraceSpec, error) {
	ts := &TraceSpec{Enabled: true, Format: "text"}
	if v, ok := t.Keys["enabled"]; ok {
		b, err := wantBool(v, "enabled")
		if err != nil {
			return nil, err
		}
		ts.Enabled = b
	}
	if v, ok := t.Keys["format"]; ok {
		s, err := wantString(v, "format")
		if err != nil {
			return nil, err
		}
		if s != "text" && s != "jsonl" {
			return nil, &Error{Line: v.Line, Msg: "format must be \"text\" or \"jsonl\""}
		}
		ts.Format = s
	}
	if v, ok := t.Keys["out"]; ok {
		s, err := wantString(v, "out")
		if err != nil {
			return nil, err
		}
		ts.Out = s
	}
	return ts, nil
}

// Merge combines files given on the command line (--config then --policy).
// A table may be defined in only one of them; a path name must be unique.
func Merge(files ...*File) (*File, error) {
	out := &File{Version: 1, Paths: map[string]*PathSpec{}}
	var netFrom, polFrom, trFrom string
	for _, f := range files {
		if f == nil {
			continue
		}
		if out.Name == "" {
			out.Name = f.Name
		}
		if f.Network != nil {
			if out.Network != nil {
				return nil, &Error{File: f.Source, Msg: "[network] is already set in " + netFrom}
			}
			out.Network, netFrom = f.Network, f.Source
		}
		if f.Policy != nil {
			if out.Policy != nil {
				return nil, &Error{File: f.Source, Msg: "[policy] is already set in " + polFrom}
			}
			out.Policy, polFrom = f.Policy, f.Source
		}
		if f.Trace != nil {
			if out.Trace != nil {
				return nil, &Error{File: f.Source, Msg: "[trace] is already set in " + trFrom}
			}
			out.Trace, trFrom = f.Trace, f.Source
		}
		for n, p := range f.Paths {
			if _, dup := out.Paths[n]; dup {
				return nil, &Error{File: f.Source, Msg: fmt.Sprintf("path %q is defined twice", n)}
			}
			out.Paths[n] = p
		}
	}
	return out, nil
}

// PathNames lists the named paths in a stable order.
func (f *File) PathNames() []string {
	var names []string
	for n := range f.Paths {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
