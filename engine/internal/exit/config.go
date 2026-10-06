// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package exit

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"vpnw.com/vpnw/internal/config"
	"vpnw.com/vpnw/internal/policy"
)

// Config is an exit's configuration file, in the same strict TOML subset as
// the Agent's files and read by the same reader. Every error names the file
// and the line.
//
//	version = 1
//	name    = "exit-de"              # stamped on the exit's record
//	listen  = "198.51.100.2:8443"
//	cert    = "exit-de.crt"          # PEM, next to this file
//	key     = "exit-de.key"
//
//	[pools.eu]                       # addresses clients can share
//	addresses = ["198.51.100.20", "198.51.100.21"]
//
//	[clients.agent-1]
//	token_sha256 = "9f2c..."         # vpnw-exit token prints a token and this
//	source       = "198.51.100.10"   # its own fixed address, or pool = "eu"
//	policy       = "agent-1.toml"    # an Agent policy file: its [policy]
//
//	[clients.ci]
//	token_sha256 = "51b0..."
//	pool         = "eu"
//	default      = "deny"            # or the policy written here, as in [policy]
//	deny_private = true
//	allow        = ["registry.partner.example"]
type Config struct {
	File   string
	Name   string
	Listen string
	// Cert and Key are as written; CertFile and KeyFile resolve them.
	Cert, Key string
	Clients   []*Client
	Pools     []*Pool
	// Warnings are things that work but deserve a look, such as a client
	// policy that lets it reach private addresses.
	Warnings []string
}

// Pool is a set of source addresses that clients share.
type Pool struct {
	Name  string
	Addrs []netip.Addr
	Line  int
}

// Client is one client of the exit.
type Client struct {
	Name string
	Hash [32]byte
	// Source is the client's own fixed address, or Pool its pool.
	Source netip.Addr
	Pool   *Pool
	Policy *policy.Policy
	// PolicyFile is the file the policy came from, or "" when it is written
	// in the client's table.
	PolicyFile string
	Line       int
}

// Loader reads an Agent configuration file, for client policies kept in
// files of their own. nil reads from disk with config.Load.
type Loader func(name string) (*config.File, error)

func errAt(file string, line int, format string, a ...any) error {
	return &config.Error{File: file, Line: line, Msg: fmt.Sprintf(format, a...)}
}

// validName reports whether s can name a client or a pool: letters, digits,
// _ and -, at most 64 of them.
func validName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// LoadConfig reads and checks an exit's configuration file.
func LoadConfig(name string) (*Config, error) {
	st, err := os.Stat(name)
	if err != nil {
		return nil, errAt(name, 0, "cannot read the file: %s", fileErr(err))
	}
	if st.Size() > config.MaxSize {
		return nil, errAt(name, 0, "file is larger than %d bytes", config.MaxSize)
	}
	b, err := os.ReadFile(name)
	if err != nil {
		return nil, errAt(name, 0, "cannot read the file: %s", fileErr(err))
	}
	return ParseConfig(string(b), name, nil)
}

func fileErr(err error) string {
	if pe, ok := err.(*os.PathError); ok {
		return pe.Err.Error()
	}
	return err.Error()
}

// CertFile and KeyFile return the certificate and key file names, relative
// to the configuration file's folder.
func (c *Config) CertFile() string { return c.inDir(c.Cert) }
func (c *Config) KeyFile() string  { return c.inDir(c.Key) }

func (c *Config) inDir(name string) string {
	if name == "" || filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(filepath.Dir(c.File), name)
}

// Client returns a client by name, or nil.
func (c *Config) Client(name string) *Client {
	for _, cl := range c.Clients {
		if cl.Name == name {
			return cl
		}
	}
	return nil
}

var rootKeys = []string{"version", "name", "listen", "cert", "key"}
var clientKeys = []string{"token_sha256", "source", "pool", "policy", "default", "deny_private", "allow", "deny"}
var policyKeys = map[string]bool{"default": true, "deny_private": true, "allow": true, "deny": true}

func known(k string, list []string) bool {
	for _, x := range list {
		if x == k {
			return true
		}
	}
	return false
}

func str(file string, v *config.Value, key string) (string, error) {
	if v.Kind != config.KString {
		return "", errAt(file, v.Line, "%s must be a string in quotes", key)
	}
	return v.Str, nil
}

// ParseConfig reads an exit's configuration from src; file names it in
// errors and is where relative file names start. load reads client policy
// files; nil reads them from disk.
func ParseConfig(src, file string, load Loader) (*Config, error) {
	if load == nil {
		load = config.Load
	}
	doc, err := config.Parse(src)
	if err != nil {
		if ce, ok := err.(*config.Error); ok {
			ce.File = file
		}
		return nil, err
	}
	c := &Config{File: file}
	root := doc.Tables[""]
	for _, k := range root.Order {
		v := root.Keys[k]
		if !known(k, rootKeys) {
			return nil, errAt(file, v.Line, "unknown key %q at the top level (known: %s)", k, strings.Join(rootKeys, ", "))
		}
		if k == "version" {
			if v.Kind != config.KInt || v.Int != 1 {
				return nil, errAt(file, v.Line, "version must be 1")
			}
			continue
		}
		s, err := str(file, v, k)
		if err != nil {
			return nil, err
		}
		switch k {
		case "name":
			if !validName(s) {
				return nil, errAt(file, v.Line, "name %q: use letters, digits, _ and -", s)
			}
			c.Name = s
		case "listen":
			// Port 0 takes any free port; serve prints the one it got.
			if _, port, err := net.SplitHostPort(s); err != nil || port == "" {
				return nil, errAt(file, v.Line, "listen %q: want an address and port, such as \"0.0.0.0:8443\"", s)
			} else if _, err := policy.ParsePort(port); err != nil && port != "0" {
				return nil, errAt(file, v.Line, "listen %q: %v", s, err)
			}
			c.Listen = s
		case "cert":
			c.Cert = s
		case "key":
			c.Key = s
		}
	}
	if _, ok := root.Keys["version"]; !ok {
		return nil, errAt(file, 1, "missing version = 1 at the top of the file")
	}
	for _, k := range []string{"listen", "cert", "key"} {
		if _, ok := root.Keys[k]; !ok {
			return nil, errAt(file, 1, "missing %s; an exit needs listen, cert and key", k)
		}
	}
	if c.Name == "" {
		c.Name = strings.TrimSuffix(filepath.Base(file), filepath.Ext(file))
		if !validName(c.Name) {
			c.Name = "exit"
		}
	}
	pools := map[string]*Pool{}
	type pending struct {
		cl   *Client
		pool string
		line int
	}
	var waiting []pending
	hashes := map[[32]byte]*Client{}
	for _, tname := range doc.Order[1:] {
		t := doc.Tables[tname]
		section, name, ok := strings.Cut(tname, ".")
		if !ok || (section != "clients" && section != "pools") {
			return nil, errAt(file, t.Line, "unknown table [%s]; an exit's file has [clients.NAME] and [pools.NAME] tables", tname)
		}
		if !validName(name) {
			return nil, errAt(file, t.Line, "%s name %q: use letters, digits, _ and -", strings.TrimSuffix(section, "s"), name)
		}
		if section == "pools" {
			p, err := parsePool(file, name, t)
			if err != nil {
				return nil, err
			}
			pools[name] = p
			c.Pools = append(c.Pools, p)
			continue
		}
		cl, pool, err := parseClient(file, name, t, load, c)
		if err != nil {
			return nil, err
		}
		if other, dup := hashes[cl.Hash]; dup {
			return nil, errAt(file, t.Keys["token_sha256"].Line, "%s has the same token as %s; every client needs its own", name, other.Name)
		}
		hashes[cl.Hash] = cl
		c.Clients = append(c.Clients, cl)
		if pool != "" {
			waiting = append(waiting, pending{cl, pool, t.Keys["pool"].Line})
		}
	}
	for _, w := range waiting {
		p, ok := pools[w.pool]
		if !ok {
			return nil, errAt(file, w.line, "pool %q is not defined; add a [pools.%s] table", w.pool, w.pool)
		}
		w.cl.Pool = p
	}
	if len(c.Clients) == 0 {
		return nil, errAt(file, 1, "no clients; add a [clients.NAME] table for each")
	}
	if err := c.checkAddresses(); err != nil {
		return nil, err
	}
	for _, cl := range c.Clients {
		if cl.Policy.Default == policy.Allow && !cl.Policy.DenyPrivate {
			c.Warnings = append(c.Warnings, fmt.Sprintf("%s:%d: client %s has default allow without deny_private, so it can reach private addresses, the exit machine's own services among them", file, cl.Line, cl.Name))
		}
	}
	return c, nil
}

func parseAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("%q is not an IP address", s)
	}
	return a.Unmap(), nil
}

func parsePool(file, name string, t *config.Table) (*Pool, error) {
	p := &Pool{Name: name, Line: t.Line}
	for _, k := range t.Order {
		v := t.Keys[k]
		if k != "addresses" {
			return nil, errAt(file, v.Line, "unknown key %q for a pool (known: addresses)", k)
		}
		if v.Kind != config.KArray {
			return nil, errAt(file, v.Line, "addresses must be a list of strings, such as [\"198.51.100.20\"]")
		}
		seen := map[netip.Addr]bool{}
		for _, e := range v.Arr {
			if e.Kind != config.KString {
				return nil, errAt(file, v.Line, "addresses must hold strings only")
			}
			a, err := parseAddr(e.Str)
			if err != nil {
				return nil, errAt(file, v.Line, "%v", err)
			}
			if seen[a] {
				return nil, errAt(file, v.Line, "address %s is listed twice", a)
			}
			seen[a] = true
			p.Addrs = append(p.Addrs, a)
		}
	}
	if len(p.Addrs) == 0 {
		return nil, errAt(file, t.Line, "pool %s has no addresses", name)
	}
	return p, nil
}

func parseClient(file, name string, t *config.Table, load Loader, c *Config) (*Client, string, error) {
	cl := &Client{Name: name, Line: t.Line}
	var pool string
	inline := false
	haveHash := false
	for _, k := range t.Order {
		v := t.Keys[k]
		if !known(k, clientKeys) {
			return nil, "", errAt(file, v.Line, "unknown key %q for a client (known: %s)", k, strings.Join(clientKeys, ", "))
		}
		if policyKeys[k] {
			inline = true
			continue
		}
		s, err := str(file, v, k)
		if err != nil {
			return nil, "", err
		}
		switch k {
		case "token_sha256":
			b, err := hex.DecodeString(s)
			if err != nil || len(b) != 32 {
				return nil, "", errAt(file, v.Line, "token_sha256 must be 64 hexadecimal characters, the SHA-256 of the token; vpnw-exit token prints one")
			}
			copy(cl.Hash[:], b)
			haveHash = true
		case "source":
			a, err := parseAddr(s)
			if err != nil {
				return nil, "", errAt(file, v.Line, "source %v", err)
			}
			cl.Source = a
		case "pool":
			pool = s
		case "policy":
			cl.PolicyFile = s
		}
	}
	if !haveHash {
		return nil, "", errAt(file, t.Line, "client %s has no token_sha256", name)
	}
	switch {
	case cl.Source.IsValid() && pool != "":
		return nil, "", errAt(file, t.Keys["pool"].Line, "client %s has both a source and a pool; give one", name)
	case !cl.Source.IsValid() && pool == "":
		return nil, "", errAt(file, t.Line, "client %s needs a source address (source = \"...\") or a pool (pool = \"...\")", name)
	}
	switch {
	case inline && cl.PolicyFile != "":
		return nil, "", errAt(file, t.Keys["policy"].Line, "client %s has a policy file and policy keys of its own; give one", name)
	case inline:
		spec, err := config.PolicyFromTable(t)
		if err != nil {
			if ce, ok := err.(*config.Error); ok {
				ce.File = file
			}
			return nil, "", err
		}
		p, err := policy.New(spec, name)
		if err != nil {
			line := t.Line
			for _, k := range []string{"allow", "deny"} {
				if v, ok := t.Keys[k]; ok && strings.HasPrefix(err.Error(), k+" entry") {
					line = v.Line
				}
			}
			return nil, "", errAt(file, line, "client %s: %v", name, err)
		}
		cl.Policy = p
	case cl.PolicyFile != "":
		f, err := load(c.inDir(cl.PolicyFile))
		if err != nil {
			return nil, "", errAt(file, t.Keys["policy"].Line, "client %s: %v", name, err)
		}
		if f.Policy == nil {
			return nil, "", errAt(file, t.Keys["policy"].Line, "client %s: %s has no [policy] table", name, cl.PolicyFile)
		}
		pname := f.Name
		if pname == "" {
			pname = filepath.Base(cl.PolicyFile)
		}
		p, err := policy.New(f.Policy, pname)
		if err != nil {
			return nil, "", errAt(file, t.Keys["policy"].Line, "client %s: %s: %v", name, cl.PolicyFile, err)
		}
		cl.Policy = p
	default:
		return nil, "", errAt(file, t.Line, "client %s has no policy: give policy = \"FILE\", or allow and deny rules in its table", name)
	}
	return cl, pool, nil
}

// checkAddresses makes sure a fixed address belongs to one client only and
// that pools share no address with each other or with a client: partners
// allow traffic by address, so an address must say who sent it.
func (c *Config) checkAddresses() error {
	owner := map[netip.Addr]string{}
	for _, cl := range c.Clients {
		if !cl.Source.IsValid() {
			continue
		}
		if o, dup := owner[cl.Source]; dup {
			return errAt(c.File, cl.Line, "source %s is already %s's; a fixed address belongs to one client (put clients that share addresses in a pool)", cl.Source, o)
		}
		owner[cl.Source] = "client " + cl.Name
	}
	for _, p := range c.Pools {
		for _, a := range p.Addrs {
			if o, dup := owner[a]; dup {
				return errAt(c.File, p.Line, "pool %s's address %s is already %s's", p.Name, a, strings.TrimPrefix(o, "client "))
			}
			owner[a] = "pool " + p.Name
		}
	}
	return nil
}

// Sources lists every source address the exit uses, sorted.
func (c *Config) Sources() []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	add := func(a netip.Addr) {
		if a.IsValid() && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, cl := range c.Clients {
		add(cl.Source)
		if cl.Pool != nil {
			for _, a := range cl.Pool.Addrs {
				add(a)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// Describe says how a client is set up, in one line.
func (cl *Client) Describe() string {
	src := "source " + cl.Source.String()
	if cl.Pool != nil {
		a, _ := cl.SourceFor("")
		src = fmt.Sprintf("pool %s (%d addresses; it uses %s)", cl.Pool.Name, len(cl.Pool.Addrs), a)
	}
	from := "policy in its table"
	if cl.PolicyFile != "" {
		from = "policy " + cl.PolicyFile
	}
	s := cl.Policy.Summary()
	rules := func(n any, kind string) string {
		if fmt.Sprint(n) == "1" {
			return "1 " + kind + " rule"
		}
		return fmt.Sprintf("%v %s rules", n, kind)
	}
	return fmt.Sprintf("%s: %s; %s (default %v, %s, %s, deny_private %v)",
		cl.Name, src, from, s["default"], rules(s["allow_rules"], "allow"), rules(s["deny_rules"], "deny"), s["deny_private"])
}
