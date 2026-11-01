// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package exit

import (
	"crypto/sha256"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/VPNWorks/vpnw/internal/broker"
	"github.com/VPNWorks/vpnw/internal/config"
	"github.com/VPNWorks/vpnw/internal/policy"
)

// Live is the broker's view of an exit's clients that a reload can swap
// while the exit serves.
type Live struct{ cur atomic.Pointer[Clients] }

// NewLive starts with the clients of the file as read at start.
func NewLive(c *Clients) *Live {
	l := &Live{}
	l.cur.Store(c)
	return l
}

// Login finds the client a token belongs to among the clients now.
func (l *Live) Login(token string) *broker.Client { return l.cur.Load().Login(token) }

// Reloader reads an exit's file again when it, or a policy file it names,
// changes, and swaps the clients in while the exit serves. Name, listen,
// cert and key stay as they were at start: changing them takes a restart.
type Reloader struct {
	Live *Live
	// Revoke closes the open connections of clients taken out of the file,
	// or whose token changed (broker.Broker.Revoke).
	Revoke func(...*broker.Client) int

	mu      sync.Mutex
	start   *Config // as the exit started: the settings a reload can't change
	cfg     *Config // the file as last taken in
	clients *Clients
	sum     [32]byte // of the files as last read
}

// NewReloader watches the exit that started with cfg and clients.
func NewReloader(cfg *Config, clients *Clients, live *Live, revoke func(...*broker.Client) int) *Reloader {
	r := &Reloader{Live: live, Revoke: revoke, start: cfg, cfg: cfg, clients: clients}
	r.sum, _ = r.files(cfg)
	return r
}

// files hashes the exit's file and the policy files it names, in order; a
// file that can't be read counts as changed.
func (r *Reloader) files(cfg *Config) ([32]byte, error) {
	h := sha256.New()
	for _, name := range append([]string{cfg.File}, cfg.PolicyFiles...) {
		st, err := os.Stat(name)
		if err == nil && st.Size() > config.MaxSize {
			err = fmt.Errorf("%s is larger than %d bytes", name, config.MaxSize)
		}
		var b []byte
		if err == nil {
			b, err = os.ReadFile(name)
		}
		if err != nil {
			fmt.Fprintf(h, "unreadable %q %v\n", name, err)
			continue
		}
		fmt.Fprintf(h, "%q %d\n", name, len(b))
		h.Write(b)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// Change is what one reload did, for the exit.reload event.
type Change struct {
	Added, Removed, Changed []string
	// Restart names the settings that changed but need a restart: name,
	// listen, cert, key.
	Restart []string
	// Closed counts the connections closed with removed clients.
	Closed   int
	Warnings []string
	// Err is why the new file wasn't taken: the clients stay as they were.
	Err error
}

// Fields is the change as the exit.reload event's fields.
func (c *Change) Fields() map[string]any {
	f := map[string]any{}
	if c.Err != nil {
		f["error"] = c.Err.Error()
		return f
	}
	for k, v := range map[string][]string{"added": c.Added, "removed": c.Removed, "changed": c.Changed, "restart": c.Restart, "warnings": c.Warnings} {
		if len(v) > 0 {
			f[k] = v
		}
	}
	if c.Closed > 0 {
		f["closed"] = c.Closed
	}
	return f
}

// fingerprint is everything about a client that decides its requests.
func fingerprint(cl *Client) string {
	pool := ""
	if cl.Pool != nil {
		pool = fmt.Sprint(cl.Pool.Addrs)
	}
	p := cl.Policy
	var b strings.Builder
	fmt.Fprintf(&b, "%x|%s|%s|%v|%s|%q|%v|%v", cl.Hash, cl.Address(), pool, cl.ExitHost, cl.PolicyFile, p.Name, p.Default, p.DenyPrivate)
	for _, rs := range [][]policy.Rule{p.Allow, p.Deny} {
		b.WriteString("|")
		for _, x := range rs {
			fmt.Fprintf(&b, "%v %q;", x.Action, x.Text)
		}
	}
	return b.String()
}

// Check reads the files again if any of them changed since the last look,
// and takes in the new clients. It returns nil when nothing changed.
func (r *Reloader) Check() *Change {
	r.mu.Lock()
	defer r.mu.Unlock()
	sum, _ := r.files(r.cfg)
	if sum == r.sum {
		return nil
	}
	r.sum = sum
	cfg, err := LoadConfig(r.start.File)
	if err != nil {
		return &Change{Err: err}
	}
	if err := cfg.CheckSources(); err != nil {
		return &Change{Err: fmt.Errorf("%v; each client's connections leave from its own address, so the exit needs them all", err)}
	}
	// The policy files may be other ones now: watch the new set.
	r.sum, _ = r.files(cfg)
	ch := &Change{Warnings: cfg.Warnings}
	for _, x := range []struct{ name, was, is string }{
		{"name", r.start.Name, cfg.Name}, {"listen", r.start.Listen, cfg.Listen},
		{"cert", r.start.Cert, cfg.Cert}, {"key", r.start.Key, cfg.Key},
	} {
		if x.was != x.is {
			ch.Restart = append(ch.Restart, x.name)
		}
	}
	old := map[string]*Client{}
	for _, cl := range r.cfg.Clients {
		old[cl.Name] = cl
	}
	oldBroker := map[string]*broker.Client{}
	for _, bc := range r.clients.list {
		oldBroker[bc.Name] = bc
	}
	var gone []*broker.Client
	seen := map[string]bool{}
	for _, cl := range cfg.Clients {
		seen[cl.Name] = true
		o, ok := old[cl.Name]
		switch {
		case !ok:
			ch.Added = append(ch.Added, cl.Name)
		case fingerprint(o) != fingerprint(cl):
			ch.Changed = append(ch.Changed, cl.Name)
			if o.Hash != cl.Hash {
				// A new token: whoever held the old one is out.
				gone = append(gone, oldBroker[cl.Name])
			}
		}
	}
	for name := range old {
		if !seen[name] {
			ch.Removed = append(ch.Removed, name)
			gone = append(gone, oldBroker[name])
		}
	}
	sort.Strings(ch.Removed)
	clients := cfg.BrokerClients()
	r.Live.cur.Store(clients)
	if r.Revoke != nil && len(gone) > 0 {
		ch.Closed = r.Revoke(gone...)
	}
	r.cfg, r.clients = cfg, clients
	return ch
}
