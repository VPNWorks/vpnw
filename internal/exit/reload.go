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
	// gens holds every broker.Client each name has had since it was last
	// taken out or given a new token: a request or a connection may still
	// hold an older one, and taking the client out must reach them all.
	gens map[string][]*broker.Client
	// warned holds the warnings said already, so a reload says only new ones.
	warned map[string]bool
}

// NewReloader watches the exit that started with cfg and clients.
func NewReloader(cfg *Config, clients *Clients, live *Live, revoke func(...*broker.Client) int) *Reloader {
	r := &Reloader{Live: live, Revoke: revoke, start: cfg, cfg: cfg, clients: clients, gens: map[string][]*broker.Client{}}
	r.sum = newSnapshot().sum(watched(cfg))
	for _, bc := range clients.list {
		r.gens[bc.Name] = append(r.gens[bc.Name], bc)
	}
	r.warned = map[string]bool{}
	for _, w := range cfg.Warnings {
		r.warned[w] = true
	}
	return r
}

// read reads one of the exit's files as LoadConfig and config.Load would.
func read(name string) ([]byte, error) {
	st, err := os.Stat(name)
	if err != nil {
		return nil, err
	}
	if st.Size() > config.MaxSize {
		return nil, fmt.Errorf("file is larger than %d bytes", config.MaxSize)
	}
	return os.ReadFile(name)
}

// snapshot is the bytes of the exit's files as read once, so the files
// are hashed and parsed from the same bytes: a change written while a
// reload is taken in is seen by the next look.
type snapshot struct {
	data map[string][]byte
	errs map[string]error
}

func (s *snapshot) get(name string) ([]byte, error) {
	if b, ok := s.data[name]; ok {
		return b, nil
	}
	if err, ok := s.errs[name]; ok {
		return nil, err
	}
	b, err := read(name)
	if err != nil {
		s.errs[name] = err
		return nil, err
	}
	s.data[name] = b
	return b, nil
}

// sum hashes the named files, in order; a file that can't be read counts
// as its error.
func (s *snapshot) sum(names []string) [32]byte {
	h := sha256.New()
	for _, name := range names {
		b, err := s.get(name)
		if err != nil {
			fmt.Fprintf(h, "unreadable %q %v\n", name, err)
			continue
		}
		fmt.Fprintf(h, "%q %d\n", name, len(b))
		h.Write(b)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func newSnapshot() *snapshot {
	return &snapshot{data: map[string][]byte{}, errs: map[string]error{}}
}

func watched(cfg *Config) []string { return append([]string{cfg.File}, cfg.PolicyFiles...) }

// parse reads the exit's file and its policy files from the snapshot.
func (s *snapshot) parse(file string) (*Config, error) {
	b, err := s.get(file)
	if err != nil {
		return nil, errAt(file, 0, "cannot read the file: %s", fileErr(err))
	}
	return ParseConfig(string(b), file, func(name string) (*config.File, error) {
		pb, err := s.get(name)
		if err != nil {
			return nil, &config.Error{File: name, Msg: "cannot read the file: " + fileErr(err)}
		}
		return config.ParseFile(name, string(pb))
	})
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
	snap := newSnapshot()
	sum := snap.sum(watched(r.cfg))
	if sum == r.sum {
		return nil
	}
	// Whatever comes of it, these bytes have been looked at.
	r.sum = sum
	cfg, err := snap.parse(r.start.File)
	if err != nil {
		return &Change{Err: err}
	}
	if err := cfg.CheckSources(); err != nil {
		return &Change{Err: fmt.Errorf("%v; each client's connections leave from its own address, so the exit needs them all", err)}
	}
	// The policy files may be other ones now: watch the new set, as read.
	r.sum = snap.sum(watched(cfg))
	ch := &Change{}
	for _, w := range cfg.Warnings {
		if !r.warned[w] {
			r.warned[w] = true
			ch.Warnings = append(ch.Warnings, w)
		}
	}
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
	clients := cfg.BrokerClients()
	var gone []*broker.Client
	seen := map[string]bool{}
	for i, cl := range cfg.Clients {
		seen[cl.Name] = true
		o, ok := old[cl.Name]
		switch {
		case !ok:
			ch.Added = append(ch.Added, cl.Name)
			r.gens[cl.Name] = []*broker.Client{clients.list[i]}
		case fingerprint(o) == fingerprint(cl):
			// Unchanged: the same client as before.
			clients.list[i] = oldBroker[cl.Name]
		default:
			ch.Changed = append(ch.Changed, cl.Name)
			if o.Hash != cl.Hash {
				// A new token: whoever held the old one is out.
				gone = append(gone, r.gens[cl.Name]...)
				r.gens[cl.Name] = nil
			}
			r.gens[cl.Name] = append(r.gens[cl.Name], clients.list[i])
		}
	}
	for name := range old {
		if !seen[name] {
			ch.Removed = append(ch.Removed, name)
			gone = append(gone, r.gens[name]...)
			delete(r.gens, name)
		}
	}
	sort.Strings(ch.Removed)
	r.Live.cur.Store(clients)
	if r.Revoke != nil && len(gone) > 0 {
		ch.Closed = r.Revoke(gone...)
	}
	r.cfg, r.clients = cfg, clients
	return ch
}
