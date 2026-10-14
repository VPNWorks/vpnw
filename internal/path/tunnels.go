// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package path

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/VPNWorks/vpnw/internal/events"
)

// Tunnels is a path through WireGuard tunnels whose configs come from a
// tunnel plugin. vpnw runs every one of them itself, as it runs the tunnel
// of a --wireguard path; the plugin only hands over the configs, and says
// how long to keep each. It is asked for one:
//
//   - when the run starts: vpnw tries what it hands over until a tunnel
//     comes up, and the program starts only then;
//   - when the config in use has been kept as long as the plugin asked;
//   - when the tunnel in use stops answering.
//
// A config is checked the way a --wireguard file is; one that is refused,
// or whose tunnel doesn't come up, is recorded and skipped. A new tunnel is
// up before anything moves to it. New connections then go through it, and
// connections already open stay on the tunnel they started on until they
// close; that tunnel is closed after its last one. A config handed over
// again while its tunnel still carries connections gets that tunnel back,
// since a second tunnel with the same key would take the peer from it.
// When no config can be had, the tunnel in use stays, even a silent one:
// nothing ever goes around the tunnels.
type Tunnels struct {
	Name   string
	Source TunnelSource
	// DNS is "tunnel", "local" or "", for every config, as for a WireGuard
	// path.
	DNS string

	once    sync.Once
	ctx     context.Context // cancelled by Stop and Close
	cancel  context.CancelFunc
	done    chan struct{} // closed when the loop that watches the tunnels ends
	mu      sync.Mutex
	cur     *tunnel
	old     []*tunnel // rotated out, still carrying connections
	skipped []Skipped // configs not used at the start, and why
	due     time.Time // when to ask the source again; zero: only on failure
	emit    func(typ string, f map[string]any)
	started bool
	closed  bool
	gone    bool // the source failed: it isn't asked again
}

// TunnelSource hands WireGuard configs to a Tunnels path: a tunnel plugin.
type TunnelSource interface {
	// Name is the source's name, the plugin's.
	Name() string
	// Next asks for a config. It returns a nil offer, and why, when the
	// source has none to give, and an error when the source itself failed;
	// a source that failed is not asked again.
	Next(ctx context.Context, q TunnelQuery) (*TunnelOffer, string, error)
}

// TunnelQuery is what a Tunnels path asks its source.
type TunnelQuery struct {
	// Reason is "start"; "due", when the config in use was kept as long as
	// the source asked; "failed", when a config's tunnel didn't come up or
	// the one in use stopped answering; or "refused", when vpnw refused the
	// config handed over.
	Reason string
	// Current is the config in use, "" before one is up.
	Current string
	// Config is the config a failure or a refusal is about, and Error what
	// went wrong with it.
	Config string
	Error  string
}

// TunnelOffer is a config a source hands over.
type TunnelOffer struct {
	Name string
	// Text is the config in the wg-quick format.
	Text string
	// Keep is how long to use it before asking again; 0 is until it fails.
	Keep time.Duration
}

// Skipped is a config the source handed over at the start that wasn't used,
// and why.
type Skipped struct {
	Config string
	Error  string
}

// TunnelSilence is how long the tunnel in use may go without answering,
// once data went out through it, before vpnw moves to another config. A
// live WireGuard peer answers data within 10 seconds. A variable so tests
// can shorten it.
var TunnelSilence = 20 * time.Second

// Limits of a Tunnels path.
const (
	// TunnelTries is how many configs vpnw tries in a row, at the start or
	// when it moves on, before it gives up for the time being.
	TunnelTries = 8
	// MinKeep and MaxKeep bound how long a config is kept before the source
	// is asked again, when the source gives a time at all.
	MinKeep = 5 * time.Second
	MaxKeep = 30 * 24 * time.Hour
	// MaxDraining is how many tunnels rotated out may still carry their
	// connections. When another would join them, the oldest is closed, with
	// the connections it still has.
	MaxDraining = 4
	// MaxTunnelPeers is how many peers a config from a tunnel plugin may
	// have. Each is looked up and sent a handshake on every try; a VPN
	// provider's config has one.
	MaxTunnelPeers = 16
	// maxErrorText bounds an error about a config in the record.
	maxErrorText = 400
)

// tunnel is one config's tunnel.
type tunnel struct {
	name   string
	text   string // the config as handed over
	wg     *WireGuard
	keep   time.Duration
	upMS   int64
	users  int // open connections, and dials and lookups going on
	conns  map[*tunnelConn]struct{}
	closed bool
	failed bool // rotated out because it stopped answering
	again  bool // moved back to while it was rotated out, not brought up anew
}

func (t *Tunnels) init() {
	t.once.Do(func() {
		t.ctx, t.cancel = context.WithCancel(context.Background())
		t.done = make(chan struct{})
	})
}

func (t *Tunnels) ID() string      { return t.Name }
func (t *Tunnels) Kind() string    { return "wireguard" }
func (t *Tunnels) RemoteDNS() bool { return false }

// Describe names the plugin and the config in use.
func (t *Tunnels) Describe() string {
	t.mu.Lock()
	cur := t.cur
	t.mu.Unlock()
	s := "WireGuard configs from tunnel plugin " + t.Source.Name()
	if cur != nil {
		s += "; in use: " + cur.name + ", " + cur.wg.Describe()
	}
	return s
}

// Health brings the first tunnel up. It asks the source for configs and
// tries each, at most TunnelTries, until one comes up.
func (t *Tunnels) Health(ctx context.Context) error {
	t.init()
	t.mu.Lock()
	if t.cur != nil {
		t.mu.Unlock()
		return nil
	}
	t.mu.Unlock()
	tn, _, why := t.bringUp(ctx, TunnelQuery{Reason: "start"}, nil)
	if tn == nil {
		return fmt.Errorf("no config from tunnel plugin %s came up: %s", t.Source.Name(), why)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		tn.wg.Close()
		return errors.New("the run has ended")
	}
	t.cur = tn
	t.dueAfter(tn.keep)
	return nil
}

// Started describes the start, for the run's first event: the source, the
// config in use, how long it is kept, and the configs skipped and why.
func (t *Tunnels) Started() map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()
	m := map[string]any{"plugin": t.Source.Name()}
	if t.cur != nil {
		m["config"] = t.cur.name
		if t.cur.keep > 0 {
			m["keep"] = int64(t.cur.keep / time.Second)
		}
	}
	if len(t.skipped) > 0 {
		var list []any
		for _, s := range t.skipped {
			list = append(list, map[string]any{"config": s.Config, "error": s.Error})
		}
		m["skipped"] = list
	}
	return m
}

// Current is the name of the config in use.
func (t *Tunnels) Current() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cur == nil {
		return ""
	}
	return t.cur.name
}

// Start begins watching the tunnel in use and asking the source again when
// it is due, and records the path's events with emit from now on. Health
// must have brought a tunnel up first.
func (t *Tunnels) Start(emit func(typ string, f map[string]any)) {
	t.init()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.started || t.cur == nil || t.closed {
		return
	}
	t.started, t.emit = true, emit
	go t.loop()
}

// Stop ends the watching and the rotation: the source is asked nothing
// more. The tunnels stay up until Close.
func (t *Tunnels) Stop() {
	t.init()
	t.cancel()
	t.mu.Lock()
	started := t.started
	t.mu.Unlock()
	if started {
		<-t.done
	}
}

// Close takes every tunnel down.
func (t *Tunnels) Close() error {
	t.Stop()
	t.mu.Lock()
	t.closed = true
	all := append([]*tunnel{}, t.old...)
	if t.cur != nil {
		all = append(all, t.cur)
	}
	t.old = nil
	for _, tn := range all {
		tn.closed = true
	}
	t.mu.Unlock()
	for _, tn := range all {
		tn.wg.Close()
	}
	return nil
}

func (t *Tunnels) record(typ string, f map[string]any) {
	t.mu.Lock()
	emit := t.emit
	t.mu.Unlock()
	if emit != nil {
		emit(typ, f)
	}
}

// dueAfter sets when the source is asked again, under t.mu.
func (t *Tunnels) dueAfter(keep time.Duration) {
	if keep <= 0 {
		t.due = time.Time{}
		return
	}
	t.due = time.Now().Add(keep)
}

func clampKeep(d time.Duration) time.Duration {
	switch {
	case d <= 0:
		return 0
	case d < MinKeep:
		return MinKeep
	case d > MaxKeep:
		return MaxKeep
	}
	return d
}

// bringUp asks the source for configs and tries each, at most TunnelTries,
// until one's tunnel is up. cur is the tunnel in use, or nil at the start.
// It returns the tunnel to move to, a new one or one rotated out that is
// still up; or kept, when the source chose the one in use; or why nothing
// came up.
func (t *Tunnels) bringUp(ctx context.Context, q TunnelQuery, cur *tunnel) (tn *tunnel, kept bool, why string) {
	tried := map[string]bool{}
	var whys []string
	end := func(last string) string {
		return strings.Join(append(whys, last), "; ")
	}
	for range TunnelTries {
		t.mu.Lock()
		gone := t.gone
		t.mu.Unlock()
		if gone {
			return nil, false, end("tunnel plugin " + t.Source.Name() + " has stopped")
		}
		off, none, err := t.Source.Next(ctx, q)
		if ctx.Err() != nil {
			return nil, false, end("stopped before a tunnel came up")
		}
		switch {
		case err != nil:
			t.mu.Lock()
			t.gone = true
			t.mu.Unlock()
			return nil, false, end(fmt.Sprintf("tunnel plugin %s stopped: %s", t.Source.Name(), events.Clean(err.Error(), maxErrorText)))
		case off == nil:
			msg := "the plugin has no other config"
			if cur == nil && len(tried) == 0 {
				msg = "the plugin has no config"
			}
			if none != "" {
				msg += ": " + events.Clean(none, maxErrorText)
			}
			return nil, false, end(msg)
		}
		if cur != nil && off.Name == cur.name {
			t.mu.Lock()
			cur.keep = clampKeep(off.Keep)
			t.mu.Unlock()
			return nil, true, ""
		}
		if tried[off.Name] {
			return nil, false, end("the plugin came round to " + off.Name + " again")
		}
		tried[off.Name] = true
		if d := t.again(off); d != nil {
			return d, false, ""
		}
		tn, reason, err := t.try(ctx, off, cur)
		if tn != nil {
			return tn, false, ""
		}
		if ctx.Err() != nil {
			return nil, false, end("stopped before a tunnel came up")
		}
		msg := events.Clean(err.Error(), maxErrorText)
		whys = append(whys, off.Name+": "+msg)
		if cur == nil {
			t.mu.Lock()
			t.skipped = append(t.skipped, Skipped{Config: off.Name, Error: msg})
			t.mu.Unlock()
		} else {
			t.record(events.TunnelError, map[string]any{"config": off.Name, "error": msg})
		}
		q = TunnelQuery{Reason: reason, Config: off.Name, Error: toPlugin(reason, err)}
		if cur != nil {
			q.Current = cur.name
		}
	}
	return nil, false, end(fmt.Sprintf("tried %d configs", TunnelTries))
}

// again finds the tunnel of the config handed over among those rotated out,
// to move back to while it is still up and answering: its connections
// carry on, where a second tunnel with the same key would take the peer
// from it. A tunnel rotated out because it stopped answering is not taken
// back; a new one is brought up in its place.
func (t *Tunnels) again(off *TunnelOffer) *tunnel {
	t.mu.Lock()
	var d *tunnel
	for _, o := range t.old {
		if o.name == off.Name && o.text == off.Text && !o.failed && !o.closed {
			d = o
		}
	}
	t.mu.Unlock()
	if d == nil || d.wg.Silent(TunnelSilence) {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	i := slices.Index(t.old, d)
	if i < 0 || d.closed {
		return nil
	}
	t.old = slices.Delete(t.old, i, i+1)
	d.keep, d.again = clampKeep(off.Keep), true
	return d
}

// try checks a config and brings its tunnel up. When it doesn't come up,
// reason is what the source is told: "refused" or "failed".
func (t *Tunnels) try(ctx context.Context, off *TunnelOffer, cur *tunnel) (tn *tunnel, reason string, err error) {
	w, err := t.build(off)
	if err == nil {
		err = t.clash(w, cur)
	}
	if err != nil {
		return nil, "refused", err
	}
	t0 := time.Now()
	if err := w.Health(ctx); err != nil {
		w.Close()
		return nil, "failed", err
	}
	return &tunnel{name: off.Name, text: off.Text, wg: w, keep: clampKeep(off.Keep), upMS: time.Since(t0).Milliseconds(),
		conns: map[*tunnelConn]struct{}{}}, "", nil
}

// build checks a config the way a --wireguard file is checked.
func (t *Tunnels) build(off *TunnelOffer) (*WireGuard, error) {
	c, err := ParseWGConf(off.Text)
	if err != nil {
		return nil, err
	}
	if len(c.Peers) > MaxTunnelPeers {
		return nil, fmt.Errorf("it has %d peers; a config from a tunnel plugin may have at most %d", len(c.Peers), MaxTunnelPeers)
	}
	c.Source = off.Name
	return NewWireGuard(t.Name, c, t.DNS)
}

// sharesPeer reports two configs whose tunnels can't both work: the same
// private key and a peer in common. The peer talks to whichever of them
// made the last handshake.
func sharesPeer(a, b *WGConf) bool {
	if a.PrivateKey != b.PrivateKey {
		return false
	}
	for _, p := range a.Peers {
		for _, q := range b.Peers {
			if p.PublicKey == q.PublicKey {
				return true
			}
		}
	}
	return false
}

// clash refuses a config whose tunnel can't be up beside the one in use or
// those rotated out: one that shares a peer with the tunnel in use, or
// whose ListenPort another tunnel holds.
func (t *Tunnels) clash(w *WireGuard, cur *tunnel) error {
	if cur != nil && sharesPeer(w.Conf, cur.wg.Conf) {
		return fmt.Errorf("it has the same private key and peer as %s, the config in use, and a WireGuard peer talks to one tunnel of a key at a time", cur.name)
	}
	port := w.Conf.ListenPort
	if port == 0 {
		return nil
	}
	t.mu.Lock()
	up := append([]*tunnel{}, t.old...)
	t.mu.Unlock()
	if cur != nil {
		up = append(up, cur)
	}
	for _, o := range up {
		if o.wg.Conf.ListenPort == port {
			return fmt.Errorf("its ListenPort %d is taken by the tunnel of %s; configs that rotate can't share a fixed port, so leave ListenPort out of them", port, o.name)
		}
	}
	return nil
}

// replace closes the rotated-out tunnels that share a peer with a tunnel
// just brought up, with the connections they still have: the peer now
// talks to the new tunnel, so theirs would only stall.
func (t *Tunnels) replace(tn *tunnel) {
	t.mu.Lock()
	var gone, keep []*tunnel
	for _, o := range t.old {
		if sharesPeer(tn.wg.Conf, o.wg.Conf) {
			gone = append(gone, o)
		} else {
			keep = append(keep, o)
		}
	}
	t.old = keep
	t.mu.Unlock()
	for _, o := range gone {
		t.cut(o, "replaced", tn.name)
	}
}

// toPlugin is what the source is told of a config that wasn't used. A
// refusal is about the config's own text, and the source is told the
// reason. Of a tunnel that didn't come up it learns no more than its
// config says: what an endpoint's name resolved to and what this machine's
// resolver answered go to the record only, since a plugin told them could
// look names up through vpnw and read the answers.
func toPlugin(reason string, err error) string {
	var le *LookupError
	var he *HandshakeError
	switch {
	case reason == "refused":
		return events.Clean(err.Error(), maxErrorText)
	case errors.As(err, &le):
		return events.Clean("cannot look up the name in endpoint "+le.Endpoint, maxErrorText)
	case errors.As(err, &he):
		return events.Clean(fmt.Sprintf("no WireGuard handshake from %s within %v", strings.Join(he.Endpoints, ", "), he.Timeout), maxErrorText)
	}
	return "its tunnel didn't start"
}

// loop watches the tunnel in use once a second: it moves on when the tunnel
// stops answering or its time is up, and closes rotated-out tunnels when
// their last connection ends.
func (t *Tunnels) loop() {
	defer close(t.done)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-tick.C:
		}
		t.closeDrained()
		t.mu.Lock()
		cur, due, gone := t.cur, t.due, t.gone
		t.mu.Unlock()
		if gone || cur == nil {
			continue
		}
		if cur.wg.Silent(TunnelSilence) {
			t.move("failed", cur, fmt.Sprintf("nothing came back through it for %v", TunnelSilence))
			continue
		}
		if !due.IsZero() && !time.Now().Before(due) {
			t.move("due", cur, "")
		}
	}
}

// move asks the source for another config and, if its tunnel comes up,
// sends new connections through it. why is set when the tunnel in use
// stopped answering.
func (t *Tunnels) move(reason string, cur *tunnel, why string) {
	q := TunnelQuery{Reason: reason, Current: cur.name}
	if reason == "failed" {
		q.Config, q.Error = cur.name, why
	}
	tn, kept, msg := t.bringUp(t.ctx, q, cur)
	if t.ctx.Err() != nil {
		switch {
		case tn != nil && tn.again:
			t.mu.Lock()
			tn.again = false
			t.old = append(t.old, tn)
			t.mu.Unlock()
		case tn != nil:
			tn.wg.Close()
		}
		return
	}
	switch {
	case tn != nil:
		t.mu.Lock()
		t.cur = tn
		cur.failed = reason == "failed"
		t.old = append(t.old, cur)
		t.dueAfter(tn.keep)
		again := tn.again
		tn.again = false
		t.mu.Unlock()
		f := map[string]any{"from": cur.name, "to": tn.name, "why": reason, "ms": tn.upMS, "peer": tn.wg.Endpoint()}
		if again {
			f["ms"], f["again"] = int64(0), true
		}
		if why != "" {
			f["error"] = why
		}
		t.record(events.TunnelSwitch, f)
		if !again {
			t.replace(tn)
		}
		// Tunnels with no connections left close first, the one just left
		// among them, so only tunnels still carrying some count against
		// MaxDraining.
		t.closeDrained()
		t.mu.Lock()
		var cut *tunnel
		if len(t.old) > MaxDraining {
			cut, t.old = t.old[0], t.old[1:]
		}
		t.mu.Unlock()
		if cut != nil {
			t.cut(cut, "limit", "")
		}
	case kept:
		if reason == "failed" {
			t.record(events.TunnelError, map[string]any{"error": fmt.Sprintf("%s stopped answering (%s); the plugin handed it back, so it stays in use", cur.name, why)})
		}
		t.mu.Lock()
		t.dueAfter(cur.keep)
		t.mu.Unlock()
		cur.wg.quietAgain()
	default:
		t.record(events.TunnelError, map[string]any{"error": msg + "; " + cur.name + " stays in use"})
		t.mu.Lock()
		t.dueAfter(cur.keep)
		t.mu.Unlock()
		cur.wg.quietAgain()
	}
}

// closeDrained closes the rotated-out tunnels whose last connection ended.
func (t *Tunnels) closeDrained() {
	t.mu.Lock()
	var done []*tunnel
	keep := t.old[:0]
	for _, o := range t.old {
		if o.users == 0 {
			o.closed = true
			done = append(done, o)
		} else {
			keep = append(keep, o)
		}
	}
	t.old = keep
	t.mu.Unlock()
	for _, o := range done {
		o.wg.Close()
		t.record(events.TunnelClose, map[string]any{"config": o.name, "why": "drained"})
	}
}

// cut closes a rotated-out tunnel that may still have connections, with
// them. why is "limit", when more than MaxDraining would be left, or
// "replaced", when by names the config whose new tunnel shares its peer.
func (t *Tunnels) cut(o *tunnel, why, by string) {
	t.mu.Lock()
	o.closed = true
	var conns []*tunnelConn
	for c := range o.conns {
		conns = append(conns, c)
	}
	t.mu.Unlock()
	for _, c := range conns {
		c.Conn.Close()
	}
	o.wg.Close()
	f := map[string]any{"config": o.name, "why": why, "cut": len(conns)}
	if by != "" {
		f["by"] = by
	}
	t.record(events.TunnelClose, f)
}

// use takes the tunnel in use for a dial or a lookup; release gives it back.
func (t *Tunnels) use() (*tunnel, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch {
	case t.closed:
		return nil, errors.New("the run has ended")
	case t.cur == nil:
		return nil, errors.New("no tunnel is up")
	}
	t.cur.users++
	return t.cur, nil
}

func (t *Tunnels) release(tn *tunnel, c *tunnelConn) {
	t.mu.Lock()
	tn.users--
	if c != nil {
		delete(tn.conns, c)
	}
	t.mu.Unlock()
}

// Dial opens a connection through the tunnel in use. It stays on that
// tunnel until it closes, whatever the path moves to meanwhile.
func (t *Tunnels) Dial(ctx context.Context, host string, ip net.IP, port int) (net.Conn, error) {
	tn, err := t.use()
	if err != nil {
		return nil, err
	}
	if ci := ConnOf(ctx); ci != nil {
		ci.Tunnel = tn.name
	}
	c, err := tn.wg.Dial(ctx, host, ip, port)
	if err != nil {
		t.release(tn, nil)
		return nil, err
	}
	tc := &tunnelConn{Conn: c, tn: tn, owner: t}
	t.mu.Lock()
	if tn.closed {
		t.mu.Unlock()
		c.Close()
		t.release(tn, nil)
		return nil, fmt.Errorf("the tunnel of %s closed while the connection was opening", tn.name)
	}
	tn.conns[tc] = struct{}{}
	t.mu.Unlock()
	return tc, nil
}

// tunnelConn is a connection through one of the tunnels; closing it lets
// that tunnel close once it is rotated out and has no others.
type tunnelConn struct {
	net.Conn
	tn    *tunnel
	owner *Tunnels
	once  sync.Once
}

func (c *tunnelConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.owner.release(c.tn, c) })
	return err
}

// CloseWrite passes a half-close through.
func (c *tunnelConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// Resolver looks names up through the tunnel in use, or on this machine
// when DNS is "local".
func (t *Tunnels) Resolver() Resolver { return tunnelsResolver{t} }

type tunnelsResolver struct{ t *Tunnels }

func (r tunnelsResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	tn, err := r.t.use()
	if err != nil {
		return nil, err
	}
	defer r.t.release(tn, nil)
	return tn.wg.Resolver().LookupIP(ctx, host)
}
