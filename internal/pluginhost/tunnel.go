// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package pluginhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/VPNWorks/vpnw/internal/path"
)

// Limits on what a tunnel plugin hands over: a config of at most MaxOffer
// bytes, named in at most MaxOfferName characters, kept at most MaxKeep
// (a longer keep is taken as MaxKeep). MaxOfferJSON is the most the offer
// may take as JSON: enough for a config of MaxOffer bytes however it is
// escaped, since an escape takes at most 6 bytes for one.
const (
	MaxOffer     = 64 << 10
	MaxOfferName = 128
	MaxKeep      = 30 * 24 * time.Hour
	MaxOfferJSON = 6*MaxOffer + 64<<10
)

// Offer is a WireGuard config a tunnel plugin handed over.
type Offer struct {
	Name string
	Text string
	// Keep is how long to use it before asking again; 0 is until it fails.
	Keep time.Duration
}

// ParseOffer reads what a tunnel plugin hands over: one JSON object,
// {"name": ..., "config": ..., "keep": seconds}, and nothing else.
func ParseOffer(b []byte) (*Offer, error) {
	if len(b) > MaxOfferJSON {
		return nil, fmt.Errorf("%d bytes, more than an offer of a config of %d bytes takes", len(b), MaxOffer)
	}
	var w struct {
		Name   *string      `json:"name"`
		Config *string      `json:"config"`
		Keep   *json.Number `json:"keep"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(&w); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("more than one JSON object")
	}
	switch {
	case w.Name == nil || *w.Name == "":
		return nil, errors.New("no name")
	case w.Config == nil || *w.Config == "":
		return nil, errors.New("no config")
	case utf8.RuneCountInString(*w.Name) > MaxOfferName || clean(*w.Name, MaxOfferName) != *w.Name:
		return nil, fmt.Errorf("a name must be printable, at most %d characters", MaxOfferName)
	case len(*w.Config) > MaxOffer:
		return nil, fmt.Errorf("a config of %d bytes, over the %d-byte limit", len(*w.Config), MaxOffer)
	case !utf8.ValidString(*w.Config):
		return nil, errors.New("a config that isn't text (UTF-8)")
	}
	o := &Offer{Name: *w.Name, Text: *w.Config}
	if w.Keep != nil {
		n, err := w.Keep.Int64()
		if err != nil || n < 0 {
			return nil, errors.New("keep must be whole seconds, 0 or more")
		}
		o.Keep = time.Duration(min(n, int64(MaxKeep/time.Second))) * time.Second
	}
	return o, nil
}

// tunnelNone and tunnelFailed are what vpnw_tunnel returns when the plugin
// has no config to give (its reason through the reason host call) and when
// it failed (its message through the error host call). Anything else is the
// offer's place in the plugin's memory: its address in the high 32 bits,
// its length in the low.
const (
	tunnelNone   = 0
	tunnelFailed = ^uint64(0)
)

// Tunnel asks a tunnel plugin for a config, with req as JSON. It returns a
// nil offer and the plugin's reason when the plugin has none to give. Any
// failure of the plugin, an offer it can't read included, is an error, and
// stops it.
func (in *Instance) Tunnel(ctx context.Context, req any) (*Offer, string, error) {
	if in.tunnelFn == nil {
		return nil, "", errors.New("is not a tunnel plugin")
	}
	if err := in.take(ctx); err != nil {
		return nil, "", err
	}
	defer func() { <-in.turn }()
	b, err := json.Marshal(req)
	if err != nil {
		return nil, "", err
	}
	res, err := in.pass(ctx, TunnelBudget, in.tunnelFn, b)
	switch {
	case err != nil:
		return nil, "", err
	case res == tunnelNone:
		return nil, in.reason, nil
	case res == tunnelFailed:
		return nil, "", in.pluginErr()
	}
	p, n := uint32(res>>32), uint32(res)
	if n > MaxOfferJSON {
		return nil, "", in.stop(fmt.Errorf("handed over %d bytes, more than an offer of a config of %d bytes takes", n, MaxOffer))
	}
	raw, ok := in.mod.Memory().Read(p, n)
	if !ok {
		return nil, "", in.stop(errors.New("handed over a config outside its memory"))
	}
	off, err := ParseOffer(raw)
	if err != nil {
		return nil, "", in.stop(fmt.Errorf("handed over something that isn't a config offer: %v", err))
	}
	return off, "", nil
}

// TunnelRequest is what a tunnel plugin is asked, as JSON.
type TunnelRequest struct {
	Run     string `json:"run"`
	Reason  string `json:"reason"`
	Current string `json:"current"`
	Config  string `json:"config"`
	Error   string `json:"error"`
}

// TunnelPlugin hands a tunnel plugin's configs to a path. It implements
// path.TunnelSource.
type TunnelPlugin struct {
	in     *Instance
	mu     sync.Mutex
	onFail func(name string, err error)
	once   sync.Once
}

// NewTunnel wraps a loaded tunnel plugin.
func NewTunnel(in *Instance) *TunnelPlugin { return &TunnelPlugin{in: in} }

// OnFail sets what hears, once, that the plugin failed. Before it is set,
// a failure is only an error from Next: at the start of a run, the run
// reports it itself.
func (t *TunnelPlugin) OnFail(f func(name string, err error)) {
	t.mu.Lock()
	t.onFail = f
	t.mu.Unlock()
}

// Name is the plugin's name.
func (t *TunnelPlugin) Name() string { return t.in.Name() }

// Next asks the plugin for a config.
func (t *TunnelPlugin) Next(ctx context.Context, q path.TunnelQuery) (*path.TunnelOffer, string, error) {
	off, none, err := t.in.Tunnel(ctx, TunnelRequest{Run: t.in.opt.Run, Reason: q.Reason, Current: q.Current, Config: q.Config, Error: q.Error})
	if err != nil {
		if ctx.Err() == nil && !errors.Is(err, ErrClosed) {
			t.mu.Lock()
			f := t.onFail
			t.mu.Unlock()
			if f != nil {
				t.once.Do(func() { f(t.in.Name(), err) })
			}
		}
		return nil, "", err
	}
	if off == nil {
		return nil, none, nil
	}
	return &path.TunnelOffer{Name: off.Name, Text: off.Text, Keep: off.Keep}, "", nil
}

// Close stops the plugin and returns its failure, if any.
func (t *TunnelPlugin) Close() error {
	err := t.in.Err()
	t.in.Close()
	return err
}
