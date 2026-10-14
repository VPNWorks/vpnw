// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package rotate_test

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/VPNWorks/vpnw/plugins/rotate/rotate"
	"github.com/VPNWorks/vpnw/plugins/sdk"
)

// folder is an in-memory folder; unreadable names fail to read.
type folder struct {
	files      map[string]string
	unreadable map[string]bool
}

func (f *folder) list() ([]sdk.FolderEntry, error) {
	var out []sdk.FolderEntry
	for n, b := range f.files {
		out = append(out, sdk.FolderEntry{Name: n, Size: int64(len(b))})
	}
	return out, nil
}

func (f *folder) read(n string) ([]byte, error) {
	if f.unreadable[n] {
		return nil, errors.New("permission denied")
	}
	b, ok := f.files[n]
	if !ok {
		return nil, errors.New("no such file")
	}
	return []byte(b), nil
}

func state(t *testing.T, f *folder, set map[string]string) *rotate.State {
	t.Helper()
	s := rotate.New(f.list, f.read)
	if err := s.Init(&sdk.Config{Folder: "/configs", Settings: set}); err != nil {
		t.Fatal(err)
	}
	return s
}

// next asks for a config and returns its name, or "none: why".
func next(t *testing.T, s *rotate.State, reason, current, config string) string {
	t.Helper()
	c, err := s.Next(&sdk.TunnelRequest{Reason: reason, Current: current, Config: config})
	if err != nil {
		return "none: " + err.Error()
	}
	return c.Name
}

func TestRotateInNameOrder(t *testing.T) {
	f := &folder{files: map[string]string{"b.conf": "B", "a.conf": "A", "c.CONF": "C", "notes.txt": "x", ".hidden.conf": "h", "empty.conf": ""}}
	s := state(t, f, map[string]string{"every": "10m"})
	steps := []struct{ reason, current, config, want string }{
		{"start", "", "", "a.conf"},
		{"due", "a.conf", "", "b.conf"},
		{"due", "b.conf", "", "c.CONF"},
		{"due", "c.CONF", "", "a.conf"},
		// After a failure or a refusal: the one after the config it's about.
		{"failed", "a.conf", "b.conf", "c.CONF"},
		{"refused", "a.conf", "c.CONF", "a.conf"},
		{"failed", "a.conf", "a.conf", "b.conf"},
		// A start again starts from the top.
		{"start", "", "", "a.conf"},
	}
	for _, st := range steps {
		if got := next(t, s, st.reason, st.current, st.config); got != st.want {
			t.Errorf("%s (current %q, config %q): %s, want %s", st.reason, st.current, st.config, got, st.want)
		}
	}
	c, _ := s.Next(&sdk.TunnelRequest{Reason: "start"})
	if c.Config != "A" || c.Keep != 10*time.Minute {
		t.Errorf("config %+v", c)
	}
}

// The folder is read every time: a config added joins the rotation, one
// taken out leaves it.
func TestRotateFollowsTheFolder(t *testing.T) {
	f := &folder{files: map[string]string{"a.conf": "A", "c.conf": "C"}}
	s := state(t, f, nil)
	if got := next(t, s, "start", "", ""); got != "a.conf" {
		t.Fatal(got)
	}
	f.files["b.conf"] = "B"
	if got := next(t, s, "due", "a.conf", ""); got != "b.conf" {
		t.Errorf("added: %s", got)
	}
	delete(f.files, "c.conf")
	if got := next(t, s, "due", "b.conf", ""); got != "a.conf" {
		t.Errorf("removed: %s", got)
	}
	// The one in use was taken out: on to the next still there.
	delete(f.files, "a.conf")
	if got := next(t, s, "due", "a.conf", ""); got != "b.conf" {
		t.Errorf("in use removed: %s", got)
	}
	// One config: the same again, which keeps it.
	if got := next(t, s, "due", "b.conf", ""); got != "b.conf" {
		t.Errorf("only one: %s", got)
	}
	delete(f.files, "b.conf")
	if got := next(t, s, "due", "b.conf", ""); got != "none: no .conf files in /configs" {
		t.Errorf("empty: %s", got)
	}
}

// Configs vpnw would refuse to take are passed over here: unreadable, too
// big, not text, or named with characters the record can't show.
func TestRotateSkips(t *testing.T) {
	f := &folder{
		files: map[string]string{"a.conf": "A", "b.conf": strings.Repeat("x", 65<<10), "c.conf": "\xff\xfe", "d.conf": "D",
			"bell\a.conf": "x", strings.Repeat("n", 130) + ".conf": "x"},
		unreadable: map[string]bool{"a.conf": true},
	}
	s := state(t, f, nil)
	if got := next(t, s, "start", "", ""); got != "d.conf" {
		t.Errorf("start: %s", got)
	}
	f.unreadable["d.conf"] = true
	got := next(t, s, "due", "d.conf", "")
	for _, w := range []string{"no config in the folder could be read", "a.conf: cannot read it", "b.conf: 66560 bytes", "c.conf: not text", "d.conf: cannot read it"} {
		if !strings.Contains(got, w) {
			t.Errorf("%q lacks %q", got, w)
		}
	}
}

// With order=random the configs come in a shuffled order, the same all
// run long; new ones join at the end.
func TestRotateRandom(t *testing.T) {
	f := &folder{files: map[string]string{"a.conf": "A", "b.conf": "B", "c.conf": "C"}}
	s := state(t, f, map[string]string{"order": "random"})
	seen := map[string]bool{}
	first := next(t, s, "start", "", "")
	cur := first
	order := []string{cur}
	for range 2 {
		cur = next(t, s, "due", cur, "")
		order = append(order, cur)
	}
	for _, n := range order {
		seen[n] = true
	}
	if len(seen) != 3 || next(t, s, "due", cur, "") != first {
		t.Errorf("order %v", order)
	}
	f.files["d.conf"] = "D"
	if got := next(t, s, "due", cur, ""); got != "d.conf" {
		t.Errorf("new one: %s after %v", got, order)
	}
	// Different runs start differently; over 50 runs, more than one first.
	firsts := map[string]bool{}
	for range 50 {
		firsts[next(t, state(t, f, map[string]string{"order": "random"}), "start", "", "")] = true
	}
	if len(firsts) < 2 {
		t.Errorf("50 runs all started with %v", firsts)
	}
}

func TestRotateSettings(t *testing.T) {
	for _, v := range []string{"", "0", "5s", "10m", "1h30m", "720h"} {
		if _, err := rotate.ParseEvery(v); err != nil {
			t.Errorf("every=%s: %v", v, err)
		}
	}
	for _, v := range []string{"4s", "1ms", "-1m", "721h", "ten minutes", "10"} {
		if _, err := rotate.ParseEvery(v); err == nil {
			t.Errorf("every=%s accepted", v)
		}
	}
	for set, want := range map[string]string{
		"order=sideways": `order must be name or random, not "sideways"`,
		"every=1s":       "every must be a duration from 5s",
		"speed=fast":     `unknown setting "speed"; rotate takes every and order`,
	} {
		k, v, _ := strings.Cut(set, "=")
		s := rotate.New(nil, nil)
		if err := s.Init(&sdk.Config{Settings: map[string]string{k: v}}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", set, err)
		}
	}
	// No folder at all (vpnw doctor starts every built-in): Init is fine,
	// and asking for a config says why there is none.
	s := rotate.New(nil, nil)
	if err := s.Init(&sdk.Config{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Next(&sdk.TunnelRequest{Reason: "start"}); err == nil || !strings.Contains(err.Error(), "cannot list the folder") {
		t.Errorf("no folder: %v", err)
	}
}

// Through the SDK, as vpnw calls it: the offer is what vpnw reads, and
// none is a reason, not a failure.
func TestRotatePlugin(t *testing.T) {
	sdk.TestFolder = fstest.MapFS{"x.conf": {Data: []byte("[Interface]\n")}}
	defer func() { sdk.TestFolder = nil }()
	sdk.Register(rotate.Plugin())
	if err := sdk.CallInit([]byte(`{"plugin":"rotate","settings":{"every":"90s"},"folder":"/f"}`)); err != nil {
		t.Fatal(err)
	}
	offer, none, _, err := sdk.CallTunnel([]byte(`{"reason":"start"}`))
	if err != nil || none {
		t.Fatalf("%s %v %v", offer, none, err)
	}
	var o map[string]any
	json.Unmarshal(offer, &o)
	if o["name"] != "x.conf" || o["config"] != "[Interface]\n" || o["keep"] != float64(90) {
		t.Errorf("offer %s", offer)
	}
	sdk.TestFolder = fstest.MapFS{}
	if _, none, why, err := sdk.CallTunnel([]byte(`{"reason":"due","current":"x.conf"}`)); !none || err != nil || why != "no .conf files in /f" {
		t.Errorf("empty: %v %q %v", none, why, err)
	}
}

// The names and requests that reach Next come from a folder anyone can put
// files in. Next never panics, and it only hands over a config that is in
// the folder.
func FuzzRotate(f *testing.F) {
	f.Add("a.conf\nb.conf\nc.txt", "due", "a.conf", "", true)
	f.Add("x.conf", "failed", "x.conf", "x.conf", false)
	f.Add("", "start", "", "", false)
	f.Fuzz(func(t *testing.T, names, reason, current, config string, random bool) {
		fl := &folder{files: map[string]string{}}
		for _, n := range strings.Split(names, "\n") {
			fl.files[n] = "config " + n
		}
		set := map[string]string{}
		if random {
			set["order"] = "random"
		}
		s := state(t, fl, set)
		for range 3 {
			c, err := s.Next(&sdk.TunnelRequest{Reason: reason, Current: current, Config: config})
			if err != nil {
				return
			}
			if _, ok := fl.files[c.Name]; !ok || c.Config != "config "+c.Name || !strings.HasSuffix(strings.ToLower(c.Name), ".conf") {
				t.Fatalf("handed over %q: %q", c.Name, c.Config)
			}
			if slices.Contains([]string{"due", "failed"}, reason) {
				current = c.Name
			}
		}
	})
}
