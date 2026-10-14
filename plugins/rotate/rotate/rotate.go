// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package rotate is the Rotate plugin's logic. Rotate is a tunnel plugin:
// it hands vpnw the WireGuard configs in its folder, the .conf files, one
// after the other.
//
// It starts with the first, in name order or, with order=random, in an
// order shuffled for each run. It moves to the next when the one in use
// has been kept for every (if set), when its tunnel doesn't come up or
// stops answering, and when vpnw refuses it. The folder is read again each
// time, so a config added while vpnw runs joins the rotation and one taken
// out leaves it.
//
// Settings: every (a duration such as 10m; unset, a config is kept until
// it stops working) and order (name or random).
package rotate

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/VPNWorks/vpnw/plugins/sdk"
)

// What vpnw takes: a config of at most 64 KiB, named in at most 128
// printable characters, kept at least 5 seconds and at most 30 days.
const (
	maxConfig = 64 << 10
	maxName   = 128
	minEvery  = 5 * time.Second
	maxEvery  = 30 * 24 * time.Hour
)

// State is one run of the plugin.
type State struct {
	every  time.Duration
	random bool
	folder string
	// order is every config seen in this run, in the order they rotate;
	// one no longer in the folder is passed over.
	order []string
	seen  map[string]bool
	list  func() ([]sdk.FolderEntry, error)
	read  func(name string) ([]byte, error)
	// shuffle puts newly seen configs in a random order.
	shuffle func([]string)
}

// New makes a State that reads its folder with list and read.
func New(list func() ([]sdk.FolderEntry, error), read func(string) ([]byte, error)) *State {
	return &State{list: list, read: read, seen: map[string]bool{},
		shuffle: func(s []string) { rand.Shuffle(len(s), func(i, j int) { s[i], s[j] = s[j], s[i] }) }}
}

// Plugin is the plugin's hooks, reading its folder through vpnw.
func Plugin() sdk.Plugin {
	s := New(sdk.FolderList, sdk.FolderRead)
	return sdk.Plugin{Init: s.Init, OnTunnel: s.Next}
}

// Init reads the settings. The folder is first read when vpnw asks for a
// config, so a run without one (vpnw doctor) starts too.
func (s *State) Init(c *sdk.Config) error {
	s.folder = c.Folder
	for k, v := range c.Settings {
		switch k {
		case "every":
			d, err := ParseEvery(v)
			if err != nil {
				return err
			}
			s.every = d
		case "order":
			switch v {
			case "", "name":
				s.random = false
			case "random":
				s.random = true
			default:
				return fmt.Errorf("order must be name or random, not %q", v)
			}
		default:
			return fmt.Errorf("unknown setting %q; rotate takes every and order", k)
		}
	}
	return nil
}

// ParseEvery reads the every setting: a duration such as 10m or 1h30m, from
// 5s to 30 days, or "" or "0" for none.
func ParseEvery(v string) (time.Duration, error) {
	if v == "" || v == "0" {
		return 0, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < minEvery || d > maxEvery {
		return 0, fmt.Errorf("every must be a duration from 5s to 720h, such as 10m or 1h, not %q", v)
	}
	return d, nil
}

// Next hands over the config after the one the request is about: the one
// that failed or was refused, else the one in use; at the start, the first.
func (s *State) Next(r *sdk.TunnelRequest) (*sdk.TunnelConfig, error) {
	present, err := s.configs()
	if err != nil {
		return nil, sdk.NoConfig("cannot list the folder: " + err.Error())
	}
	if len(present) == 0 {
		where := "the folder"
		if s.folder != "" {
			where = s.folder
		}
		return nil, sdk.NoConfig("no .conf files in " + where)
	}
	after := r.Config
	if after == "" {
		after = r.Current
	}
	if r.Reason == "start" {
		after = ""
	}
	start := 0
	for i, n := range s.order {
		if n == after {
			start = i + 1
		}
	}
	var why []string
	for k := range len(s.order) {
		name := s.order[(start+k)%len(s.order)]
		if !present[name] {
			continue
		}
		b, err := s.read(name)
		switch {
		case err != nil:
			why = append(why, name+": cannot read it")
		case len(b) > maxConfig:
			why = append(why, fmt.Sprintf("%s: %d bytes, more than a config of 64 KiB", name, len(b)))
		case !utf8.Valid(b):
			why = append(why, name+": not text")
		default:
			for _, w := range why {
				sdk.Log("skipped " + w)
			}
			return &sdk.TunnelConfig{Name: name, Config: string(b), Keep: s.every}, nil
		}
	}
	return nil, sdk.NoConfig("no config in the folder could be read: " + strings.Join(why, "; "))
}

// configs lists the .conf files in the folder, and adds any new ones to
// the rotation.
func (s *State) configs() (map[string]bool, error) {
	if s.list == nil {
		return nil, errors.New("no folder")
	}
	ents, err := s.list()
	if err != nil {
		return nil, err
	}
	present := map[string]bool{}
	var fresh []string
	for _, e := range ents {
		if !isConfig(e.Name) || e.Size == 0 {
			continue
		}
		present[e.Name] = true
		if !s.seen[e.Name] {
			s.seen[e.Name] = true
			fresh = append(fresh, e.Name)
		}
	}
	sort.Strings(fresh)
	if s.random {
		s.shuffle(fresh)
		s.order = append(s.order, fresh...)
	} else if len(fresh) > 0 {
		s.order = append(s.order, fresh...)
		sort.Strings(s.order)
	}
	return present, nil
}

// isConfig accepts a .conf file with a name vpnw can record as it is.
func isConfig(name string) bool {
	if !strings.EqualFold(path.Ext(name), ".conf") || strings.HasPrefix(name, ".") || utf8.RuneCountInString(name) > maxName {
		return false
	}
	for _, r := range name {
		switch {
		case r == utf8.RuneError, r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f,
			r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0x2028, r == 0x2029:
			return false
		}
	}
	return true
}
