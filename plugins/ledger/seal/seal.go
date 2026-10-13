// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package seal is the Ledger plugin's logic: an Observer that writes each
// event of a run to its file as it arrives, linked into a hash chain, with a
// checkpoint every so often and an end line when the run finishes. See
// package chain for the format.
//
// Each checkpoint is also copied into the run's own record as a
// plugin.ledger.checkpoint event, so the ledger and the trace vouch for each
// other: a ledger rewritten from some line on stops matching the copies.
// At the end it prints where the ledger is and its last hash, which can be
// kept somewhere else for a later check.
//
// Settings:
//
//	every  entries between checkpoints, 1 to 1000000 (default 100)
package seal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/VPNWorks/vpnw/plugins/ledger/chain"
	"github.com/VPNWorks/vpnw/plugins/sdk"
)

// DefaultEvery is how many entries go between checkpoints.
const DefaultEvery = 100

type state struct {
	cfg   *sdk.Config
	w     *chain.Writer
	every uint64
}

// Plugin returns the hooks.
func Plugin() sdk.Plugin {
	s := &state{}
	return sdk.Plugin{Init: s.init, RawEvents: true, OnEvent: s.event, Finish: s.finish}
}

func (s *state) init(c *sdk.Config) error {
	s.cfg = c
	if c.File == "" {
		return errors.New("Ledger needs its file: run it with vpnw run, trace or guard --plugin ledger")
	}
	s.every = DefaultEvery
	for k, v := range c.Settings {
		switch k {
		case "every":
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil || n < 1 || n > 1_000_000 {
				return fmt.Errorf("every=%q: give a number of entries from 1 to 1000000", v)
			}
			s.every = n
		default:
			return fmt.Errorf("unknown setting %q (Ledger has: every)", k)
		}
	}
	w, hd, err := chain.NewWriter(c.Run)
	if err != nil {
		return err
	}
	s.w = w
	return write(hd)
}

func write(b []byte) error {
	if err := sdk.FileWrite(b); err != nil {
		return errors.New("cannot write the ledger file (vpnw -v shows why)")
	}
	return nil
}

var lostType = []byte(`"type":"events.lost"`)

func (s *state) event(e *sdk.Event) error {
	var line []byte
	var err error
	if bytes.Contains(e.Raw, lostType) {
		var l struct {
			Type   string `json:"type"`
			Fields struct {
				Count uint64 `json:"count"`
			} `json:"fields"`
		}
		if json.Unmarshal(e.Raw, &l) == nil && l.Type == "events.lost" {
			if l.Fields.Count == 0 {
				return nil
			}
			line, err = s.w.Lost(l.Fields.Count)
		}
	}
	if line == nil && err == nil {
		line, err = s.w.Event(e.Raw)
	}
	if err != nil {
		return err
	}
	if err := write(line); err != nil {
		return err
	}
	if s.w.SinceCheckpoint() >= s.every {
		return s.checkpoint(false)
	}
	return nil
}

func (s *state) checkpoint(end bool) error {
	b, cp := s.w.Checkpoint()
	if err := write(b); err != nil {
		return err
	}
	f := map[string]any{"cp": cp, "n": s.w.Entries(), "h": s.w.Head().String()}
	if end {
		f["end"] = true
	}
	sdk.Emit("checkpoint", f)
	sdk.FileSync()
	return nil
}

func (s *state) finish() error {
	if s.w == nil {
		return nil
	}
	if err := s.checkpoint(true); err != nil {
		return err
	}
	if err := write(s.w.End()); err != nil {
		return err
	}
	sdk.FileSync()
	sdk.Stderr(fmt.Sprintf("vpnw: ledger: %d entries sealed in %s\nvpnw: ledger: last hash %s\n", s.w.Entries(), s.cfg.File, s.w.Head()))
	return nil
}
