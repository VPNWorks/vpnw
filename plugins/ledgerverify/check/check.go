// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package check is the ledger-verify plugin's logic: an Advisor that reads
// a ledger, line by line as it is on disk, and the run's traces after it,
// and says whether anything was changed, and where.
//
// The first file must be the ledger. Files after it are traces of the same
// run (--out, or the saved "last" trace): the checkpoint copies Ledger left
// there are checked against the ledger, and the trace's events name the
// line when a ledger was rewritten from some line on.
//
// Settings:
//
//	head  the ledger's last hash, kept somewhere else; the ledger must end
//	      with it
package check

import (
	"errors"
	"fmt"
	"strings"

	"github.com/VPNWorks/vpnw/plugins/ledger/chain"
	"github.com/VPNWorks/vpnw/plugins/sdk"
)

type state struct {
	v      chain.Verifier
	ledger string // the ledger's file name
	files  map[string]bool
}

// Plugin returns the hooks.
func Plugin() sdk.Plugin {
	s := &state{files: map[string]bool{}}
	return sdk.Plugin{Init: s.init, OnLine: s.line, Finish: s.finish}
}

func (s *state) init(c *sdk.Config) error {
	for k, v := range c.Settings {
		switch k {
		case "head":
			h, err := chain.ParseHash(strings.ToLower(strings.TrimSpace(v)))
			if err != nil {
				return fmt.Errorf("head=%q: %v", v, err)
			}
			s.v.Head = &h
		default:
			return fmt.Errorf("unknown setting %q (ledger-verify has: head)", k)
		}
	}
	return nil
}

func (s *state) line(l *sdk.Line) error {
	if !s.files[l.File] {
		s.files[l.File] = true
		if s.ledger == "" {
			if !chain.IsLedger(l.Text) {
				return fmt.Errorf("%s is not a VPN Works ledger; give the ledger first, then the run's traces", l.File)
			}
			s.ledger = l.File
		} else if l.File == s.ledger {
			return fmt.Errorf("%s is given twice", l.File)
		} else if l.N == 1 && chain.IsLedger(l.Text) {
			return fmt.Errorf("%s is a second ledger; check one at a time", l.File)
		}
	}
	if l.File == s.ledger {
		s.v.Ledger(l.File, l.N, l.Text, l.Partial)
	} else {
		s.v.Trace(l.File, l.N, l.Text)
	}
	return nil
}

func (s *state) finish() error {
	if s.ledger == "" {
		return errors.New("no ledger was given")
	}
	r := s.v.Result()
	sdk.Stdout(strings.Join(r.Lines, "\n") + "\n")
	if r.Verdict != chain.Intact {
		return errors.New(r.Problem)
	}
	return nil
}
