// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build wasip1

// Command learn is the Learn plugin: an Advisor that turns traces into a
// draft policy. Every destination the program reached becomes an allow rule
// and everything else is denied. The draft allows whatever the program did,
// including anything it should not have done, so it is for reading before
// use; it marks denied destinations, raw addresses and lopsided uploads.
//
// Settings:
//
//	name       the policy's name
//	ports      true writes host:port rules instead of host rules
//	wildcards  true folds three or more names under one domain into *.domain
//	summary    true writes a one-line count to standard error
package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/VPNWorks/vpnw/internal/events"
	"github.com/VPNWorks/vpnw/plugins/learn/learn"
	"github.com/VPNWorks/vpnw/plugins/sdk"
)

var (
	cfg *sdk.Config
	all []events.Event
)

func init() {
	sdk.Register(sdk.Plugin{
		Init: func(c *sdk.Config) error {
			cfg = c
			return nil
		},
		RawEvents: true,
		OnEvent: func(e *sdk.Event) error {
			var ev events.Event
			if err := json.Unmarshal(e.Raw, &ev); err != nil {
				return err
			}
			all = append(all, ev)
			return nil
		},
		Finish: func() error {
			s := cfg.Settings
			res := learn.FromEvents(all, learn.Options{
				Name: s["name"], Ports: s["ports"] == "true", Wildcards: s["wildcards"] == "true", Now: time.Now(),
			})
			sdk.Stdout(res.TOML)
			if s["summary"] == "true" {
				sdk.Stderr(fmt.Sprintf("learned %d destinations allowed, %d left out\n", len(res.Allowed), len(res.Denied)))
			}
			return nil
		},
	})
}

func main() {}
