// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build wasip1

// Command trace is the Trace plugin: an Observer that prints a run's events
// for people, one line each. vpnw uses it for the console output of run,
// trace and guard.
//
// Settings:
//
//	level        all (trace's default), decisions (guard's default) or quiet
//	show_allows  true prints allowed connections at the decisions level too
package main

import (
	"encoding/json"
	"fmt"

	"github.com/VPNWorks/vpnw/internal/events"
	"github.com/VPNWorks/vpnw/plugins/sdk"
	"github.com/VPNWorks/vpnw/plugins/trace/render"
)

type stderr struct{}

func (stderr) Write(b []byte) (int, error) {
	sdk.Stderr(string(b))
	return len(b), nil
}

var text *render.Text

func init() {
	sdk.Register(sdk.Plugin{
		Init: func(c *sdk.Config) error {
			level := render.All
			switch c.Settings["level"] {
			case "", "all":
			case "decisions":
				level = render.Decisions
			case "quiet":
				level = render.Quiet
			default:
				return fmt.Errorf("level must be all, decisions or quiet, not %q", c.Settings["level"])
			}
			text = render.NewText(stderr{}, level)
			text.Color = c.Color
			text.ShowAllows = c.Settings["show_allows"] == "true"
			text.Zone = c.Zone()
			return nil
		},
		RawEvents: true,
		OnEvent: func(e *sdk.Event) error {
			var ev events.Event
			if err := json.Unmarshal(e.Raw, &ev); err != nil {
				return err
			}
			text.Emit(&ev)
			return nil
		},
	})
}

func main() {}
