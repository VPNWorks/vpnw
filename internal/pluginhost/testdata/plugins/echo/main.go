//go:build wasip1

// echo writes each event type to stdout, emits plugin.echo.seen for each
// connection attempt, and reports a count when it finishes.
package main

import (
	"fmt"

	"github.com/VPNWorks/vpnw/plugins/sdk"
)

var n int
var prefix string

func init() {
	sdk.Register(sdk.Plugin{
		Init: func(c *sdk.Config) error {
			if c.Settings["fail_init"] == "true" {
				return fmt.Errorf("refusing to start: fail_init is set")
			}
			prefix = c.Settings["prefix"] + c.Command + ":"
			sdk.Log("started for " + c.Command)
			return nil
		},
		OnEvent: func(e *sdk.Event) error {
			n++
			sdk.Stdout(prefix + e.Type + "\n")
			if e.Type == "connection.attempt" {
				sdk.Emit("seen", map[string]any{"host": e.Str("host"), "port": e.Int("port")})
				sdk.Emit("Bad Type!", nil)
			}
			return nil
		},
		Finish: func() error {
			sdk.Stderr(fmt.Sprintf("finished after %d events\n", n))
			return nil
		},
	})
}

func main() {}
