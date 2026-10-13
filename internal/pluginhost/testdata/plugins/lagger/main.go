//go:build wasip1

// lagger sleeps on its first event, so the events after it pile up and
// some are dropped, then counts events and the lost marks it is handed.
package main

import (
	"fmt"
	"time"

	"github.com/VPNWorks/vpnw/plugins/sdk"
)

var events, lost int64
var first = true

func init() {
	sdk.Register(sdk.Plugin{
		OnEvent: func(e *sdk.Event) error {
			if first {
				first = false
				time.Sleep(1500 * time.Millisecond)
			}
			if e.Type == "events.lost" {
				lost += e.Int("count")
				return nil
			}
			events++
			return nil
		},
		Finish: func() error {
			sdk.Stderr(fmt.Sprintf("events %d lost %d\n", events, lost))
			return nil
		},
	})
}

func main() {}
