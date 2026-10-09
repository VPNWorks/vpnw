//go:build wasip1

// slow takes 2 ms per event, so a fast run leaves it behind.
package main

import (
	"time"

	"github.com/VPNWorks/vpnw/plugins/sdk"
)

func init() {
	sdk.Register(sdk.Plugin{OnEvent: func(e *sdk.Event) error {
		time.Sleep(2 * time.Millisecond)
		return nil
	}})
}

func main() {}
