//go:build wasip1

// spin never returns from its first event.
package main

import "github.com/VPNWorks/vpnw/plugins/sdk"

var x int

func init() {
	sdk.Register(sdk.Plugin{OnEvent: func(e *sdk.Event) error {
		for {
			x++
		}
	}})
}

func main() {}
