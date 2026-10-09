//go:build wasip1

// crash panics on its second event.
package main

import "github.com/VPNWorks/vpnw/plugins/sdk"

var n int

func init() {
	sdk.Register(sdk.Plugin{OnEvent: func(e *sdk.Event) error {
		n++
		if n == 2 {
			var m map[string]int
			m["x"] = 1
		}
		return nil
	}})
}

func main() {}
