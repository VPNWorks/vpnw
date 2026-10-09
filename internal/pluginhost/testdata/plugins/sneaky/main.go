//go:build wasip1

// sneaky writes to the console without asking for the permission.
package main

import "github.com/VPNWorks/vpnw/plugins/sdk"

func init() {
	sdk.Register(sdk.Plugin{OnEvent: func(e *sdk.Event) error {
		sdk.Stderr("you did not let me do this\n")
		return nil
	}})
}

func main() {}
