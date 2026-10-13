//go:build wasip1

// filesneak writes to a file without asking for the file.write permission.
package main

import "github.com/VPNWorks/vpnw/plugins/sdk"

func init() {
	sdk.Register(sdk.Plugin{
		OnEvent: func(e *sdk.Event) error { return sdk.FileWrite([]byte(e.Type)) },
	})
}

func main() {}
