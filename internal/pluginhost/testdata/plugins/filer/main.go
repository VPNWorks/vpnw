//go:build wasip1

// filer writes the path vpnw gave it, then each event's type, to its file.
// With the setting require=true it refuses to start when it has no file.
package main

import (
	"errors"

	"github.com/VPNWorks/vpnw/plugins/sdk"
)

func init() {
	sdk.Register(sdk.Plugin{
		Init: func(c *sdk.Config) error {
			if err := sdk.FileWrite([]byte("file " + c.File + " run " + c.Run + "\n")); err != nil {
				if c.Settings["require"] == "true" {
					return errors.New("no file: " + err.Error())
				}
			}
			return nil
		},
		OnEvent: func(e *sdk.Event) error {
			return sdk.FileWrite([]byte(e.Type + "\n"))
		},
		Finish: func() error {
			if err := sdk.FileSync(); err != nil {
				return err
			}
			return sdk.FileWrite([]byte("finished\n"))
		},
	})
}

func main() {}
