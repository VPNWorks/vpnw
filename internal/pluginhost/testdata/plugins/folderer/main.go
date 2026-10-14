//go:build wasip1

// folderer lists its folder when it starts, then reads each file named in
// the setting read (comma-separated), and logs what happened:
// "list NAME:SIZE ...", then "read NAME LEN SHA-PREFIX" or "read NAME failed".
package main

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/VPNWorks/vpnw/plugins/sdk"
)

func init() {
	sdk.Register(sdk.Plugin{
		Init: func(c *sdk.Config) error {
			sdk.Log("folder " + c.Folder)
			list, err := sdk.FolderList()
			if err != nil {
				sdk.Log("list failed")
			} else {
				var parts []string
				for _, e := range list {
					parts = append(parts, fmt.Sprintf("%s:%d", e.Name, e.Size))
				}
				sdk.Log("list " + strings.Join(parts, " "))
			}
			for _, name := range strings.Split(c.Settings["read"], ",") {
				if name == "" {
					continue
				}
				b, err := sdk.FolderRead(name)
				if err != nil {
					sdk.Log("read " + name + " failed")
					continue
				}
				sdk.Log(fmt.Sprintf("read %s %d %x", name, len(b), sha256.Sum256(b)))
			}
			return nil
		},
	})
}

func main() {}
