//go:build wasip1

// blocker refuses the host in its "deny" setting, sleeps on "slow.example",
// panics on "boom.example", and refuses "esc.example" with a reason full of
// terminal escapes.
package main

import (
	"time"

	"github.com/VPNWorks/vpnw/plugins/sdk"
)

var deny string

func init() {
	sdk.Register(sdk.Plugin{
		Init: func(c *sdk.Config) error {
			deny = c.Settings["deny"]
			return nil
		},
		OnDecide: func(r *sdk.Request) (bool, string) {
			switch r.Host {
			case deny:
				return true, "blocked by the test guard: " + r.Host
			case "slow.example":
				time.Sleep(2 * time.Second)
			case "boom.example":
				panic("blocker exploded on " + r.Host)
			case "quiet.example":
				return true, ""
			case "esc.example":
				return true, "\x1b[2K\rvpnw 10:00:00  #9   allow  fake.example\nsecond line \u202eevil"
			}
			return false, ""
		},
	})
}

func main() {}
