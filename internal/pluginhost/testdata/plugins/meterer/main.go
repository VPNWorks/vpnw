//go:build wasip1

// meterer puts byte budgets on connections: a good one on "budget.example",
// and on the other hosts below one vpnw must refuse, which stops the plugin.
package main

import (
	"unsafe"

	"github.com/VPNWorks/vpnw/plugins/sdk"
)

//go:wasmimport vpnw meter
func rawMeter(p unsafe.Pointer, n uint32)

func raw(s string) {
	b := []byte(s)
	rawMeter(unsafe.Pointer(unsafe.SliceData(b)), uint32(len(b)))
}

func init() {
	sdk.Register(sdk.Plugin{
		Decide: func(r *sdk.Request) sdk.Decision {
			switch r.Host {
			case "budget.example":
				return sdk.Decision{Budget: &sdk.Budget{Key: "host " + r.Host, Up: 100, Down: 2000, Reason: "test budget"}}
			case "denied.example":
				return sdk.Decision{Deny: true, Reason: "no", Budget: &sdk.Budget{Key: "k", Up: 1}}
			case "nokey.example":
				return sdk.Decision{Budget: &sdk.Budget{Up: 1}}
			case "esc.example":
				return sdk.Decision{Budget: &sdk.Budget{Key: "a\x1b[2Kb", Up: 1}}
			case "negative.example":
				return sdk.Decision{Budget: &sdk.Budget{Key: "k", Up: -1}}
			case "zero.example":
				return sdk.Decision{Budget: &sdk.Budget{Key: "k"}}
			case "junk.example":
				raw(`{"key":"k","up":1,"extra":true}`)
			case "twice.example":
				raw(`{"key":"k","up":1}`)
				raw(`{"key":"k","up":2}`)
			}
			return sdk.Decision{}
		},
	})
}

func main() {}
