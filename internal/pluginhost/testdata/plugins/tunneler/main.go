//go:build wasip1

// tunneler is a test tunnel plugin. With mode=files (the default) it hands
// over the files of its folder in name order, after the one the request is
// about, kept for keep seconds; the other modes misbehave:
//
//	echo        hands over a config whose text is the request, as JSON
//	none        has no config to give
//	panic       panics
//	later       hands over the first file, then panics on every other call
//	spin        loops forever
//	badname     hands over a config named with a newline
//	huge        hands over a config of 100 KiB
//	enormous    hands over a config of 1 MiB
//	escaped     hands over a config just under 64 KiB that JSON escapes
//	            at length: lines ending in CR LF, and "<" (6 bytes each)
//	forever     hands over its first file, kept for 1000 days
//	error       fails with an error
package main

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/VPNWorks/vpnw/plugins/sdk"
)

var (
	mode  = "files"
	keep  time.Duration
	calls int
)

func init() {
	sdk.Register(sdk.Plugin{
		Init: func(c *sdk.Config) error {
			if m := c.Settings["mode"]; m != "" {
				mode = m
			}
			if k := c.Settings["keep"]; k != "" {
				n, err := strconv.Atoi(k)
				if err != nil {
					return err
				}
				keep = time.Duration(n) * time.Second
			}
			return nil
		},
		OnTunnel: func(r *sdk.TunnelRequest) (*sdk.TunnelConfig, error) {
			calls++
			switch mode {
			case "echo":
				b, _ := json.Marshal(r)
				return &sdk.TunnelConfig{Name: "echo", Config: string(b)}, nil
			case "none":
				return nil, sdk.NoConfig("nothing here")
			case "panic":
				panic("tunneler exploded")
			case "later":
				if calls > 1 {
					panic("tunneler exploded later")
				}
			case "spin":
				for {
				}
			case "badname":
				return &sdk.TunnelConfig{Name: "two\nlines", Config: "x"}, nil
			case "huge":
				return &sdk.TunnelConfig{Name: "huge", Config: strings.Repeat("#", 100<<10)}, nil
			case "enormous":
				return &sdk.TunnelConfig{Name: "enormous", Config: strings.Repeat("#", 1<<20)}, nil
			case "escaped":
				line := "# <" + strings.Repeat("<", 60) + "\r\n"
				return &sdk.TunnelConfig{Name: "escaped", Config: strings.Repeat(line, (64<<10)/len(line))}, nil
			case "error":
				return nil, errors.New("tunneler failed on purpose")
			}
			list, err := sdk.FolderList()
			if err != nil {
				return nil, err
			}
			if len(list) == 0 {
				return nil, sdk.NoConfig("an empty folder")
			}
			after := r.Config
			if after == "" {
				after = r.Current
			}
			i := 0
			for j, e := range list {
				if e.Name == after {
					i = (j + 1) % len(list)
				}
			}
			b, err := sdk.FolderRead(list[i].Name)
			if err != nil {
				return nil, err
			}
			if mode == "forever" {
				return &sdk.TunnelConfig{Name: list[i].Name, Config: string(b), Keep: 1000 * 24 * time.Hour}, nil
			}
			return &sdk.TunnelConfig{Name: list[i].Name, Config: string(b), Keep: keep}, nil
		},
	})
}

func main() {}
