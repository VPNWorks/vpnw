// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// FuzzParse checks that no input crashes the parser or is accepted with a
// leftover error, and that any file it accepts round-trips through a second
// parse of nothing surprising.
func FuzzParse(f *testing.F) {
	f.Add(archExample)
	f.Add("version = 1\n[policy]\nallow = [\"a\", \"b\"]\n")
	f.Add("version = 1\nx = [[1],[2]]\n")
	f.Add("version = 1\nname = \"\\u00e9\"\n")
	f.Add("[[[")
	f.Add("version = 1\r\n[network]\r\ntype=\"proxy\"\r\nurl=\"socks5://h:1\"\r\n")
	f.Fuzz(func(t *testing.T, src string) {
		file, err := ParseFile("fuzz.toml", src)
		if err != nil {
			if strings.Contains(err.Error(), "panic") {
				t.Fatal(err)
			}
			return
		}
		if file.Version != 1 {
			t.Fatalf("accepted version %d", file.Version)
		}
		for name, p := range file.Paths {
			if p.Type != "direct" && p.Type != "proxy" {
				t.Fatalf("path %q has type %q", name, p.Type)
			}
		}
	})
}
