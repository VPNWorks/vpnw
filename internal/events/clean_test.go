// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"strings"
	"testing"
)

// Text from outside vpnw is printed and recorded only once it can't draw
// on a terminal, and only up to a length.
func TestClean(t *testing.T) {
	for _, c := range []struct {
		in   string
		max  int
		want string
	}{
		{"plain text", 100, "plain text"},
		{"two\nlines\r", 100, "two?lines?"},
		{"\x1b[2Kfake", 100, "?[2Kfake"},
		{"bell\a and \x7f and \u0085", 100, "bell? and ? and ?"},
		{"rtl ‮ and ⁦ isolated", 100, "rtl ? and ? isolated"},
		{"bad \xff utf-8", 100, "bad ? utf-8"},
		{"Grüße, 東京", 100, "Grüße, 東京"},
		{strings.Repeat("x", 12), 10, strings.Repeat("x", 10) + "…"},
		{strings.Repeat("x", 10), 10, strings.Repeat("x", 10)},
	} {
		if got := Clean(c.in, c.max); got != c.want {
			t.Errorf("Clean(%q, %d) = %q, want %q", c.in, c.max, got, c.want)
		}
	}
}
