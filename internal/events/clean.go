// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"strings"
	"unicode/utf8"
)

// Clean makes text from outside vpnw (a plugin, a config file) safe to
// record and print: control characters (terminal escapes and newlines
// included) and the Unicode marks that reorder text on screen become "?",
// invalid UTF-8 becomes "?", and the text is cut at max runes. Without
// this, such text could draw on the terminal, for example by faking a vpnw
// line.
func Clean(s string, max int) string {
	var b strings.Builder
	n := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if n == max {
			b.WriteString("…")
			break
		}
		n++
		switch {
		case r == utf8.RuneError && size == 1,
			r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f,
			r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0x2028, r == 0x2029:
			b.WriteByte('?')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
