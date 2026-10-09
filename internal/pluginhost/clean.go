// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package pluginhost

import (
	"strings"
	"unicode/utf8"
)

// clean makes text from a plugin safe to print: control characters
// (terminal escapes and newlines included) and the Unicode marks that
// reorder text on screen become "?", invalid UTF-8 becomes "?", and the
// text is cut at max runes. Without this a plugin with no console
// permission could still draw on the terminal through a refusal reason or
// an error message, for example by faking a vpnw line.
func clean(s string, max int) string {
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

// cleanValue cleans every string in an emitted event's fields, keys
// included, at any depth.
func cleanValue(v any) any {
	switch x := v.(type) {
	case string:
		return clean(x, 1000)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[clean(k, 64)] = cleanValue(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = cleanValue(val)
		}
		return out
	}
	return v
}
