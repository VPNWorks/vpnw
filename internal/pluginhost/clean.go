// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package pluginhost

import "github.com/VPNWorks/vpnw/internal/events"

// clean makes text from a plugin safe to print: see events.Clean. Without
// it a plugin with no console permission could still draw on the terminal
// through a refusal reason or an error message, for example by faking a
// vpnw line.
func clean(s string, max int) string { return events.Clean(s, max) }

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
