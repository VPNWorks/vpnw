// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package events

import "fmt"

// HumanBytes prints 1234 as "1.2 KB".
func HumanBytes(n int64) string {
	switch {
	case n < 1000:
		return fmt.Sprintf("%d B", n)
	case n < 1000*1000:
		return fmt.Sprintf("%.1f KB", float64(n)/1000)
	case n < 1000*1000*1000:
		return fmt.Sprintf("%.1f MB", float64(n)/1e6)
	}
	return fmt.Sprintf("%.2f GB", float64(n)/1e9)
}

// BudgetBytes writes a budget the way it was most likely given: exactly,
// in the largest unit that divides it (10 MB, 256 KiB), else as HumanBytes.
func BudgetBytes(n int64) string {
	for _, u := range []struct {
		s string
		v int64
	}{{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"TB", 1e12}, {"GB", 1e9}, {"MB", 1e6}, {"KB", 1e3}} {
		if n >= u.v && n%u.v == 0 {
			return fmt.Sprintf("%d %s", n/u.v, u.s)
		}
	}
	return HumanBytes(n)
}
