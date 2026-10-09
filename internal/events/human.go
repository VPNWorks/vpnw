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
