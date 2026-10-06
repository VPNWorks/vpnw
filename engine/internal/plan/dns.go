// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build !js

package plan

import (
	"errors"
	"net"
)

// dnsMessage words a lookup error the way the broker's events do.
func dnsMessage(err error) string {
	var de *net.DNSError
	if errors.As(err, &de) {
		switch {
		case de.IsNotFound:
			return "no such host"
		case de.IsTimeout:
			return "timed out"
		}
		return de.Err
	}
	return err.Error()
}
