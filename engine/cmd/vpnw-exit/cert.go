// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/x509"
	"time"
)

// parseLeaf returns when a certificate stops being valid.
func parseLeaf(der []byte) (time.Time, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return time.Time{}, err
	}
	return c.NotAfter.UTC(), nil
}
