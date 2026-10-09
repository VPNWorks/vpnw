// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package process

// InterfacesOK reports whether the interfaces seen inside a fresh network
// namespace are exactly what a sealed run expects: loopback and nothing else.
// A sealed run refuses to start if anything else is present, because another
// interface could carry traffic straight out, around the broker.
func InterfacesOK(ifs []string) bool {
	return len(ifs) == 1 && ifs[0] == "lo"
}
