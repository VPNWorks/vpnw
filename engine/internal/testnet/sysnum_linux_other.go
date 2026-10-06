// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !amd64 && !arm64

package testnet

// sysSetns is not wired up on this architecture; NS.Do reports an error.
const sysSetns = 0
