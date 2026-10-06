// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package main

import "io"

func recordCmd(args []string, stdout, stderr io.Writer) int {
	return fail(stderr, exitUnavailable, "record needs a Linux gateway with nftables; learn, replay, export and check work anywhere")
}
