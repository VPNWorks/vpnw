// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package main

import "io"

func runCmd(args []string, stdout, stderr io.Writer) int {
	return fail(stderr, exitUnavailable, "run needs Linux, with user namespaces, nftables and the TUN driver; verdict, list and probe work anywhere")
}

func clientCmd(args []string, stderr io.Writer) int {
	return fail(stderr, exitUnavailable, "the stand-in clients need Linux: a TUN device, policy routing and nftables")
}
