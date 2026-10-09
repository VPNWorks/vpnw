// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !amd64 && !arm64

package process

// The Unix-socket filter is built for x86-64 and arm64 only. Elsewhere a
// sealed run refuses to start unless --allow-unix-sockets is given.
const (
	seccompSupported   = false
	auditArch          = 0
	x32Bit             = 0
	sysSocket          = 0
	sysIoUringSetup    = 0
	sysIoUringEnter    = 0
	sysIoUringRegister = 0
)
