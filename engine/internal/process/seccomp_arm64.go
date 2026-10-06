// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux && arm64

package process

const (
	seccompSupported   = true
	auditArch          = 0xc00000b7 // AUDIT_ARCH_AARCH64
	x32Bit             = 0xffffffff // no x32 on arm64: matches nothing real
	sysSocket          = 198
	sysIoUringSetup    = 425
	sysIoUringEnter    = 426
	sysIoUringRegister = 427
)
