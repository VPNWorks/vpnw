// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package process

const (
	seccompSupported   = true
	auditArch          = 0xc000003e // AUDIT_ARCH_X86_64
	x32Bit             = 0x40000000 // x32 system calls carry this bit
	sysSocket          = 41
	sysIoUringSetup    = 425
	sysIoUringEnter    = 426
	sysIoUringRegister = 427
)
