// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package pluginhost

import "syscall"

const openNonblock = syscall.O_NONBLOCK
