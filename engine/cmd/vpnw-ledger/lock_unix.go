// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import (
	"fmt"
	"os"
	"syscall"
)

// lock keeps the ledger to this seal alone. The lock goes with the process,
// so a seal that crashed leaves none behind.
func lock(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("%s is in use by another vpnw-ledger seal", f.Name())
	}
	return nil
}
