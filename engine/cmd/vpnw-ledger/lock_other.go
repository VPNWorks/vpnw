// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package main

import "os"

// lock does nothing here: run one seal per ledger.
func lock(*os.File) error { return nil }
