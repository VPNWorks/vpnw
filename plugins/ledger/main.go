// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build wasip1

// Command ledger is the Ledger plugin: an Observer that seals a run's
// events into a hash-chained ledger as the run goes. See package seal.
package main

import (
	"github.com/VPNWorks/vpnw/plugins/ledger/seal"
	"github.com/VPNWorks/vpnw/plugins/sdk"
)

func init() { sdk.Register(seal.Plugin()) }

func main() {}
