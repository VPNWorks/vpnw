// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build wasip1

// Command ledgerverify is the ledger-verify plugin: an Advisor that checks
// a ledger written by the Ledger plugin. See package check.
package main

import (
	"github.com/VPNWorks/vpnw/plugins/ledgerverify/check"
	"github.com/VPNWorks/vpnw/plugins/sdk"
)

func init() { sdk.Register(check.Plugin()) }

func main() {}
