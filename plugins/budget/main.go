// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build wasip1

// Command budget is the Budget plugin: a Guard that allows only the hosts
// on its list, each with byte and connection budgets. See package budget.
package main

import (
	"github.com/VPNWorks/vpnw/plugins/budget/budget"
	"github.com/VPNWorks/vpnw/plugins/sdk"
)

func init() { sdk.Register(budget.Plugin()) }

func main() {}
