// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build wasip1

// Command rotate is the Rotate plugin: a tunnel plugin that hands vpnw the
// WireGuard configs in its folder, one after the other. See package rotate.
package main

import (
	"github.com/VPNWorks/vpnw/plugins/rotate/rotate"
	"github.com/VPNWorks/vpnw/plugins/sdk"
)

func init() { sdk.Register(rotate.Plugin()) }

func main() {}
