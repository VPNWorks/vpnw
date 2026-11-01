// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package version holds the version of vpnw, the VPN Works core.
package version

// Version is the release version. 0.3.0 was the first release of the core
// and plugin platform; 0.4.0 adds WireGuard paths, run inside vpnw; 0.4.1
// runs the IPv6 escape tests in CI and fixes a race in closing plugins;
// 0.5.0 adds Ledger and the file.write permission. 0.6.0 adds Lab, the
// fault kit in the tests, and the fixes it found. 0.7.0 adds Exit, the
// server end of a path (vpnw exit). 0.8.0 adds Tunnel plugins, the
// folder.read permission and the built-in rotate plugin. 0.9.0 adds byte
// budgets for Guards (the meter host call), the built-in budget plugin and
// the exit's reload of its clients file.
const Version = "0.9.0"

// Schema is the version of the event schema written to every event ("v").
const Schema = 1
