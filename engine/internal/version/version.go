// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package version holds the engine version shared by the CLI, the events and
// the browser build.
package version

// Version is the engine version. The Alpha was 0.1.x; 0.2.0 adds proxies
// over TLS, a list of exits with failover, and the run's ID sent to the exit.
const Version = "0.2.0"

// Schema is the version of the event schema written to every event ("v").
const Schema = 1
