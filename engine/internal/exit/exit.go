// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package exit is VPN Works Exit, the far end of the tunnel. An exit takes
// HTTP CONNECT and SOCKS5 requests over TLS from its clients, each known by a
// token. It decides every request with that client's own policy, using the
// Agent's policy engine and the same steps as the Agent's broker, connects
// from the client's fixed source address, and keeps a record of its own in
// the Agent's event model, tagged with the client's run and connection IDs so
// the two records join up.
//
// This package holds the parts without network I/O: the configuration, the
// tokens, the IDs a client sends, source addresses, decisions, and the join
// of an Agent's record with an exit's. The server is in exit/server.
package exit

// Version is the Exit engine's version.
const Version = "0.1.0"

// AuthDeny is the event an exit records when a client comes without a valid
// token. It is an event of schema v1 that only exits write: its fields are
// the peer's address, the protocol, the reason, and the destination when the
// request named one. The token itself is never recorded.
const AuthDeny = "auth.deny"
