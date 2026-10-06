// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build js

package plan

// dnsMessage words a lookup error. The browser build has no net.DNSError;
// its lookups return errors that already read like the broker's.
func dnsMessage(err error) string { return err.Error() }
