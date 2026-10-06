// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package exit

import (
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"

	"vpnw.com/vpnw/internal/plan"
)

// Decide works out what the exit does with one request from this client. It
// is the Agent's own request plan, the steps its broker takes, on a path that
// resolves names where it stands: at the exit, names are resolved by the
// exit. So a name rule, a wildcard, an address range, deny_private and the
// default all decide here exactly as they do at the Agent, given the same
// answers from DNS. lookup answers the DNS questions; it is asked only when
// an address can change the decision, or to connect.
func (cl *Client) Decide(host string, port int, lookup func(string) ([]net.IP, error)) plan.Plan {
	return plan.Request(cl.Policy, host, port, false, lookup)
}

// Addresses lists the addresses the client may leave from.
func (cl *Client) Addresses() []netip.Addr {
	if cl.Pool != nil {
		return cl.Pool.Addrs
	}
	return []netip.Addr{cl.Source}
}

// SourceFor picks the address a connection of this client leaves from. With
// no request it is the client's own fixed address, or the address of its pool
// that the client's name maps to, so a client keeps one address from one
// connection to the next. A client may ask for another address of its own
// pool; an address that is not the client's is refused.
func (cl *Client) SourceFor(want string) (netip.Addr, error) {
	if want != "" {
		a, err := ParseSource(want)
		if err != nil {
			return netip.Addr{}, err
		}
		for _, x := range cl.Addresses() {
			if x == a {
				return a, nil
			}
		}
		return netip.Addr{}, fmt.Errorf("%s is not one of the source addresses of client %s", a, cl.Name)
	}
	if cl.Pool == nil {
		return cl.Source, nil
	}
	h := fnv.New32a()
	h.Write([]byte(cl.Name))
	return cl.Pool.Addrs[int(h.Sum32()%uint32(len(cl.Pool.Addrs)))], nil
}
