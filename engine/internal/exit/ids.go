// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package exit

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// IDs are what a client says about a request besides where it goes: its run
// and connection IDs, which tag the exit's record so it joins the client's,
// and, rarely, the source address it asks for.
//
// Over HTTP CONNECT they are headers:
//
//	VPNW-Run: r-3f9a1c
//	VPNW-Conn: 17
//	VPNW-Source: 198.51.100.21      (optional)
//
// Over SOCKS5, which has no headers, they are the user name of the
// user-and-password login, RUN/CONN or RUN/CONN/SOURCE, with the token as
// the password. A user name without a slash carries no IDs.
type IDs struct {
	Run    string
	Conn   uint64
	Source string
}

// ParseRun checks a run ID: 1 to 64 letters, digits, dots, dashes and
// underscores.
func ParseRun(s string) (string, error) {
	if s == "" || len(s) > 64 {
		return "", errors.New("a run ID has 1 to 64 characters")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return "", fmt.Errorf("a run ID has letters, digits, dots, dashes and underscores only, not %q", string(c))
		}
	}
	return s, nil
}

// ParseConn checks a connection ID: a whole number from 1 up, in decimal,
// with no sign and no leading zero.
func ParseConn(s string) (uint64, error) {
	if s == "" || len(s) > 20 || s[0] == '0' {
		return 0, fmt.Errorf("connection ID %q: want a whole number from 1 up", s)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("connection ID %q: want a whole number from 1 up", s)
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("connection ID %q is too large", s)
	}
	return n, nil
}

// ParseSource checks an address a client asks to leave from.
func ParseSource(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("source %q is not an IP address", s)
	}
	return a.Unmap(), nil
}

// FromHeaders reads the IDs from HTTP header values. A request may carry no
// IDs at all; a run ID needs a connection ID with it, and the other way
// round.
func FromHeaders(run, conn, source string) (IDs, error) {
	var ids IDs
	if (run == "") != (conn == "") {
		return ids, errors.New("VPNW-Run and VPNW-Conn go together")
	}
	if run != "" {
		var err error
		if ids.Run, err = ParseRun(run); err != nil {
			return IDs{}, fmt.Errorf("VPNW-Run: %v", err)
		}
		if ids.Conn, err = ParseConn(conn); err != nil {
			return IDs{}, fmt.Errorf("VPNW-Conn: %v", err)
		}
	}
	if source != "" {
		a, err := ParseSource(source)
		if err != nil {
			return IDs{}, fmt.Errorf("VPNW-Source: %v", err)
		}
		ids.Source = a.String()
	}
	return ids, nil
}

// ParseSOCKSUser reads the IDs from a SOCKS5 user name.
func ParseSOCKSUser(u string) (IDs, error) {
	if !strings.Contains(u, "/") {
		return IDs{}, nil
	}
	parts := strings.Split(u, "/")
	if len(parts) > 3 {
		return IDs{}, errors.New("the user name holds RUN/CONN or RUN/CONN/SOURCE")
	}
	src := ""
	if len(parts) == 3 {
		src = parts[2]
		if src == "" {
			return IDs{}, errors.New("the source after the second slash is empty")
		}
	}
	return FromHeaders(parts[0], parts[1], src)
}

// SOCKSUser writes the IDs as a SOCKS5 user name.
func (i IDs) SOCKSUser() string {
	s := i.Run + "/" + strconv.FormatUint(i.Conn, 10)
	if i.Source != "" {
		s += "/" + i.Source
	}
	return s
}
