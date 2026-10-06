// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// ParseConntrackLine reads one line of "conntrack -E -o timestamp" output.
// It returns ok=false, with no error, for events other than [NEW] and for
// protocols other than tcp and udp. Only the original direction (the first
// src=, dst= and dport=) counts. Lines from "-o extended" are accepted too.
//
//	[1695801234.567890]	    [NEW] tcp      6 120 SYN_SENT src=10.8.0.11 dst=10.0.1.20 sport=51234 dport=443 [UNREPLIED] src=10.0.1.20 ...
func ParseConntrackLine(line string) (f Flow, ok bool, err error) {
	s := strings.TrimSpace(line)
	if !strings.HasPrefix(s, "[") {
		return f, false, errors.New("no [timestamp]: record with conntrack -E -o timestamp")
	}
	end := strings.IndexByte(s, ']')
	if end < 0 {
		return f, false, errors.New("unterminated [timestamp]")
	}
	ts := s[1:end]
	if ts == "" || ts[0] < '0' || ts[0] > '9' {
		return f, false, errors.New("no [timestamp]: record with conntrack -E -o timestamp")
	}
	sec, frac, _ := strings.Cut(ts, ".")
	secs, err := strconv.ParseInt(sec, 10, 64)
	if err != nil || secs < 0 {
		return f, false, fmt.Errorf("timestamp %q: want seconds since 1970", ts)
	}
	var nsec int64
	if frac != "" {
		if len(frac) > 9 {
			return f, false, fmt.Errorf("timestamp %q: too many digits", ts)
		}
		n, err := strconv.ParseInt(frac, 10, 64)
		if err != nil || n < 0 {
			return f, false, fmt.Errorf("timestamp %q: bad fraction", ts)
		}
		for i := len(frac); i < 9; i++ {
			n *= 10
		}
		nsec = n
	}
	f.Time = time.Unix(secs, nsec).UTC()
	fields := strings.Fields(s[end+1:])
	if len(fields) == 0 {
		return f, false, errors.New("no event after the timestamp")
	}
	if fields[0] != "[NEW]" {
		return f, false, nil
	}
	fields = fields[1:]
	if len(fields) >= 2 && (fields[0] == "ipv4" || fields[0] == "ipv6") {
		if fields[0] == "ipv6" {
			return f, false, nil
		}
		fields = fields[2:]
	}
	if len(fields) < 2 {
		return f, false, errors.New("missing protocol")
	}
	switch fields[0] {
	case "tcp":
		f.Proto = TCP
	case "udp":
		f.Proto = UDP
	default:
		return f, false, nil
	}
	var haveSrc, haveDst, havePort bool
	for _, fld := range fields[1:] {
		k, v, found := strings.Cut(fld, "=")
		if !found {
			continue
		}
		switch k {
		case "src":
			if haveSrc {
				continue
			}
			a, err := netip.ParseAddr(v)
			if err != nil {
				return f, false, fmt.Errorf("src: %v", err)
			}
			f.Src, haveSrc = a, true
		case "dst":
			if haveDst {
				continue
			}
			a, err := netip.ParseAddr(v)
			if err != nil {
				return f, false, fmt.Errorf("dst: %v", err)
			}
			f.Dst, haveDst = a, true
		case "dport":
			if havePort {
				continue
			}
			n, err := strconv.ParseUint(v, 10, 16)
			if err != nil || n == 0 {
				return f, false, fmt.Errorf("dport %q is not a port", v)
			}
			f.Port, havePort = uint16(n), true
		}
		if haveSrc && haveDst && havePort {
			break
		}
	}
	if !haveSrc || !haveDst || !havePort {
		return f, false, errors.New("missing src=, dst= or dport=")
	}
	if !f.Src.Is4() || !f.Dst.Is4() {
		return f, false, nil
	}
	return f, true, f.Check()
}

// ConntrackStats counts what ReadConntrack saw.
type ConntrackStats struct {
	Lines, Flows, Ignored int
}

// ReadConntrack reads conntrack event output and calls fn for each new
// tcp or udp connection.
func ReadConntrack(r io.Reader, name string, fn func(Flow) error) (ConntrackStats, error) {
	var st ConntrackStats
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, MaxLine), MaxLine)
	for sc.Scan() {
		st.Lines++
		if strings.TrimSpace(sc.Text()) == "" {
			st.Ignored++
			continue
		}
		f, ok, err := ParseConntrackLine(sc.Text())
		if err != nil {
			return st, fmt.Errorf("%s:%d: %v", name, st.Lines, err)
		}
		if !ok {
			st.Ignored++
			continue
		}
		st.Flows++
		if err := fn(f); err != nil {
			return st, err
		}
	}
	if err := sc.Err(); err != nil {
		return st, fmt.Errorf("%s: %v", name, err)
	}
	return st, nil
}
