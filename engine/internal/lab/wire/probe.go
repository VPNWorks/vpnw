// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package wire

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"vpnw.com/vpnw/internal/lab"
)

// Zone is the DNS zone the probe asks about. ".test" is reserved for
// testing, so no real resolver answers for it.
const Zone = "lab.test"

// Probe names one probe of a run.
type Probe struct {
	Kind string // lab.DNS, lab.TCP or lab.UDP
	Via  string // lab.Direct or lab.Proxy
	Run  string
	Seq  int
}

// CheckRun reports whether a run id can go into probe names and tags: 1 to
// 32 characters, lower-case letters, digits and hyphens.
func CheckRun(run string) error {
	if run == "" || len(run) > 32 {
		return fmt.Errorf("run id %q: want 1 to 32 characters", run)
	}
	for _, c := range run {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return fmt.Errorf("run id %q: only lower-case letters, digits and hyphens", run)
		}
	}
	return nil
}

// Name is the DNS name a DNS probe asks for, unique to the probe:
// "d17.r-3f9a1c.lab.test" for direct probe 17 of run r-3f9a1c, "p17..."
// for the same probe sent through the proxy.
func (p Probe) Name() string {
	v := "d"
	if p.Via == lab.Proxy {
		v = "p"
	}
	return v + strconv.Itoa(p.Seq) + "." + p.Run + "." + Zone
}

// ParseName reads a DNS probe's name. Names outside the zone are refused.
func ParseName(name string) (Probe, error) {
	p := Probe{Kind: lab.DNS}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	rest, ok := strings.CutSuffix(name, "."+Zone)
	if !ok {
		return p, fmt.Errorf("%q is not in %s", name, Zone)
	}
	first, run, ok := strings.Cut(rest, ".")
	if !ok || len(first) < 2 {
		return p, fmt.Errorf("%q is not a probe's name", name)
	}
	switch first[0] {
	case 'd':
		p.Via = lab.Direct
	case 'p':
		p.Via = lab.Proxy
	default:
		return p, fmt.Errorf("%q is not a probe's name", name)
	}
	seq, err := parseSeq(first[1:])
	if err != nil {
		return p, fmt.Errorf("%q: %v", name, err)
	}
	if err := CheckRun(run); err != nil {
		return p, err
	}
	p.Seq, p.Run = seq, run
	return p, nil
}

func parseSeq(s string) (int, error) {
	if s == "" || len(s) > 1 && s[0] == '0' {
		return 0, errors.New("not a sequence number")
	}
	n, err := strconv.ParseUint(s, 10, 31)
	if err != nil {
		return 0, errors.New("not a sequence number")
	}
	return int(n), nil
}

// tagWord starts every tag.
const tagWord = "vpnw-lab"

// Tag is the line a TCP or UDP probe carries: "vpnw-lab tcp direct
// r-3f9a1c 17\n". A DNS probe sent through the proxy carries one too, on
// the connection it opens by name.
func (p Probe) Tag() string {
	return tagWord + " " + p.Kind + " " + p.Via + " " + p.Run + " " + strconv.Itoa(p.Seq) + "\n"
}

// MaxTag is the longest tag line.
const MaxTag = 80

// ParseTag reads a probe's tag line.
func ParseTag(s string) (Probe, error) {
	var p Probe
	if len(s) > MaxTag {
		return p, errors.New("tag too long")
	}
	f := strings.Fields(s)
	if len(f) != 5 || f[0] != tagWord {
		return p, errors.New("not a probe's tag")
	}
	switch f[1] {
	case lab.DNS, lab.TCP, lab.UDP:
	default:
		return p, fmt.Errorf("tag: kind %q", f[1])
	}
	switch f[2] {
	case lab.Direct, lab.Proxy:
	default:
		return p, fmt.Errorf("tag: via %q", f[2])
	}
	if err := CheckRun(f[3]); err != nil {
		return p, err
	}
	seq, err := parseSeq(f[4])
	if err != nil {
		return p, fmt.Errorf("tag: %v", err)
	}
	return Probe{Kind: f[1], Via: f[2], Run: f[3], Seq: seq}, nil
}
