// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package scope learns least-privilege access for a VPN from its traffic.
//
// A VPN gateway sees every connection its users open into the office
// network. Scope reads those connections as flows, maps each VPN address to
// the person behind it, and drafts rules that give each person, or each
// group whose active members all use something, just what was used. Before
// anything is enforced, the draft can be replayed against recorded traffic
// to show what it would block. Then it is exported as nftables rules for the
// gateway.
//
// Scope decides on addresses, ports and protocols only. It never sees
// payloads, and a flow record holds none.
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

// Version is the Scope engine's version.
const Version = "0.1.0"

// Proto is a transport protocol, by its IP protocol number.
type Proto uint8

const (
	TCP Proto = 6
	UDP Proto = 17
)

func (p Proto) String() string {
	switch p {
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	}
	return "proto-" + strconv.Itoa(int(p))
}

// ParseProto reads "tcp" or "udp".
func ParseProto(s string) (Proto, error) {
	switch s {
	case "tcp":
		return TCP, nil
	case "udp":
		return UDP, nil
	}
	return 0, fmt.Errorf("protocol %q: want tcp or udp", s)
}

// Flow is one new connection seen at the gateway: when, which protocol, from
// which VPN address, to which address and port.
type Flow struct {
	Time  time.Time
	Proto Proto
	Src   netip.Addr
	Dst   netip.Addr
	Port  uint16
}

// Key is a flow's destination: address, port and protocol.
type Key struct {
	Dst   netip.Addr
	Port  uint16
	Proto Proto
}

// Key returns the flow's destination.
func (f Flow) Key() Key { return Key{f.Dst, f.Port, f.Proto} }

func (k Key) String() string {
	return fmt.Sprintf("%s:%d/%s", k.Dst, k.Port, k.Proto)
}

// AppendJSON appends the flow as one line of JSON, without the newline:
//
//	{"t":"2026-09-14T09:12:03.25Z","proto":"tcp","src":"10.8.0.11","dst":"10.0.1.20","port":443}
func (f Flow) AppendJSON(b []byte) []byte {
	b = append(b, `{"t":"`...)
	b = f.Time.UTC().AppendFormat(b, time.RFC3339Nano)
	b = append(b, `","proto":"`...)
	b = append(b, f.Proto.String()...)
	b = append(b, `","src":"`...)
	b = f.Src.AppendTo(b)
	b = append(b, `","dst":"`...)
	b = f.Dst.AppendTo(b)
	b = append(b, `","port":`...)
	b = strconv.AppendUint(b, uint64(f.Port), 10)
	return append(b, '}')
}

// Check reports what is wrong with a flow, if anything.
func (f Flow) Check() error {
	switch {
	case f.Time.IsZero():
		return errors.New("no time")
	case f.Proto != TCP && f.Proto != UDP:
		return fmt.Errorf("protocol %s: want tcp or udp", f.Proto)
	case !f.Src.Is4() || !f.Dst.Is4():
		return errors.New("only IPv4 addresses are supported in this version")
	case f.Port == 0:
		return errors.New("port 0")
	}
	return nil
}

// ParseFlowJSON reads one flow line in the format AppendJSON writes. The
// keys may come in any order and unknown keys with string or number values
// are skipped. String escapes are refused: Scope never writes them.
func ParseFlowJSON(line string) (Flow, error) {
	var f Flow
	s := strings.TrimSpace(line)
	if len(s) < 2 || s[0] != '{' || s[len(s)-1] != '}' {
		return f, errors.New("not a JSON object")
	}
	s = strings.TrimSpace(s[1 : len(s)-1])
	var seen [5]bool
	for s != "" {
		key, rest, err := jsonString(s)
		if err != nil {
			return f, err
		}
		rest = strings.TrimLeft(rest, " \t")
		if rest == "" || rest[0] != ':' {
			return f, fmt.Errorf("expected : after %q", key)
		}
		rest = strings.TrimLeft(rest[1:], " \t")
		var val string
		isStr := strings.HasPrefix(rest, `"`)
		if isStr {
			val, rest, err = jsonString(rest)
			if err != nil {
				return f, err
			}
		} else {
			end := strings.IndexAny(rest, ", \t")
			if end < 0 {
				end = len(rest)
			}
			val, rest = rest[:end], rest[end:]
			if val == "" {
				return f, fmt.Errorf("missing value for %q", key)
			}
			for _, c := range val {
				if (c < '0' || c > '9') && c != '-' && c != '.' && c != 'e' && c != 'E' && c != '+' {
					return f, fmt.Errorf("value for %q: only strings and numbers are allowed", key)
				}
			}
		}
		idx := -1
		switch key {
		case "t":
			idx = 0
			if !isStr {
				return f, errors.New(`"t" must be a string`)
			}
			if f.Time, err = time.Parse(time.RFC3339Nano, val); err != nil {
				return f, fmt.Errorf(`"t": %v`, err)
			}
		case "proto":
			idx = 1
			if !isStr {
				return f, errors.New(`"proto" must be a string`)
			}
			if f.Proto, err = ParseProto(val); err != nil {
				return f, err
			}
		case "src", "dst":
			if !isStr {
				return f, fmt.Errorf("%q must be a string", key)
			}
			a, err := netip.ParseAddr(val)
			if err != nil {
				return f, fmt.Errorf("%q: %v", key, err)
			}
			if key == "src" {
				idx, f.Src = 2, a
			} else {
				idx, f.Dst = 3, a
			}
		case "port":
			idx = 4
			if isStr {
				return f, errors.New(`"port" must be a number`)
			}
			n, err := strconv.ParseUint(val, 10, 16)
			if err != nil {
				return f, fmt.Errorf(`"port": %q is not a port number`, val)
			}
			f.Port = uint16(n)
		}
		if idx >= 0 {
			if seen[idx] {
				return f, fmt.Errorf("key %q appears twice", key)
			}
			seen[idx] = true
		}
		rest = strings.TrimLeft(rest, " \t")
		if rest == "" {
			break
		}
		if rest[0] != ',' {
			return f, fmt.Errorf("expected , after %q", key)
		}
		s = strings.TrimLeft(rest[1:], " \t")
		if s == "" {
			return f, errors.New("trailing comma")
		}
	}
	for i, name := range []string{"t", "proto", "src", "dst", "port"} {
		if !seen[i] {
			return f, fmt.Errorf("missing %q", name)
		}
	}
	return f, f.Check()
}

func jsonString(s string) (val, rest string, err error) {
	if !strings.HasPrefix(s, `"`) {
		return "", "", errors.New("expected a string")
	}
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			return "", "", errors.New("string escapes are not supported")
		case '"':
			return s[1:i], s[i+1:], nil
		}
		if s[i] < 0x20 {
			return "", "", errors.New("control character in string")
		}
	}
	return "", "", errors.New("unterminated string")
}

// ReadStats counts what ReadFlows saw.
type ReadStats struct {
	Lines   int
	Flows   int
	Skipped int // blank lines and comments
}

// MaxLine is the longest flow line accepted.
const MaxLine = 4096

// ReadFlows reads flow lines from r and calls fn for each. Blank lines and
// lines starting with # are skipped. A bad line stops the read with an error
// naming the line.
func ReadFlows(r io.Reader, name string, fn func(Flow) error) (ReadStats, error) {
	var st ReadStats
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, MaxLine), MaxLine)
	for sc.Scan() {
		st.Lines++
		line := sc.Text()
		t := strings.TrimSpace(line)
		if t == "" || t[0] == '#' {
			st.Skipped++
			continue
		}
		f, err := ParseFlowJSON(t)
		if err != nil {
			return st, fmt.Errorf("%s:%d: %v", name, st.Lines, err)
		}
		st.Flows++
		if err := fn(f); err != nil {
			return st, err
		}
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return st, fmt.Errorf("%s:%d: line longer than %d bytes", name, st.Lines+1, MaxLine)
		}
		return st, fmt.Errorf("%s: %v", name, err)
	}
	return st, nil
}

// FlowWriter writes flows as JSON Lines.
type FlowWriter struct {
	w   *bufio.Writer
	buf []byte
}

// NewFlowWriter returns a writer that buffers output to w.
func NewFlowWriter(w io.Writer) *FlowWriter {
	return &FlowWriter{w: bufio.NewWriterSize(w, 64*1024)}
}

// Write writes one flow line.
func (fw *FlowWriter) Write(f Flow) error {
	fw.buf = append(f.AppendJSON(fw.buf[:0]), '\n')
	_, err := fw.w.Write(fw.buf)
	return err
}

// Flush writes any buffered data.
func (fw *FlowWriter) Flush() error { return fw.w.Flush() }
