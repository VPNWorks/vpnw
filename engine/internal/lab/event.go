// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package lab

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Event is one line of a recording. Which fields are set depends on Ev.
//
//	{"t":"2026-10-05T21:00:00.05Z","ev":"sent","kind":"dns","via":"direct","seq":1}
//	{"t":"2026-10-05T21:00:00.0507Z","ev":"arrival","kind":"dns","via":"direct","seq":1,"at":"vpn-dns","src":"10.66.0.2"}
type Event struct {
	T  time.Time
	Ev string

	// EvRun: the header.
	Lab        string     // the Lab version that made the recording
	Run        string     // the run's id, also part of every probe's name and tag
	App        string     // the app under test
	Scenario   string     // the scenario's name
	Seed       int64      // the seed of the timetable's jitter
	IntervalMS int        // the probe's interval in milliseconds
	Exit       netip.Addr // the VPN's exit address: arrivals from it came through the tunnel
	Home       netip.Addr // the home network's public address: arrivals from it left outside

	// EvStep.
	Step  string
	Fault string

	// EvSent and EvArrival.
	Kind string
	Via  string
	Seq  int
	At   string     // EvArrival: which observer
	Src  netip.Addr // EvArrival: the source address the observer saw

	// EvClient and EvApp: what changed, and any detail.
	State string
	Note  string
}

// MaxLine is the longest recording line accepted.
const MaxLine = 4096

// AppendJSON appends the event as one line of JSON, without the newline.
// Keys come in a fixed order and empty fields are left out.
func (e Event) AppendJSON(b []byte) []byte {
	b = append(b, `{"t":"`...)
	b = e.T.UTC().AppendFormat(b, time.RFC3339Nano)
	b = append(b, '"')
	str := func(k, v string) {
		if v != "" {
			b = append(b, `,"`...)
			b = append(b, k...)
			b = append(b, `":`...)
			b = appendString(b, v)
		}
	}
	num := func(k string, v int64, always bool) {
		if v != 0 || always {
			b = append(b, `,"`...)
			b = append(b, k...)
			b = append(b, `":`...)
			b = strconv.AppendInt(b, v, 10)
		}
	}
	addr := func(k string, a netip.Addr) {
		if a.IsValid() {
			str(k, a.String())
		}
	}
	str("ev", e.Ev)
	str("lab", e.Lab)
	str("run", e.Run)
	str("app", e.App)
	str("scenario", e.Scenario)
	num("seed", e.Seed, e.Ev == EvRun)
	num("interval_ms", int64(e.IntervalMS), false)
	addr("exit", e.Exit)
	addr("home", e.Home)
	str("step", e.Step)
	str("fault", e.Fault)
	str("kind", e.Kind)
	str("via", e.Via)
	num("seq", int64(e.Seq), e.Ev == EvSent || e.Ev == EvArrival)
	str("at", e.At)
	addr("src", e.Src)
	str("state", e.State)
	str("note", e.Note)
	return append(b, '}')
}

// appendString appends s as a JSON string. Invalid UTF-8 becomes U+FFFD.
func appendString(b []byte, s string) []byte {
	const hex = "0123456789abcdef"
	b = append(b, '"')
	for i := 0; i < len(s); {
		c := s[i]
		if c >= 0x80 {
			r, n := utf8.DecodeRuneInString(s[i:])
			b = utf8.AppendRune(b, r)
			i += n
			continue
		}
		switch {
		case c == '"' || c == '\\':
			b = append(b, '\\', c)
		case c == '\n':
			b = append(b, '\\', 'n')
		case c == '\t':
			b = append(b, '\\', 't')
		case c < 0x20 || c == 0x7f:
			b = append(b, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xf])
		default:
			b = append(b, c)
		}
		i++
	}
	return append(b, '"')
}

// value is one value of a flat JSON object: a string or an integer.
type value struct {
	s     string
	isStr bool
}

// parseObject reads a JSON object whose values are strings or integers and
// calls fn for each key in order.
func parseObject(line string, fn func(key string, v value) error) error {
	s := strings.TrimSpace(line)
	if len(s) < 2 || s[0] != '{' || s[len(s)-1] != '}' {
		return errors.New("not a JSON object")
	}
	s = skipSpace(s[1 : len(s)-1])
	for s != "" {
		key, rest, err := readString(s)
		if err != nil {
			return err
		}
		rest = skipSpace(rest)
		if rest == "" || rest[0] != ':' {
			return fmt.Errorf("expected : after %q", key)
		}
		rest = skipSpace(rest[1:])
		var v value
		if strings.HasPrefix(rest, `"`) {
			v.isStr = true
			if v.s, rest, err = readString(rest); err != nil {
				return err
			}
		} else {
			end := 0
			if end < len(rest) && rest[end] == '-' {
				end++
			}
			digits := end
			for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
				end++
			}
			if end == digits {
				if rest == "" || rest[0] == ',' {
					return fmt.Errorf("missing value for %q", key)
				}
				return fmt.Errorf("value for %q: only strings and integers are allowed", key)
			}
			v.s, rest = rest[:end], rest[end:]
		}
		if err := fn(key, v); err != nil {
			return err
		}
		rest = skipSpace(rest)
		if rest == "" {
			break
		}
		if rest[0] != ',' {
			return fmt.Errorf("expected , after %q", key)
		}
		s = skipSpace(rest[1:])
		if s == "" {
			return errors.New("trailing comma")
		}
	}
	return nil
}

func skipSpace(s string) string { return strings.TrimLeft(s, " \t\r\n") }

// readString reads a JSON string at the start of s, with its escapes.
func readString(s string) (val, rest string, err error) {
	if !strings.HasPrefix(s, `"`) {
		return "", "", errors.New("expected a string")
	}
	var b []byte
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			val = s[1:i]
			if b != nil {
				val = string(b)
			}
			if !utf8.ValidString(val) {
				return "", "", errors.New("a string is not valid UTF-8")
			}
			return val, s[i+1:], nil
		case c < 0x20:
			return "", "", errors.New("control character in a string")
		case c == '\\':
			if b == nil {
				b = append([]byte{}, s[1:i]...)
			}
			if i+1 >= len(s) {
				return "", "", errors.New("unterminated string")
			}
			i++
			switch s[i] {
			case '"', '\\', '/':
				b = append(b, s[i])
			case 'b':
				b = append(b, '\b')
			case 'f':
				b = append(b, '\f')
			case 'n':
				b = append(b, '\n')
			case 'r':
				b = append(b, '\r')
			case 't':
				b = append(b, '\t')
			case 'u':
				if i+4 >= len(s) {
					return "", "", errors.New("short \\u escape")
				}
				n, err := strconv.ParseUint(s[i+1:i+5], 16, 16)
				if err != nil {
					return "", "", fmt.Errorf("bad \\u escape %q", s[i+1:i+5])
				}
				b = utf8.AppendRune(b, rune(n))
				i += 4
			default:
				return "", "", fmt.Errorf("unknown escape \\%c", s[i])
			}
		default:
			if b != nil {
				b = append(b, c)
			}
		}
	}
	return "", "", errors.New("unterminated string")
}

// ParseEvent reads one recording line in the format AppendJSON writes. The
// keys may come in any order, and unknown keys with string or integer values
// are skipped.
func ParseEvent(line string) (Event, error) {
	var e Event
	seen := map[string]bool{}
	err := parseObject(line, func(key string, v value) error {
		if seen[key] {
			return fmt.Errorf("key %q appears twice", key)
		}
		seen[key] = true
		wantStr := func() error {
			if !v.isStr {
				return fmt.Errorf("%q must be a string", key)
			}
			return nil
		}
		wantNum := func(max int64) (int64, error) {
			if v.isStr {
				return 0, fmt.Errorf("%q must be a number", key)
			}
			n, err := strconv.ParseInt(v.s, 10, 64)
			if err != nil || n < 0 || n > max {
				return 0, fmt.Errorf("%q: %s is out of range", key, v.s)
			}
			return n, nil
		}
		wantAddr := func(a *netip.Addr) error {
			if err := wantStr(); err != nil {
				return err
			}
			p, err := netip.ParseAddr(v.s)
			if err != nil || !p.Is4() {
				return fmt.Errorf("%q: %q is not an IPv4 address", key, v.s)
			}
			*a = p
			return nil
		}
		var err error
		switch key {
		case "t":
			if err = wantStr(); err == nil {
				if e.T, err = time.Parse(time.RFC3339Nano, v.s); err != nil {
					err = fmt.Errorf(`"t": %q is not a time such as 2026-10-05T21:00:00.05Z`, v.s)
				}
			}
		case "ev":
			err = wantStr()
			e.Ev = v.s
		case "lab":
			err = wantStr()
			e.Lab = v.s
		case "run":
			err = wantStr()
			e.Run = v.s
		case "app":
			err = wantStr()
			e.App = v.s
		case "scenario":
			err = wantStr()
			e.Scenario = v.s
		case "seed":
			e.Seed, err = wantNum(1<<62 - 1)
		case "interval_ms":
			var n int64
			n, err = wantNum(60000)
			e.IntervalMS = int(n)
		case "exit":
			err = wantAddr(&e.Exit)
		case "home":
			err = wantAddr(&e.Home)
		case "step":
			err = wantStr()
			e.Step = v.s
		case "fault":
			err = wantStr()
			e.Fault = v.s
		case "kind":
			err = wantStr()
			e.Kind = v.s
		case "via":
			err = wantStr()
			e.Via = v.s
		case "seq":
			var n int64
			n, err = wantNum(1<<31 - 1)
			e.Seq = int(n)
		case "at":
			err = wantStr()
			e.At = v.s
		case "src":
			err = wantAddr(&e.Src)
		case "state":
			err = wantStr()
			e.State = v.s
		case "note":
			err = wantStr()
			e.Note = v.s
		}
		return err
	})
	if err != nil {
		return e, err
	}
	if !seen["t"] {
		return e, errors.New(`missing "t"`)
	}
	if !seen["ev"] {
		return e, errors.New(`missing "ev"`)
	}
	return e, e.Check()
}

// Check reports what is wrong with an event, if anything.
func (e Event) Check() error {
	if e.T.IsZero() {
		return errors.New("no time")
	}
	need := func(field, val string, list ...string) error {
		if val == "" {
			return fmt.Errorf("a %s event needs %q", e.Ev, field)
		}
		if len(list) > 0 && !oneOf(val, list...) {
			return fmt.Errorf("%q: %q is not one of %s", field, val, strings.Join(list, ", "))
		}
		return nil
	}
	var err error
	switch e.Ev {
	case EvRun:
		for _, f := range [][2]string{{"run", e.Run}, {"app", e.App}, {"scenario", e.Scenario}} {
			if err = need(f[0], f[1]); err != nil {
				return err
			}
		}
		switch {
		case e.IntervalMS <= 0:
			return errors.New(`a run event needs "interval_ms" above 0`)
		case !e.Exit.IsValid() || !e.Home.IsValid():
			return errors.New(`a run event needs the "exit" and "home" addresses`)
		case e.Exit == e.Home:
			return errors.New(`"exit" and "home" must differ, or no arrival can be told apart`)
		}
	case EvStep:
		err = need("step", e.Step, StepStart, StepFaultOn, StepFaultOff, StepStop)
	case EvSent, EvArrival:
		if err = need("kind", e.Kind, DNS, TCP, UDP); err == nil {
			err = need("via", e.Via, Direct, Proxy)
		}
		if err == nil && e.Ev == EvArrival {
			if err = need("at", e.At, AtHomeDNS, AtVPNDNS, AtZoneDNS, AtTCP, AtUDP); err == nil && !e.Src.IsValid() {
				err = errors.New(`an arrival needs "src"`)
			}
		}
	case EvClient, EvApp:
		err = need("state", e.State)
	default:
		err = fmt.Errorf(`"ev": %q is not one of run, step, sent, arrival, client, app`, e.Ev)
	}
	return err
}

// ReadStats counts what ReadEvents saw.
type ReadStats struct {
	Lines   int
	Events  int
	Skipped int // blank lines and comments
}

// ReadEvents reads recording lines from r and calls fn for each event.
// Blank lines and lines starting with # are skipped. A bad line stops the
// read with an error naming the file and the line.
func ReadEvents(r io.Reader, name string, fn func(Event) error) (ReadStats, error) {
	var st ReadStats
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, MaxLine), MaxLine)
	for sc.Scan() {
		st.Lines++
		t := strings.TrimSpace(sc.Text())
		if t == "" || t[0] == '#' {
			st.Skipped++
			continue
		}
		e, err := ParseEvent(t)
		if err != nil {
			return st, fmt.Errorf("%s:%d: %v", name, st.Lines, err)
		}
		st.Events++
		if err := fn(e); err != nil {
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

// EventWriter writes events as JSON Lines.
type EventWriter struct {
	w   *bufio.Writer
	buf []byte
}

// NewEventWriter returns a writer that buffers output to w.
func NewEventWriter(w io.Writer) *EventWriter {
	return &EventWriter{w: bufio.NewWriterSize(w, 32*1024)}
}

// Write writes one event line.
func (ew *EventWriter) Write(e Event) error {
	ew.buf = append(e.AppendJSON(ew.buf[:0]), '\n')
	_, err := ew.w.Write(ew.buf)
	return err
}

// Flush writes any buffered data.
func (ew *EventWriter) Flush() error { return ew.w.Flush() }
