// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package config reads VPNW configuration files.
//
// The format is a strict subset of TOML: tables ([policy], [paths.office]),
// key = value pairs, and values that are strings, integers, booleans or arrays
// of those. Anything outside the subset is an error, never silently skipped:
// inline tables, arrays of tables, floats, dates and multi-line strings are
// refused with the line number. There is no environment-variable expansion,
// no include and no search path.
package config

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Kind is the type of a parsed value.
type Kind int

const (
	KString Kind = iota
	KInt
	KBool
	KArray
)

func (k Kind) String() string {
	switch k {
	case KString:
		return "string"
	case KInt:
		return "integer"
	case KBool:
		return "boolean"
	case KArray:
		return "array"
	}
	return "value"
}

// Value is one parsed TOML value.
type Value struct {
	Kind Kind
	Str  string
	Int  int64
	Bool bool
	Arr  []Value
	Line int
}

// Table is one [table] with its keys in file order.
type Table struct {
	Name  string
	Keys  map[string]*Value
	Order []string
	Line  int
}

// Doc is a parsed file. The root table has the name "".
type Doc struct {
	Tables map[string]*Table
	Order  []string
}

// Error is a parse or validation error tied to a line.
type Error struct {
	File string
	Line int
	Msg  string
}

func (e *Error) Error() string {
	switch {
	case e.File != "" && e.Line > 0:
		return fmt.Sprintf("%s:%d: %s", e.File, e.Line, e.Msg)
	case e.Line > 0:
		return fmt.Sprintf("line %d: %s", e.Line, e.Msg)
	case e.File != "":
		return fmt.Sprintf("%s: %s", e.File, e.Msg)
	}
	return e.Msg
}

// MaxSize is the largest configuration file accepted, in bytes.
const MaxSize = 1 << 20

// maxDepth limits nested arrays.
const maxDepth = 8

type parser struct {
	src  string
	pos  int
	line int
}

// Parse reads a document in the supported TOML subset.
func Parse(src string) (*Doc, error) {
	if len(src) > MaxSize {
		return nil, &Error{Msg: fmt.Sprintf("file is larger than %d bytes", MaxSize)}
	}
	if !utf8.ValidString(src) {
		return nil, &Error{Msg: "file is not valid UTF-8"}
	}
	if strings.IndexByte(src, 0) >= 0 {
		return nil, &Error{Msg: "file contains a NUL byte"}
	}
	p := &parser{src: src, line: 1}
	doc := &Doc{Tables: map[string]*Table{}}
	root := &Table{Name: "", Keys: map[string]*Value{}, Line: 1}
	doc.Tables[""] = root
	doc.Order = append(doc.Order, "")
	cur := root
	for {
		p.skipSpace()
		if p.eof() {
			return doc, nil
		}
		c := p.peek()
		switch {
		case c == '#':
			p.skipComment()
		case c == '\n':
			p.next()
		case c == '\r':
			if err := p.newline(); err != nil {
				return nil, err
			}
		case c == '[':
			t, err := p.tableHeader()
			if err != nil {
				return nil, err
			}
			if old, ok := doc.Tables[t]; ok {
				return nil, p.errf("table [%s] is defined twice (first on line %d)", t, old.Line)
			}
			cur = &Table{Name: t, Keys: map[string]*Value{}, Line: p.line}
			doc.Tables[t] = cur
			doc.Order = append(doc.Order, t)
			if err := p.endOfLine(); err != nil {
				return nil, err
			}
		default:
			line := p.line
			key, err := p.key()
			if err != nil {
				return nil, err
			}
			p.skipSpace()
			if p.eof() {
				return nil, p.errf("expected = after key %q", key)
			}
			if p.peek() == '.' {
				return nil, p.errf("dotted keys are not supported; use a [table] header")
			}
			if p.peek() != '=' {
				return nil, p.errf("expected = after key %q", key)
			}
			p.next()
			p.skipSpace()
			v, err := p.value(0)
			if err != nil {
				return nil, err
			}
			v.Line = line
			if _, dup := cur.Keys[key]; dup {
				return nil, &Error{Line: line, Msg: fmt.Sprintf("key %q is set twice in %s", key, tableLabel(cur.Name))}
			}
			cur.Keys[key] = &v
			cur.Order = append(cur.Order, key)
			if err := p.endOfLine(); err != nil {
				return nil, err
			}
		}
	}
}

func tableLabel(name string) string {
	if name == "" {
		return "the top level"
	}
	return "[" + name + "]"
}

func (p *parser) eof() bool  { return p.pos >= len(p.src) }
func (p *parser) peek() byte { return p.src[p.pos] }
func (p *parser) next() byte {
	c := p.src[p.pos]
	p.pos++
	if c == '\n' {
		p.line++
	}
	return c
}

func (p *parser) errf(format string, a ...any) error {
	return &Error{Line: p.line, Msg: fmt.Sprintf(format, a...)}
}

func (p *parser) skipSpace() {
	for !p.eof() && (p.peek() == ' ' || p.peek() == '\t') {
		p.pos++
	}
}

func (p *parser) skipComment() {
	for !p.eof() && p.peek() != '\n' {
		c := p.peek()
		if c < 0x20 && c != '\t' && c != '\r' {
			return
		}
		p.pos++
	}
}

func (p *parser) newline() error {
	if p.peek() == '\r' {
		p.pos++
		if p.eof() || p.peek() != '\n' {
			return p.errf("a carriage return must be followed by a newline")
		}
	}
	p.next()
	return nil
}

// endOfLine accepts optional spaces and a comment, then a newline or EOF.
func (p *parser) endOfLine() error {
	p.skipSpace()
	if p.eof() {
		return nil
	}
	if p.peek() == '#' {
		p.skipComment()
		if p.eof() {
			return nil
		}
	}
	switch p.peek() {
	case '\n', '\r':
		return p.newline()
	}
	return p.errf("unexpected %q after the value; one key per line", string(p.peek()))
}

func isBare(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

func (p *parser) key() (string, error) {
	if p.eof() {
		return "", p.errf("expected a key")
	}
	c := p.peek()
	if c == '"' || c == '\'' {
		s, err := p.str()
		if err != nil {
			return "", err
		}
		if s == "" {
			return "", p.errf("empty keys are not allowed")
		}
		return s, nil
	}
	start := p.pos
	for !p.eof() && isBare(p.peek()) {
		p.pos++
	}
	if p.pos == start {
		return "", p.errf("expected a key, found %q", string(c))
	}
	return p.src[start:p.pos], nil
}

func (p *parser) tableHeader() (string, error) {
	p.next() // [
	if !p.eof() && p.peek() == '[' {
		return "", p.errf("arrays of tables ([[...]]) are not supported")
	}
	var parts []string
	for {
		p.skipSpace()
		k, err := p.key()
		if err != nil {
			return "", err
		}
		parts = append(parts, k)
		p.skipSpace()
		if p.eof() {
			return "", p.errf("unterminated table header")
		}
		if p.peek() == '.' {
			p.next()
			continue
		}
		if p.peek() == ']' {
			p.next()
			break
		}
		return "", p.errf("unexpected %q in table header", string(p.peek()))
	}
	if len(parts) > 2 {
		return "", p.errf("table names have at most two parts, as in [paths.office]")
	}
	return strings.Join(parts, "."), nil
}

func (p *parser) value(depth int) (Value, error) {
	if p.eof() {
		return Value{}, p.errf("expected a value")
	}
	switch c := p.peek(); {
	case c == '"' || c == '\'':
		s, err := p.str()
		return Value{Kind: KString, Str: s, Line: p.line}, err
	case c == '[':
		return p.array(depth)
	case c == '{':
		return Value{}, p.errf("inline tables are not supported")
	case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
		return p.word()
	case c == '+' || c == '-' || (c >= '0' && c <= '9'):
		return p.integer()
	default:
		return Value{}, p.errf("unexpected %q where a value should be", string(c))
	}
}

func (p *parser) word() (Value, error) {
	start := p.pos
	for !p.eof() && isBare(p.peek()) {
		p.pos++
	}
	switch w := p.src[start:p.pos]; w {
	case "true":
		return Value{Kind: KBool, Bool: true, Line: p.line}, nil
	case "false":
		return Value{Kind: KBool, Bool: false, Line: p.line}, nil
	case "inf", "nan":
		return Value{}, p.errf("inf and nan are not supported")
	default:
		return Value{}, p.errf("unknown value %q; strings need quotes", w)
	}
}

func (p *parser) integer() (Value, error) {
	start := p.pos
	if p.peek() == '+' || p.peek() == '-' {
		p.pos++
	}
	for !p.eof() {
		c := p.peek()
		if c >= '0' && c <= '9' || c == '_' {
			p.pos++
			continue
		}
		if c == '.' || c == 'e' || c == 'E' || c == ':' || c == 'T' || c == 'x' || c == 'o' || c == 'b' {
			return Value{}, p.errf("only whole decimal numbers are supported")
		}
		break
	}
	lit := p.src[start:p.pos]
	digits := strings.TrimLeft(lit, "+-")
	if digits == "" {
		return Value{}, p.errf("expected digits")
	}
	if strings.HasPrefix(digits, "_") || strings.HasSuffix(digits, "_") || strings.Contains(digits, "__") {
		return Value{}, p.errf("underscores must sit between digits")
	}
	clean := strings.ReplaceAll(digits, "_", "")
	if len(clean) > 1 && clean[0] == '0' {
		return Value{}, p.errf("numbers must not start with 0")
	}
	n, err := strconv.ParseInt(strings.ReplaceAll(lit, "_", ""), 10, 64)
	if err != nil {
		return Value{}, p.errf("number out of range")
	}
	return Value{Kind: KInt, Int: n, Line: p.line}, nil
}

func (p *parser) str() (string, error) {
	q := p.next()
	if strings.HasPrefix(p.src[p.pos:], string([]byte{q, q})) {
		return "", p.errf("multi-line strings are not supported")
	}
	var b strings.Builder
	for {
		if p.eof() {
			return "", p.errf("unterminated string")
		}
		c := p.peek()
		if c == '\n' || c == '\r' {
			return "", p.errf("unterminated string")
		}
		if c < 0x20 && c != '\t' || c == 0x7f {
			return "", p.errf("control characters are not allowed in strings")
		}
		p.pos++
		if c == q {
			return b.String(), nil
		}
		if q == '"' && c == '\\' {
			if p.eof() {
				return "", p.errf("unterminated escape")
			}
			e := p.next()
			switch e {
			case '"':
				b.WriteByte('"')
			case '\\':
				b.WriteByte('\\')
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case 'u', 'U':
				n := 4
				if e == 'U' {
					n = 8
				}
				if p.pos+n > len(p.src) {
					return "", p.errf("short unicode escape")
				}
				v, err := strconv.ParseUint(p.src[p.pos:p.pos+n], 16, 32)
				if err != nil || v > utf8.MaxRune || (v >= 0xD800 && v <= 0xDFFF) {
					return "", p.errf("invalid unicode escape")
				}
				p.pos += n
				b.WriteRune(rune(v))
			default:
				return "", p.errf("unknown escape \\%s", string(e))
			}
			continue
		}
		b.WriteByte(c)
	}
}

// skipArraySpace skips spaces, newlines and comments inside an array.
func (p *parser) skipArraySpace() error {
	for !p.eof() {
		switch p.peek() {
		case ' ', '\t':
			p.pos++
		case '\n':
			p.next()
		case '\r':
			if err := p.newline(); err != nil {
				return err
			}
		case '#':
			p.skipComment()
		default:
			return nil
		}
	}
	return nil
}

func (p *parser) array(depth int) (Value, error) {
	if depth >= maxDepth {
		return Value{}, p.errf("arrays nested too deeply")
	}
	line := p.line
	p.next() // [
	v := Value{Kind: KArray, Line: line}
	for {
		if err := p.skipArraySpace(); err != nil {
			return Value{}, err
		}
		if p.eof() {
			return Value{}, &Error{Line: line, Msg: "unterminated array"}
		}
		if p.peek() == ']' {
			p.next()
			return v, nil
		}
		el, err := p.value(depth + 1)
		if err != nil {
			return Value{}, err
		}
		if len(v.Arr) > 0 && v.Arr[0].Kind != el.Kind {
			return Value{}, p.errf("arrays must hold one kind of value (found %s after %s)", el.Kind, v.Arr[0].Kind)
		}
		v.Arr = append(v.Arr, el)
		if err := p.skipArraySpace(); err != nil {
			return Value{}, err
		}
		if p.eof() {
			return Value{}, &Error{Line: line, Msg: "unterminated array"}
		}
		switch p.peek() {
		case ',':
			p.next()
		case ']':
			p.next()
			return v, nil
		default:
			return Value{}, p.errf("expected , or ] in array")
		}
	}
}
