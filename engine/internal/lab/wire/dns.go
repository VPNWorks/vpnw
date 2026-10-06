// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package wire holds the small formats Lab speaks on the test network: DNS
// queries and answers for the probe's zone, the tags the probe puts in its
// TCP and UDP probes, the names it asks for, and the framing of the
// stand-in VPN tunnel. None of it is encrypted: the stand-ins are test
// fixtures, not VPNs.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// DNS record types and response codes Lab uses.
const (
	TypeA      = 1
	ClassIN    = 1
	RcodeOK    = 0
	RcodeNXDom = 3
	RcodeRefus = 5
	headerLen  = 12
	maxName    = 255
)

// Query builds a DNS query for an A record of name, with recursion desired.
func Query(id uint16, name string) ([]byte, error) {
	b := make([]byte, headerLen, headerLen+len(name)+6)
	binary.BigEndian.PutUint16(b[0:], id)
	b[2] = 0x01 // RD
	binary.BigEndian.PutUint16(b[4:], 1)
	var err error
	if b, err = appendName(b, name); err != nil {
		return nil, err
	}
	b = binary.BigEndian.AppendUint16(b, TypeA)
	return binary.BigEndian.AppendUint16(b, ClassIN), nil
}

func appendName(b []byte, name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > maxName-2 {
		return nil, fmt.Errorf("DNS name %q: want 1 to 253 characters", name)
	}
	for _, l := range strings.Split(name, ".") {
		if l == "" || len(l) > 63 {
			return nil, fmt.Errorf("DNS name %q: each label needs 1 to 63 characters", name)
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0), nil
}

// Question is the first question of a DNS message.
type Question struct {
	ID    uint16
	Name  string // lower case, without the final dot
	Type  uint16
	Class uint16
	End   int // where the question ends in the message
}

// ParseQuery reads a DNS query's header and its first question. It refuses
// responses, messages without exactly one question, and compressed names,
// which no query needs.
func ParseQuery(msg []byte) (Question, error) {
	var q Question
	if len(msg) < headerLen {
		return q, errors.New("DNS message shorter than its header")
	}
	q.ID = binary.BigEndian.Uint16(msg[0:])
	if msg[2]&0x80 != 0 {
		return q, errors.New("a DNS response, not a query")
	}
	if op := msg[2] >> 3 & 0x0f; op != 0 {
		return q, fmt.Errorf("DNS opcode %d: only standard queries", op)
	}
	if n := binary.BigEndian.Uint16(msg[4:]); n != 1 {
		return q, fmt.Errorf("%d questions: want 1", n)
	}
	var sb strings.Builder
	i := headerLen
	for {
		if i >= len(msg) {
			return q, errors.New("DNS name runs past the message")
		}
		l := int(msg[i])
		if l&0xc0 != 0 {
			return q, errors.New("compressed or extended label in a question")
		}
		i++
		if l == 0 {
			break
		}
		if i+l > len(msg) {
			return q, errors.New("DNS label runs past the message")
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		for _, c := range msg[i : i+l] {
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c <= ' ' || c == '.' || c >= 0x7f {
				return q, fmt.Errorf("DNS label with byte %#x", c)
			}
			sb.WriteByte(c)
		}
		if sb.Len() > maxName-2 {
			return q, errors.New("DNS name longer than 253 characters")
		}
		i += l
	}
	if sb.Len() == 0 {
		return q, errors.New("a question for the root")
	}
	if i+4 > len(msg) {
		return q, errors.New("DNS question without its type and class")
	}
	q.Name = sb.String()
	q.Type = binary.BigEndian.Uint16(msg[i:])
	q.Class = binary.BigEndian.Uint16(msg[i+2:])
	q.End = i + 4
	return q, nil
}

// Answer builds the response to a query that ParseQuery read: an A record
// with addr when rcode is RcodeOK and the question asks for one, or just
// the code. The question is copied from the query.
func Answer(query []byte, q Question, rcode int, addr netip.Addr, ttl uint32) []byte {
	b := make([]byte, 0, q.End+16)
	b = append(b, query[:q.End]...)
	b[2] = 0x80 | query[2]&0x01 // QR, and RD as asked
	b[3] = 0x80 | byte(rcode&0x0f)
	binary.BigEndian.PutUint16(b[6:], 0)
	binary.BigEndian.PutUint16(b[8:], 0)
	binary.BigEndian.PutUint16(b[10:], 0)
	if rcode != RcodeOK || q.Type != TypeA || q.Class != ClassIN || !addr.Is4() {
		return b
	}
	binary.BigEndian.PutUint16(b[6:], 1)
	b = append(b, 0xc0, headerLen) // the name, as a pointer to the question
	b = binary.BigEndian.AppendUint16(b, TypeA)
	b = binary.BigEndian.AppendUint16(b, ClassIN)
	b = binary.BigEndian.AppendUint32(b, ttl)
	b = binary.BigEndian.AppendUint16(b, 4)
	a := addr.As4()
	return append(b, a[:]...)
}

// Response is what ParseAnswer reads from a DNS response.
type Response struct {
	ID    uint16
	Rcode int
	Addrs []netip.Addr // the A records among the answers
}

// ParseAnswer reads a DNS response: its id, its response code and the
// addresses of its A records.
func ParseAnswer(msg []byte) (Response, error) {
	var r Response
	if len(msg) < headerLen {
		return r, errors.New("DNS message shorter than its header")
	}
	if msg[2]&0x80 == 0 {
		return r, errors.New("a DNS query, not a response")
	}
	r.ID = binary.BigEndian.Uint16(msg[0:])
	r.Rcode = int(msg[3] & 0x0f)
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	an := int(binary.BigEndian.Uint16(msg[6:]))
	i := headerLen
	var err error
	for n := 0; n < qd; n++ {
		if i, err = skipName(msg, i); err != nil {
			return r, err
		}
		i += 4
	}
	for n := 0; n < an; n++ {
		if i, err = skipName(msg, i); err != nil {
			return r, err
		}
		if i+10 > len(msg) {
			return r, errors.New("DNS answer runs past the message")
		}
		typ := binary.BigEndian.Uint16(msg[i:])
		class := binary.BigEndian.Uint16(msg[i+2:])
		l := int(binary.BigEndian.Uint16(msg[i+8:]))
		i += 10
		if i+l > len(msg) {
			return r, errors.New("DNS record data runs past the message")
		}
		if typ == TypeA && class == ClassIN && l == 4 {
			r.Addrs = append(r.Addrs, netip.AddrFrom4([4]byte(msg[i:i+4])))
		}
		i += l
	}
	if i > len(msg) {
		return r, errors.New("DNS message ends inside a question")
	}
	return r, nil
}

// skipName steps over a name, which may end in a compression pointer.
func skipName(msg []byte, i int) (int, error) {
	for {
		if i >= len(msg) {
			return 0, errors.New("DNS name runs past the message")
		}
		l := int(msg[i])
		switch {
		case l == 0:
			return i + 1, nil
		case l&0xc0 == 0xc0:
			if i+2 > len(msg) {
				return 0, errors.New("DNS pointer runs past the message")
			}
			return i + 2, nil
		case l&0xc0 != 0:
			return 0, errors.New("extended DNS label")
		}
		i += 1 + l
	}
}
