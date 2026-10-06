// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package wire

import (
	"errors"
	"fmt"
)

// The stand-in tunnel carries IP packets in UDP datagrams, with a four-byte
// header and nothing else: no keys, no encryption, no authentication. It is
// a test fixture with a VPN's timing, not a VPN.
const (
	Hello   = 1 // client to server: start a session; the payload is a nonce
	Welcome = 2 // server to client: the nonce back
	Data    = 3 // either way: one IP packet
	Ping    = 4 // client to server: still there? The payload is a counter
	Pong    = 5 // server to client: the counter back
)

// FrameHeader is the length of a frame's header: "VL", the version and the
// type.
const FrameHeader = 4

const frameVersion = 1

// AppendFrame appends a frame of type typ carrying payload.
func AppendFrame(b []byte, typ byte, payload []byte) []byte {
	b = append(b, 'V', 'L', frameVersion, typ)
	return append(b, payload...)
}

// ParseFrame reads a frame. The payload shares memory with b.
func ParseFrame(b []byte) (typ byte, payload []byte, err error) {
	if len(b) < FrameHeader || b[0] != 'V' || b[1] != 'L' {
		return 0, nil, errors.New("not a tunnel frame")
	}
	if b[2] != frameVersion {
		return 0, nil, fmt.Errorf("tunnel frame version %d", b[2])
	}
	switch b[3] {
	case Hello, Welcome, Ping, Pong:
		if len(b) != FrameHeader+8 {
			return 0, nil, fmt.Errorf("frame type %d needs an 8-byte payload", b[3])
		}
	case Data:
		if len(b) < FrameHeader+20 || b[FrameHeader]>>4 != 4 {
			return 0, nil, errors.New("a data frame must carry an IPv4 packet")
		}
	default:
		return 0, nil, fmt.Errorf("unknown tunnel frame type %d", b[3])
	}
	return b[3], b[FrameHeader:], nil
}
