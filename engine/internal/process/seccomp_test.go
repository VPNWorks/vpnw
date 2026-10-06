// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package process

import (
	"encoding/binary"
	"testing"
)

// run executes the filter the way the kernel does, for the few instructions
// it uses, on one system call.
func run(t *testing.T, f []sockFilter, arch uint32, nr int32, arg0 uint64) uint32 {
	t.Helper()
	data := make([]byte, 64)
	binary.LittleEndian.PutUint32(data[offNr:], uint32(nr))
	binary.LittleEndian.PutUint32(data[offArch:], arch)
	binary.LittleEndian.PutUint64(data[offArg0:], arg0)
	var a uint32
	for pc := 0; pc < len(f); pc++ {
		in := f[pc]
		switch in.code {
		case bpfLD | bpfW | bpfABS:
			a = binary.LittleEndian.Uint32(data[in.k:])
		case bpfJMP | bpfJEQ | bpfK:
			if a == in.k {
				pc += int(in.jt)
			} else {
				pc += int(in.jf)
			}
		case bpfJMP | bpfJGE | bpfK:
			if a >= in.k {
				pc += int(in.jt)
			} else {
				pc += int(in.jf)
			}
		case bpfRET | bpfK:
			return in.k
		default:
			t.Fatalf("unexpected instruction %#x at %d", in.code, pc)
		}
	}
	t.Fatal("the filter fell off its end")
	return 0
}

func TestUnixSocketFilter(t *testing.T) {
	f, err := unixSocketFilter()
	if err != nil {
		t.Fatal(err)
	}
	deny := uint32(secRetErrno | 1) // EPERM
	cases := []struct {
		name string
		arch uint32
		nr   int32
		arg0 uint64
		want uint32
	}{
		{"socket(AF_UNIX)", auditArch, sysSocket, afUnix, deny},
		{"socket(AF_UNIX) with high bits set", auditArch, sysSocket, 1<<32 | afUnix, deny},
		{"socket(AF_INET)", auditArch, sysSocket, 2, secRetAllow},
		{"socket(AF_INET6)", auditArch, sysSocket, 10, secRetAllow},
		{"io_uring_setup", auditArch, sysIoUringSetup, 0, deny},
		{"io_uring_enter", auditArch, sysIoUringEnter, 0, deny},
		{"io_uring_register", auditArch, sysIoUringRegister, 0, deny},
		{"another call", auditArch, 0, 0, secRetAllow},
		{"a 32-bit call (another architecture)", 0x40000003, 102, 0, deny},
	}
	if x32Bit == 0x40000000 {
		cases = append(cases, struct {
			name string
			arch uint32
			nr   int32
			arg0 uint64
			want uint32
		}{"x32 socket", auditArch, 0x40000000 | sysSocket, afUnix, deny})
	}
	for _, c := range cases {
		if got := run(t, f, c.arch, c.nr, c.arg0); got != c.want {
			t.Errorf("%s: got %#x, want %#x", c.name, got, c.want)
		}
	}
}
