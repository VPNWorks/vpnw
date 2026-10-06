// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package process

import (
	"errors"
	"syscall"
	"unsafe"
)

// The sandbox's second wall. The network namespace takes away every route
// out, but Unix sockets live in the file system, not in a network namespace:
// a program could still connect to one, such as the Docker socket, and ask
// the service behind it to reach the network for it. So the helper installs
// a seccomp filter before it starts the program:
//
//   - socket(AF_UNIX, ...) fails with EPERM (socketpair still works, so
//     programs can talk to their own children);
//   - io_uring_setup, io_uring_enter and io_uring_register fail with EPERM,
//     because io_uring can create sockets without calling socket();
//   - any system call made with another architecture's numbering (32-bit
//     calls on a 64-bit kernel, x32) fails with EPERM, so the filter cannot
//     be walked around through a second system call table.
//
// Like every seccomp filter it is inherited by the program's children and
// cannot be removed. It does not affect Unix socket descriptors the program
// inherited already open; vpnw passes none.

const (
	seccompModeFilter = 2
	prSetNoNewPrivs   = 38
	prSetSeccomp      = 22

	secRetAllow = 0x7fff0000
	secRetErrno = 0x00050000

	bpfLD  = 0x00
	bpfW   = 0x00
	bpfABS = 0x20
	bpfJMP = 0x05
	bpfJEQ = 0x10
	bpfJGE = 0x30
	bpfK   = 0x00
	bpfRET = 0x06

	afUnix = 1

	// Offsets in struct seccomp_data.
	offNr   = 0
	offArch = 4
	offArg0 = 16 // low 32 bits on little-endian machines
)

type sockFilter struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

type sockFprog struct {
	len    uint16
	filter *sockFilter
}

func stmt(code uint16, k uint32) sockFilter { return sockFilter{code: code, k: k} }
func jump(code uint16, k uint32, jt, jf uint8) sockFilter {
	return sockFilter{code: code, jt: jt, jf: jf, k: k}
}

// unixSocketFilter builds the filter for this machine's architecture.
func unixSocketFilter() ([]sockFilter, error) {
	if !seccompSupported {
		return nil, errors.New("the Unix-socket filter is not built for this processor; use --allow-unix-sockets to run without it")
	}
	deny := uint32(secRetErrno | uint32(syscall.EPERM))
	// Jump offsets count instructions after the current one.
	f := []sockFilter{
		/* 0 */ stmt(bpfLD|bpfW|bpfABS, offArch),
		/* 1 */ jump(bpfJMP|bpfJEQ|bpfK, auditArch, 1, 0),
		/* 2 */ stmt(bpfRET|bpfK, deny), // another architecture's numbering
		/* 3 */ stmt(bpfLD|bpfW|bpfABS, offNr),
		/* 4 */ jump(bpfJMP|bpfJGE|bpfK, x32Bit, 0, 1),
		/* 5 */ stmt(bpfRET|bpfK, deny), // x32 system calls (amd64); never true elsewhere
		/* 6 */ jump(bpfJMP|bpfJEQ|bpfK, sysIoUringSetup, 3, 0),
		/* 7 */ jump(bpfJMP|bpfJEQ|bpfK, sysIoUringEnter, 2, 0),
		/* 8 */ jump(bpfJMP|bpfJEQ|bpfK, sysIoUringRegister, 1, 0),
		/* 9 */ jump(bpfJMP|bpfJEQ|bpfK, sysSocket, 1, 4),
		/* 10 */ stmt(bpfRET|bpfK, deny), // io_uring
		/* 11 */ stmt(bpfLD|bpfW|bpfABS, offArg0), // socket(): the domain
		/* 12 */ jump(bpfJMP|bpfJEQ|bpfK, afUnix, 0, 1),
		/* 13 */ stmt(bpfRET|bpfK, deny),
		/* 14 */ stmt(bpfRET|bpfK, secRetAllow),
	}
	return f, nil
}

// denyUnixSockets installs the filter on the calling thread. The caller must
// have locked the goroutine to its thread and must start the workload from
// it, since seccomp filters, like capabilities, belong to a thread.
func denyUnixSockets() error {
	f, err := unixSocketFilter()
	if err != nil {
		return err
	}
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0); e != 0 {
		return errors.New("cannot set no_new_privs: " + e.Error())
	}
	prog := sockFprog{len: uint16(len(f)), filter: &f[0]}
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetSeccomp, seccompModeFilter, uintptr(unsafe.Pointer(&prog))); e != 0 {
		return errors.New("cannot install the seccomp filter: " + e.Error() + "; use --allow-unix-sockets to run without it")
	}
	return nil
}
