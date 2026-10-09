// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build wasip1

package sdk

import "unsafe"

// Host calls, all in the "vpnw" module. vpnw refuses to load a plugin that
// imports one its manifest does not permit.

//go:wasmimport vpnw log
func hostLog(p unsafe.Pointer, n uint32)

//go:wasmimport vpnw error
func hostError(p unsafe.Pointer, n uint32)

//go:wasmimport vpnw reason
func hostReason(p unsafe.Pointer, n uint32)

//go:wasmimport vpnw write
func hostWrite(stream uint32, p unsafe.Pointer, n uint32)

//go:wasmimport vpnw emit
func hostEmit(p unsafe.Pointer, n uint32)

func ptr(b []byte) unsafe.Pointer { return unsafe.Pointer(unsafe.SliceData(b)) }

func write(stream uint32, b []byte) {
	if len(b) > 0 {
		hostWrite(stream, ptr(b), uint32(len(b)))
	}
}

func logLine(b []byte) {
	if len(b) > 0 {
		hostLog(ptr(b), uint32(len(b)))
	}
}

func emit(b []byte) { hostEmit(ptr(b), uint32(len(b))) }

func fail(err error) uint32 {
	b := []byte(err.Error())
	if len(b) == 0 {
		b = []byte("error")
	}
	hostError(ptr(b), uint32(len(b)))
	return 1
}

// Buffers handed to the host by vpnw_alloc, kept alive until the hook that
// receives them takes them back.
var buffers = map[uintptr][]byte{}

func take(p unsafe.Pointer, n uint32) []byte {
	b, ok := buffers[uintptr(p)]
	if !ok {
		return nil
	}
	delete(buffers, uintptr(p))
	if int(n) < len(b) {
		b = b[:n]
	}
	return b
}

//go:wasmexport vpnw_abi
func exportABI() uint32 { return ABI }

//go:wasmexport vpnw_alloc
func exportAlloc(n uint32) unsafe.Pointer {
	if n == 0 {
		n = 1
	}
	b := make([]byte, n)
	p := ptr(b)
	buffers[uintptr(p)] = b
	return p
}

//go:wasmexport vpnw_init
func exportInit(p unsafe.Pointer, n uint32) uint32 {
	if err := doInit(take(p, n)); err != nil {
		return fail(err)
	}
	return 0
}

//go:wasmexport vpnw_on_event
func exportEvent(p unsafe.Pointer, n uint32) uint32 {
	if err := doEvent(take(p, n)); err != nil {
		return fail(err)
	}
	return 0
}

// vpnw_on_decide returns 0 to let the connection through and 1 to refuse it;
// the reason, if any, comes through the reason host call first.
//
//go:wasmexport vpnw_on_decide
func exportDecide(p unsafe.Pointer, n uint32) uint32 {
	deny, reason, err := doDecide(take(p, n))
	if err != nil {
		return fail(err)
	}
	if !deny {
		return 0
	}
	if reason != "" {
		b := []byte(reason)
		hostReason(ptr(b), uint32(len(b)))
	}
	return 1
}

//go:wasmexport vpnw_finish
func exportFinish() uint32 {
	if err := doFinish(); err != nil {
		return fail(err)
	}
	return 0
}
