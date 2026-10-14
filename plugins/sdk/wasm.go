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

//go:wasmimport vpnw file_write
func hostFileWrite(p unsafe.Pointer, n uint32) uint32

//go:wasmimport vpnw file_sync
func hostFileSync() uint32

//go:wasmimport vpnw folder_list
func hostFolderList(p unsafe.Pointer, capacity uint32) uint32

//go:wasmimport vpnw folder_read
func hostFolderRead(np unsafe.Pointer, nn uint32, p unsafe.Pointer, capacity uint32) uint32

func folderList(buf []byte) uint32 { return hostFolderList(ptr(buf), uint32(len(buf))) }

func folderRead(name string, buf []byte) uint32 {
	nb := []byte(name)
	if len(nb) == 0 {
		return folderFailed
	}
	return hostFolderRead(ptr(nb), uint32(len(nb)), ptr(buf), uint32(len(buf)))
}

func fileWrite(b []byte) uint32 {
	for len(b) > 0 {
		n := min(len(b), 1<<20)
		if hostFileWrite(ptr(b), uint32(n)) != 0 {
			return 1
		}
		b = b[n:]
	}
	return 0
}

func fileSync() uint32 { return hostFileSync() }

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

// handed keeps the last offer alive until vpnw has read it, after
// vpnw_tunnel returns and before the next call.
var handed []byte

// vpnw_tunnel returns 0 when the plugin has no config (the reason, if any,
// comes through the reason host call first), all ones when it failed (the
// error through the error host call), and otherwise where the offer is in
// memory: its address in the high 32 bits, its length in the low.
//
//go:wasmexport vpnw_tunnel
func exportTunnel(p unsafe.Pointer, n uint32) uint64 {
	offer, none, why, err := doTunnel(take(p, n))
	switch {
	case err != nil:
		fail(err)
		return ^uint64(0)
	case none:
		if why != "" {
			b := []byte(why)
			hostReason(ptr(b), uint32(len(b)))
		}
		return 0
	}
	handed = offer
	return uint64(uintptr(ptr(handed)))<<32 | uint64(len(handed))
}
