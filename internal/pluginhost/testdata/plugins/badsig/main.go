//go:build wasip1

// badsig exports vpnw_on_decide with no result, so a host that trusted the
// export's name alone would read a result that is not there.
package main

import "unsafe"

//go:wasmexport vpnw_abi
func abi() uint32 { return 1 }

var keep = map[uintptr][]byte{}

//go:wasmexport vpnw_alloc
func alloc(n uint32) unsafe.Pointer {
	b := make([]byte, n+1)
	p := unsafe.Pointer(unsafe.SliceData(b))
	keep[uintptr(p)] = b
	return p
}

//go:wasmexport vpnw_init
func initHook(p unsafe.Pointer, n uint32) uint32 { return 0 }

//go:wasmexport vpnw_on_decide
func decide(p unsafe.Pointer, n uint32) {}

func main() {}
