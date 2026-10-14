// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package netstack

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

// Closing the device while the stack sends packets through it drops them.
// wireguard-go's original closed the channel they are sent on, and a
// sender then panicked, taking the process down.
func TestCloseWhileSending(t *testing.T) {
	for range 20 {
		dev, tnet, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, nil, 1420)
		if err != nil {
			t.Fatal(err)
		}
		// Something takes packets now and then, as WireGuard does.
		go func() {
			buf, sizes := [][]byte{make([]byte, 1500)}, []int{0}
			for {
				if _, err := dev.Read(buf, sizes, 0); err != nil {
					return
				}
				time.Sleep(time.Millisecond)
			}
		}()
		stop := make(chan struct{})
		var wg sync.WaitGroup
		for range 8 {
			u, err := tnet.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("10.0.0.1:9"))
			if err != nil {
				t.Fatal(err)
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				b := make([]byte, 1200)
				for {
					select {
					case <-stop:
						return
					default:
					}
					if _, err := u.Write(b); err != nil {
						return
					}
				}
			}()
		}
		time.Sleep(10 * time.Millisecond)
		dev.Close()
		close(stop)
		wg.Wait()
		if _, err := dev.Read([][]byte{make([]byte, 1500)}, []int{0}, 0); err == nil {
			t.Fatal("read from a closed device")
		}
		dev.Close()
	}
}
