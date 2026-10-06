// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package world

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"vpnw.com/vpnw/internal/testnet"
)

// forwarder sends DNS queries to the zone's name server from one address in
// a namespace, all over one socket made when the world is built, and hands
// each answer back by its query id. A socket per query would need a thread
// entering the namespace per query, which slows a busy machine.
type forwarder struct {
	conn    *net.UDPConn
	mu      sync.Mutex
	next    uint16
	pending map[uint16]pending
}

type pending struct {
	id    uint16 // the query's own id, put back in the answer
	reply func([]byte)
	at    time.Time
}

// forwardTimeout is how long an unanswered query is remembered.
const forwardTimeout = 2 * time.Second

func (w *World) newForwarder(ns *testnet.NS, from netip.Addr) (*forwarder, error) {
	f := &forwarder{pending: map[uint16]pending{}}
	err := ns.Do(func() (err error) {
		f.conn, err = net.DialUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(from, 0)), net.UDPAddrFromAddrPort(netip.AddrPortFrom(ZoneDNS, DNSPort)))
		return err
	})
	if err != nil {
		return nil, err
	}
	w.onClose(func() { f.conn.Close() })
	go f.read()
	return f, nil
}

// ask sends a query on; reply gets the answer, if one comes.
func (f *forwarder) ask(msg []byte, reply func([]byte)) error {
	if len(msg) < 12 {
		return errors.New("DNS message shorter than its header")
	}
	q := append([]byte(nil), msg...)
	now := time.Now()
	f.mu.Lock()
	for id, p := range f.pending {
		if now.Sub(p.at) > forwardTimeout {
			delete(f.pending, id)
		}
	}
	id := f.next
	f.next++
	f.pending[id] = pending{id: binary.BigEndian.Uint16(q), reply: reply, at: now}
	f.mu.Unlock()
	binary.BigEndian.PutUint16(q, id)
	_, err := f.conn.Write(q)
	return err
}

func (f *forwarder) read() {
	buf := make([]byte, 2048)
	for {
		n, err := f.conn.Read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if n < 12 {
			continue
		}
		ans := append([]byte(nil), buf[:n]...)
		id := binary.BigEndian.Uint16(ans)
		f.mu.Lock()
		p, ok := f.pending[id]
		delete(f.pending, id)
		f.mu.Unlock()
		if ok {
			binary.BigEndian.PutUint16(ans, p.id)
			p.reply(ans)
		}
	}
}

// query sends one query and waits for its answer.
func (f *forwarder) query(msg []byte) ([]byte, error) {
	got := make(chan []byte, 1)
	if err := f.ask(msg, func(b []byte) { got <- b }); err != nil {
		return nil, err
	}
	select {
	case b := <-got:
		return b, nil
	case <-time.After(forwardTimeout):
		return nil, errors.New("no answer from the zone's name server")
	}
}

// workers are goroutines that live inside a namespace, each on a thread of
// its own, and run what the world asks there: sockets made in a job belong
// to the namespace.
type workers struct{ jobs chan func() }

func (w *World) newWorkers(ns *testnet.NS, n int) (*workers, error) {
	ws := &workers{jobs: make(chan func())}
	for i := 0; i < n; i++ {
		ready := make(chan struct{})
		go ns.Do(func() error {
			close(ready)
			for job := range ws.jobs {
				job()
			}
			return nil
		})
		<-ready
	}
	w.onClose(func() { close(ws.jobs) })
	return ws, nil
}

// do runs fn inside the namespace and waits for it.
func (ws *workers) do(fn func()) {
	done := make(chan struct{})
	ws.jobs <- func() { fn(); close(done) }
	<-done
}
