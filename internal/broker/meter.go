// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/VPNWorks/vpnw/internal/events"
)

// Meter is a byte budget a Guard puts on a connection it lets through.
// Every connection a Guard gives the same Key, for the rest of the run,
// counts against one budget: Up bytes the program may send, Down bytes it
// may receive (0: no limit that way). A connection that would pass a limit
// is carried up to it, then cut; a connection asked for once a limit is
// spent is refused. Reason says what the budget is, for the record.
type Meter struct {
	Key    string
	Up     int64
	Down   int64
	Reason string
}

// MaxMeters is how many budgets one Guard may keep in a run. A Guard that
// asks for more has its next connections refused, so a plugin can't make
// vpnw keep unbounded state.
var MaxMeters = 100_000

const (
	dirUp = iota
	dirDown
)

var dirName = [2]string{"up", "down"}

// meter is the running count of one budget.
type meter struct {
	guard, key string
	used       [2]atomic.Int64
	mu         sync.Mutex // guards limit and reason
	limit      [2]int64
	reason     string
}

// limits returns the meter's limits and reason.
func (m *meter) limits() ([2]int64, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.limit, m.reason
}

// take lets up to n more bytes through in one direction and returns how many.
func (m *meter) take(dir int, n int64) int64 {
	lim, _ := m.limits()
	if lim[dir] <= 0 {
		m.used[dir].Add(n)
		return n
	}
	for {
		cur := m.used[dir].Load()
		room := lim[dir] - cur
		if room <= 0 {
			return 0
		}
		g := min(n, room)
		if m.used[dir].CompareAndSwap(cur, cur+g) {
			return g
		}
	}
}

func (m *meter) give(dir int, n int64) {
	if n > 0 {
		m.used[dir].Add(-n)
	}
}

// spent says which direction of the meter has no bytes left, or -1.
func (m *meter) spent() int {
	lim, _ := m.limits()
	for d := range 2 {
		if lim[d] > 0 && m.used[d].Load() >= lim[d] {
			return d
		}
	}
	return -1
}

// meterFor finds or makes the meter for a Guard's key, with the limits it
// gives now (a Guard may raise or lower a budget as the run goes). It
// returns nil when the Guard already keeps MaxMeters.
func (b *Broker) meterFor(guard string, m *Meter) *meter {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.meters == nil {
		b.meters = map[string]*meter{}
		b.meterCount = map[string]int{}
	}
	k := guard + "\x00" + m.Key
	mt := b.meters[k]
	if mt == nil {
		if b.meterCount[guard] >= MaxMeters {
			return nil
		}
		mt = &meter{guard: guard, key: m.Key}
		b.meters[k] = mt
		b.meterCount[guard]++
	}
	mt.mu.Lock()
	mt.limit = [2]int64{max(m.Up, 0), max(m.Down, 0)}
	mt.reason = m.Reason
	mt.mu.Unlock()
	return mt
}

// metered is one connection's budgets, and its cut, once there is one.
type metered struct {
	b      *Broker
	path   string
	conn   uint64
	meters []*meter
	once   sync.Once
	cut    atomic.Bool
}

// errCut ends a copy whose budget ran out.
var errCut = errors.New("byte budget spent")

// take lets up to n bytes through every meter of the connection and
// returns how many; what one meter took beyond what the others allowed is
// given back.
func (u *metered) take(dir int, n int64) int64 {
	if u == nil {
		return n
	}
	if u.cut.Load() {
		return 0
	}
	got := make([]int64, len(u.meters))
	g := n
	for i, m := range u.meters {
		got[i] = m.take(dir, g)
		g = min(g, got[i])
	}
	for i, m := range u.meters {
		m.give(dir, got[i]-g)
	}
	if g < n {
		u.stop(dir)
	}
	return g
}

// stop records the cut, once: which budget ran out, and why.
func (u *metered) stop(dir int) {
	u.once.Do(func() {
		u.cut.Store(true)
		// The first meter with nothing left that way is the one that cut.
		m := u.meters[0]
		for _, x := range u.meters {
			if lim, _ := x.limits(); lim[dir] > 0 && x.used[dir].Load() >= lim[dir] {
				m = x
				break
			}
		}
		lim, reason := m.limits()
		f := map[string]any{"rule": "plugin:" + m.guard, "key": events.Clean(m.key, 128), "limit": dirName[dir], "bytes": lim[dir]}
		if reason != "" {
			f["reason"] = reason
		}
		u.b.emitPath(u.path, events.ConnectionCut, u.conn, f)
	})
}

// writer counts what passes to w against the connection's budgets in one
// direction; once a budget is spent it writes what's left of it and fails.
func (u *metered) writer(w io.Writer, dir int) io.Writer {
	if u == nil {
		return w
	}
	return &meterWriter{w: w, u: u, dir: dir}
}

type meterWriter struct {
	w   io.Writer
	u   *metered
	dir int
}

func (mw *meterWriter) Write(p []byte) (int, error) {
	g := mw.u.take(mw.dir, int64(len(p)))
	n, err := mw.w.Write(p[:g])
	if err != nil {
		// Unsent bytes don't count.
		for _, m := range mw.u.meters {
			m.give(mw.dir, g-int64(n))
		}
		return n, err
	}
	if g < int64(len(p)) {
		return n, errCut
	}
	return n, nil
}

// spentReason is the refusal of a connection whose budget is spent.
func spentReason(m *meter, dir int) string {
	lim, reason := m.limits()
	var b strings.Builder
	b.WriteString("byte budget spent: ")
	b.WriteString(events.BudgetBytes(lim[dir]))
	if dir == dirUp {
		b.WriteString(" sent")
	} else {
		b.WriteString(" received")
	}
	if reason != "" {
		b.WriteString(" (" + reason + ")")
	}
	return b.String()
}
