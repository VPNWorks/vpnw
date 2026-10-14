// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package path

// MoveNow asks the source for another config at once, as when the config in
// use is due (reason "due") or its tunnel stopped answering ("failed").
func (t *Tunnels) MoveNow(reason string) {
	t.mu.Lock()
	cur := t.cur
	t.mu.Unlock()
	why := ""
	if reason == "failed" {
		why = "the test said so"
	}
	t.move(reason, cur, why)
}

// CloseDrained closes the rotated-out tunnels with no connections left.
func (t *Tunnels) CloseDrained() { t.closeDrained() }

// Open counts the tunnels up: the one in use and those rotated out.
func (t *Tunnels) Open() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := len(t.old)
	if t.cur != nil {
		n++
	}
	return n
}

// UnicastData, WGMessage and ToPlugin are unicastData, wgMessage and
// toPlugin, for their tests.
var (
	UnicastData = unicastData
	WGMessage   = wgMessage
	ToPlugin    = toPlugin
)
