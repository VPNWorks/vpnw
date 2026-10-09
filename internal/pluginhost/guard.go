// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package pluginhost

import (
	"context"
	"sync"

	"github.com/VPNWorks/vpnw/internal/broker"
)

// GuardCheck puts a Guard plugin in front of the broker. It implements
// broker.Guard.
type GuardCheck struct {
	in     *Instance
	onFail func(name string, err error)
	once   sync.Once
}

// NewGuard wraps a loaded Guard plugin. onFail, if not nil, is called once,
// the first time the plugin fails.
func NewGuard(in *Instance, onFail func(name string, err error)) *GuardCheck {
	return &GuardCheck{in: in, onFail: onFail}
}

// Name is the plugin's name.
func (g *GuardCheck) Name() string { return g.in.Name() }

// Check asks the plugin. After a failure every connection is refused
// without asking.
func (g *GuardCheck) Check(ctx context.Context, r broker.GuardRequest) (bool, string, error) {
	deny, reason, err := g.in.Decide(ctx, r)
	if err != nil {
		g.once.Do(func() {
			if g.onFail != nil {
				g.onFail(g.in.Name(), err)
			}
		})
	}
	return deny, reason, err
}

// Close stops the plugin and returns its failure, if any.
func (g *GuardCheck) Close() error {
	err := g.in.Err()
	g.in.Close()
	return err
}
