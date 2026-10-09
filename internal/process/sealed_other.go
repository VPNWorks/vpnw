// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package process

import (
	"errors"
	"net"
	"os"
)

// SandboxArg is argv[1] of the helper that runs inside the namespace.
const SandboxArg = "__vpnw_sandbox__"

var errNoSeal = errors.New("sealed runs need Linux; on this system vpnw runs programs with the env backend (proxy settings only)")

// Sealed is not available on this platform.
type Sealed struct{ Interfaces []string }

func (s *Sealed) Name() string                  { return "sealed" }
func (s *Sealed) Enforced() bool                { return true }
func (s *Sealed) Listen() (net.Listener, error) { return nil, errNoSeal }
func (s *Sealed) Start(Spec) (int, error) {
	return 0, &StartError{Code: ExitNoEnforcement, Msg: errNoSeal.Error()}
}
func (s *Sealed) Wait() (Result, error)  { return Result{}, errNoSeal }
func (s *Sealed) Signal(os.Signal) error { return nil }
func (s *Sealed) Close() error           { return nil }

// Check always fails outside Linux.
func Check() error { return errNoSeal }

// SandboxMain is never used outside Linux.
func SandboxMain([]string) int { return ExitNoEnforcement }
