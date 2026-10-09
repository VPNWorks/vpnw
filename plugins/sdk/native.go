// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build !wasip1

package sdk

import "io"

// Outside WebAssembly there is no host. These let a plugin's logic be tested
// with go test: Stdout and Stderr go to the writers below, Emit and Log to
// the functions, and Call runs a hook the way vpnw would.

// TestStdout, TestStderr, TestLog and TestEmit receive what a plugin sends
// when it runs under go test. Nil discards.
var (
	TestStdout io.Writer
	TestStderr io.Writer
	TestLog    func(string)
	TestEmit   func([]byte)
)

func write(stream uint32, b []byte) {
	w := TestStdout
	if stream == 2 {
		w = TestStderr
	}
	if w != nil {
		w.Write(b)
	}
}

func logLine(b []byte) {
	if TestLog != nil {
		TestLog(string(b))
	}
}

func emit(b []byte) {
	if TestEmit != nil {
		TestEmit(b)
	}
}

// CallInit, CallEvent, CallDecide and CallFinish run the registered hooks
// with the JSON vpnw would send, for tests.
func CallInit(cfg []byte) error                   { return doInit(cfg) }
func CallEvent(ev []byte) error                   { return doEvent(ev) }
func CallDecide(req []byte) (bool, string, error) { return doDecide(req) }
func CallFinish() error                           { return doFinish() }
