// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build !wasip1

package sdk

import (
	"encoding/json"
	"io"
	"io/fs"
	"strings"
)

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
	// TestFile receives FileWrite; nil makes FileWrite and FileSync fail,
	// as when vpnw has no file open for the plugin.
	TestFile io.Writer
	// TestFolder is what FolderList and FolderRead read: its regular files
	// at the top. Nil makes them fail, as when vpnw has no folder open for
	// the plugin.
	TestFolder fs.FS
)

func folderList(buf []byte) uint32 {
	if TestFolder == nil {
		return folderFailed
	}
	ents, err := fs.ReadDir(TestFolder, ".")
	if err != nil {
		return folderFailed
	}
	list := []FolderEntry{}
	for _, e := range ents {
		if info, err := e.Info(); err == nil && info.Mode().IsRegular() {
			list = append(list, FolderEntry{Name: e.Name(), Size: info.Size()})
		}
	}
	b, _ := json.Marshal(list)
	return give(b, buf)
}

func folderRead(name string, buf []byte) uint32 {
	if TestFolder == nil || !fs.ValidPath(name) || name == "." || strings.Contains(name, "/") {
		return folderFailed
	}
	b, err := fs.ReadFile(TestFolder, name)
	if err != nil {
		return folderFailed
	}
	return give(b, buf)
}

func give(b, buf []byte) uint32 {
	if len(b) <= len(buf) {
		copy(buf, b)
	}
	return uint32(len(b))
}

func fileWrite(b []byte) uint32 {
	if TestFile == nil {
		return 1
	}
	if _, err := TestFile.Write(b); err != nil {
		return 1
	}
	return 0
}

func fileSync() uint32 {
	if TestFile == nil {
		return 1
	}
	return 0
}

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

// CallInit, CallEvent, CallDecide, CallTunnel and CallFinish run the
// registered hooks with the JSON vpnw would send, for tests. CallTunnel
// returns the offer as vpnw reads it, or none and why.
func CallInit(cfg []byte) error                   { return doInit(cfg) }
func CallEvent(ev []byte) error                   { return doEvent(ev) }
func CallDecide(req []byte) (bool, string, error) { return doDecide(req) }
func CallFinish() error                           { return doFinish() }
func CallTunnel(req []byte) (offer []byte, none bool, why string, err error) {
	return doTunnel(req)
}
