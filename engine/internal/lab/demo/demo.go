// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package demo holds the recordings the browser demo replays. Each is a
// real run in the test network, made by tools/record-lab-demo.sh with the
// vpnw-lab command, and kept here as it came out.
package demo

import (
	"embed"
	"fmt"
	"strings"

	"vpnw.com/vpnw/internal/lab"
)

//go:embed *.jsonl
var files embed.FS

// Recording describes one recording of the demo.
type Recording struct {
	Name  string // the file's name
	Title string // what the page calls it
}

// Recordings are the demo's recordings in the order the page shows them:
// the correct client and the dns-leak client through the same silent
// server, then two more faults.
var Recordings = []Recording{
	{"correct-server-silent.jsonl", "The correct client, the server silent for 5 s"},
	{"dns-leak-server-silent.jsonl", "The dns-leak client, the server silent for 5 s"},
	{"no-kill-switch-app-killed.jsonl", "The no-kill-switch client, killed for 2 s"},
	{"follows-routes-route-push.jsonl", "The follows-routes client, a route pushed for 2 s"},
}

// Text returns a recording's text.
func Text(name string) (string, error) {
	b, err := files.ReadFile(name)
	if err != nil {
		return "", fmt.Errorf("no recording %q in the demo", name)
	}
	return string(b), nil
}

// Read reads one of the demo's recordings.
func Read(name string) (*lab.Recording, error) {
	text, err := Text(name)
	if err != nil {
		return nil, err
	}
	return lab.ReadRecording(strings.NewReader(text), name)
}
