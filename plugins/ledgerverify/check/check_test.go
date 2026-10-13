// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package check

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/VPNWorks/vpnw/plugins/ledger/chain"
	"github.com/VPNWorks/vpnw/plugins/sdk"
)

func line(file string, n int, text string, partial bool) []byte {
	b, _ := json.Marshal(map[string]any{"file": file, "line": n, "text": text, "partial": partial})
	return b
}

func run(t *testing.T, settings map[string]string, lines ...[]byte) (string, error) {
	t.Helper()
	var out bytes.Buffer
	sdk.TestStdout = &out
	sdk.Register(Plugin())
	cfg, _ := json.Marshal(map[string]any{"command": "verify", "settings": settings})
	if err := sdk.CallInit(cfg); err != nil {
		return "", err
	}
	for _, l := range lines {
		if err := sdk.CallEvent(l); err != nil {
			return out.String(), err
		}
	}
	err := sdk.CallFinish()
	return out.String(), err
}

func ledger(t *testing.T) []string {
	w, hd, _ := chain.NewWriter("r-1")
	out := []string{strings.TrimSpace(string(hd))}
	b, _ := w.Event([]byte(`{"v":1,"type":"run.start","run":"r-1"}`))
	out = append(out, strings.TrimSpace(string(b)))
	c, _ := w.Checkpoint()
	out = append(out, strings.TrimSpace(string(c)), strings.TrimSpace(string(w.End())))
	return out
}

func TestIntactAndChanged(t *testing.T) {
	l := ledger(t)
	var in [][]byte
	for i, x := range l {
		in = append(in, line("a.ledger", i+1, x, false))
	}
	out, err := run(t, nil, in...)
	if err != nil || !strings.HasPrefix(out, "intact: a.ledger holds 1 entries") {
		t.Fatalf("%v\n%s", err, out)
	}
	in[1] = line("a.ledger", 2, strings.Replace(l[1], "run.start", "run.stop", 1), false)
	out, err = run(t, nil, in...)
	if err == nil || !strings.Contains(err.Error(), "a.ledger:2: the event doesn't match its hash") || !strings.HasPrefix(out, "CHANGED: ") {
		t.Fatalf("%v\n%s", err, out)
	}
}

func TestOrderAndSettings(t *testing.T) {
	if _, err := run(t, nil, line("t.jsonl", 1, `{"v":1}`, false)); err == nil || !strings.Contains(err.Error(), "give the ledger first") {
		t.Errorf("trace first: %v", err)
	}
	l := ledger(t)
	if _, err := run(t, nil, line("a", 1, l[0], false), line("b", 1, l[0], false)); err == nil || !strings.Contains(err.Error(), "second ledger") {
		t.Errorf("two ledgers: %v", err)
	}
	if _, err := run(t, map[string]string{"head": "xyz"}); err == nil || !strings.Contains(err.Error(), "64 lower-case hex") {
		t.Errorf("bad head: %v", err)
	}
	if _, err := run(t, map[string]string{"nope": "1"}); err == nil || !strings.Contains(err.Error(), "unknown setting") {
		t.Errorf("unknown setting: %v", err)
	}
	if _, err := run(t, nil); err == nil || !strings.Contains(err.Error(), "no ledger") {
		t.Errorf("nothing given: %v", err)
	}
}
