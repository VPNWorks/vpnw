// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package seal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/VPNWorks/vpnw/plugins/ledger/chain"
	"github.com/VPNWorks/vpnw/plugins/sdk"
)

func start(t *testing.T, settings map[string]string) (*bytes.Buffer, *[]string) {
	t.Helper()
	var file bytes.Buffer
	var emitted []string
	sdk.TestFile, sdk.TestStderr = &file, &bytes.Buffer{}
	sdk.TestEmit = func(b []byte) { emitted = append(emitted, string(b)) }
	sdk.Register(Plugin())
	cfg, _ := json.Marshal(map[string]any{"plugin": "ledger", "command": "trace", "run": "r-1", "file": "/x/r-1.ledger", "settings": settings})
	if err := sdk.CallInit(cfg); err != nil {
		t.Fatal(err)
	}
	return &file, &emitted
}

func ev(i int) []byte {
	b, _ := json.Marshal(map[string]any{"v": 1, "ts": time.Unix(int64(i), 0).UTC(), "type": "connection.attempt", "run": "r-1", "conn": i})
	return b
}

func check(t *testing.T, file string) chain.Report {
	t.Helper()
	v := &chain.Verifier{}
	lines := strings.Split(strings.TrimSuffix(file, "\n"), "\n")
	for i, l := range lines {
		v.Ledger("f", i+1, []byte(l), false)
	}
	return v.Result()
}

func TestSealsAndChecksOut(t *testing.T) {
	file, emitted := start(t, map[string]string{"every": "3"})
	for i := 1; i <= 7; i++ {
		if err := sdk.CallEvent(ev(i)); err != nil {
			t.Fatal(err)
		}
	}
	lost, _ := json.Marshal(map[string]any{"v": 1, "type": "events.lost", "run": "r-1", "fields": map[string]any{"count": 5}})
	if err := sdk.CallEvent(lost); err != nil {
		t.Fatal(err)
	}
	if err := sdk.CallFinish(); err != nil {
		t.Fatal(err)
	}
	r := check(t, file.String())
	if r.Verdict != chain.Intact || r.Entries != 8 || r.Lost != 5 {
		t.Fatalf("%+v\n%s", r, file)
	}
	// Checkpoints after entries 3 and 6, and at the end; each copied out.
	if n := strings.Count(file.String(), `{"cp":`); n != 3 || len(*emitted) != 3 || !strings.Contains((*emitted)[2], `"end":true`) {
		t.Fatalf("%d checkpoints, emitted %q", n, *emitted)
	}
}

func TestRefuses(t *testing.T) {
	sdk.TestFile = &bytes.Buffer{}
	sdk.Register(Plugin())
	for _, c := range []struct {
		cfg  map[string]any
		want string
	}{
		{map[string]any{"run": "r-1"}, "needs its file"},
		{map[string]any{"run": "r-1", "file": "f", "settings": map[string]string{"every": "0"}}, "from 1 to 1000000"},
		{map[string]any{"run": "r-1", "file": "f", "settings": map[string]string{"often": "1"}}, `unknown setting "often"`},
	} {
		b, _ := json.Marshal(c.cfg)
		if err := sdk.CallInit(b); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v, want %q", c.cfg, err, c.want)
		}
	}
	sdk.TestFile = nil
	b, _ := json.Marshal(map[string]any{"run": "r-1", "file": "f"})
	if err := sdk.CallInit(b); err == nil || !strings.Contains(err.Error(), "cannot write the ledger file") {
		t.Errorf("no file to write: %v", err)
	}
}

func BenchmarkEvent(b *testing.B) {
	sdk.TestFile, sdk.TestEmit = discard{}, nil
	sdk.Register(Plugin())
	cfg, _ := json.Marshal(map[string]any{"run": "r-1", "file": "f"})
	sdk.CallInit(cfg)
	e := ev(1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := sdk.CallEvent(e); err != nil {
			b.Fatal(fmt.Sprint(err))
		}
	}
}

type discard struct{}

func (discard) Write(b []byte) (int, error) { return len(b), nil }
