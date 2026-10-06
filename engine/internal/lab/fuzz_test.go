// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package lab

import (
	"bytes"
	"reflect"
	"testing"
)

func FuzzParseEvent(f *testing.F) {
	f.Add(`{"t":"2026-10-05T21:00:00.05Z","ev":"sent","kind":"dns","via":"direct","seq":1}`)
	f.Add(`{"t":"2026-10-05T21:00:00Z","ev":"run","lab":"0.1.0","run":"r","app":"a","scenario":"s","seed":3,"interval_ms":50,"exit":"192.0.2.20","home":"203.0.113.2"}`)
	f.Add(`{"t":"2026-10-05T21:00:00Z","ev":"arrival","kind":"udp","via":"proxy","seq":9,"at":"udp","src":"192.0.2.20"}`)
	f.Add(`{ "note":"a\"b\\c\u00e9\n", "state":"x", "ev":"app", "t":"2026-10-05T21:00:00+02:00" }`)
	f.Fuzz(func(t *testing.T, line string) {
		e, err := ParseEvent(line)
		if err != nil {
			return
		}
		again, err := ParseEvent(string(e.AppendJSON(nil)))
		if err != nil {
			t.Fatalf("%q parsed, but its own line does not: %v", line, err)
		}
		e.T = e.T.UTC()
		if !reflect.DeepEqual(again, e) {
			t.Fatalf("round trip of %q:\n%+v\n%+v", line, e, again)
		}
	})
}

func FuzzRecording(f *testing.F) {
	var buf bytes.Buffer
	b := leakyRun()
	b.rec.WriteTo(&buf)
	f.Add(buf.String())
	f.Add(`{"t":"2026-10-05T21:00:00Z","ev":"run","run":"r","app":"a","scenario":"s","interval_ms":1,"exit":"192.0.2.20","home":"203.0.113.2"}
{"t":"2026-10-05T21:00:00Z","ev":"sent","kind":"tcp","via":"direct","seq":0}
{"t":"2026-10-05T21:00:01Z","ev":"arrival","kind":"tcp","via":"direct","seq":0,"at":"tcp","src":"203.0.113.2"}
{"t":"2026-10-05T21:00:00Z","ev":"step","step":"stop"}
`)
	f.Fuzz(func(t *testing.T, text string) {
		rec, err := ParseRecording(text, "fuzz.jsonl")
		if err != nil {
			return
		}
		probes, v := Analyze(rec)
		if v.Sent != len(probes) || v.Sent != v.Tunnel+v.Leaked+v.Lost {
			t.Fatalf("counts don't add up: %+v", v)
		}
		inWindows := 0
		for _, w := range v.Windows {
			inWindows += w.Probes
			if w.End.Before(w.Start) || len(w.Kinds) == 0 {
				t.Fatalf("bad window %+v", w)
			}
		}
		if inWindows != v.Leaked || (v.Leaked > 0) != (v.Status == Leak) {
			t.Fatalf("windows hold %d probes, %d leaked, status %s", inWindows, v.Leaked, v.Status)
		}
		sum := 0
		for _, c := range v.Kinds {
			sum += c.Sent
		}
		if sum != v.Sent {
			t.Fatalf("kinds hold %d probes of %d", sum, v.Sent)
		}
		v.Text()
		var out bytes.Buffer
		if _, err := rec.WriteTo(&out); err != nil {
			t.Fatal(err)
		}
		again, err := ReadRecording(&out, "again.jsonl")
		if err != nil {
			t.Fatalf("a recording that was read does not read again: %v", err)
		}
		if w := Decide(again); w.Summary() != v.Summary() || w.Leaked != v.Leaked {
			t.Fatalf("the verdict changed after writing the recording out: %s, %s", v.Summary(), w.Summary())
		}
	})
}
