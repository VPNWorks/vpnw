// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)

// testKey is a fixed key: the seed is the byte b repeated.
func testKey(t testing.TB, b byte) *PrivateKey {
	t.Helper()
	k, err := NewKey(bytes.NewReader(bytes.Repeat([]byte{b}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// clock starts at t0 and moves one second each time it is read.
func clock() func() time.Time {
	now := t0
	return func() time.Time { now = now.Add(time.Second); return now }
}

// agentLines makes n records in the style of the Agent's events.
func agentLines(n int) []string {
	var out []string
	for i := 1; i <= n; i++ {
		out = append(out, fmt.Sprintf(`{"v":1,"ts":"2026-10-05T10:00:%02d.%06dZ","type":"connection.open","run":"r-test","pid":4242,"path":"direct","conn":%d,"fields":{"host":"h%d.example","ip":"192.0.2.%d","ms":%d}}`,
			i%60, i, i, i, i%250, i%7))
	}
	return out
}

func text(lines []string) []byte { return []byte(strings.Join(lines, "\n") + "\n") }

// seal seals records into a new ledger with a checkpoint every every records.
func seal(t testing.TB, key *PrivateKey, records []byte, every int) []byte {
	t.Helper()
	var led bytes.Buffer
	s, err := NewSealer(&led, key, "test.jsonl", Options{Every: every, Now: clock()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SealAll(bytes.NewReader(records), "test.jsonl", 0); err != nil {
		t.Fatal(err)
	}
	return led.Bytes()
}

// check verifies records against a ledger.
func check(t testing.TB, records, ledger []byte, pub *PublicKey, opt VerifyOptions) *Report {
	t.Helper()
	recs, _, err := HashRecords(bytes.NewReader(records), 0)
	if err != nil {
		t.Fatal(err)
	}
	led, err := ReadLedger(bytes.NewReader(ledger), "test.jsonl.ledger")
	if err != nil {
		t.Fatal(err)
	}
	return Verify(recs, "test.jsonl", led, pub, opt)
}

func lines(b []byte) []string { return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") }
