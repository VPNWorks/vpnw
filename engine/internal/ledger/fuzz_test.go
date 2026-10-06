// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// fuzzLog is a sealed log the fuzz targets start from, with its lines.
func fuzzLog(t testing.TB) (k *PrivateKey, records, ledger []byte, recLines []string, led *Ledger) {
	k = testKey(t, 1)
	recLines = agentLines(20)
	records = text(recLines)
	ledger = seal(t, k, records, 4) // checkpoints after 4, 8, 12, 16 and 20 records
	var err error
	if led, err = ReadLedger(bytes.NewReader(ledger), "l"); err != nil {
		t.Fatal(err)
	}
	return
}

func FuzzParseKey(f *testing.F) {
	k := testKey(f, 1)
	f.Add(k.Text())
	f.Add(k.Public().Text())
	f.Add("version = 1\nid = \"k-00000000\"\npublic = \"ed25519 AAAA\"\n")
	f.Fuzz(func(t *testing.T, src string) {
		if pub, err := ParsePublicKey(src, "k.pub"); err == nil {
			again, err := ParsePublicKey(pub.Text(), "k.pub")
			if len(pub.Key) != ed25519.PublicKeySize || pub.ID != KeyID(pub.Key) || err != nil || !again.Key.Equal(pub.Key) {
				t.Fatalf("%q: a public key that doesn't hold: %v", src, err)
			}
		}
		if priv, err := ParsePrivateKey(src, "k.key"); err == nil {
			msg := []byte("checkpoint")
			if !ed25519.Verify(priv.Public().Key, msg, ed25519.Sign(priv.Key, msg)) || priv.ID != KeyID(priv.Public().Key) {
				t.Fatalf("%q: a private key that doesn't sign", src)
			}
		}
	})
}

// A checkpoint is accepted only in the one form seal writes.
func FuzzParseCheckpoint(f *testing.F) {
	k, _, _, _, led := fuzzLog(f)
	for _, c := range led.Checkpoints {
		f.Add(c.AppendJSON(nil))
	}
	f.Add([]byte(`{"cp":1}`))
	f.Fuzz(func(t *testing.T, line []byte) {
		c, err := ParseCheckpoint(line)
		if err != nil {
			return
		}
		if !bytes.Equal(c.AppendJSON(nil), line) {
			t.Fatalf("accepted in another form: %s", line)
		}
		c.Check(k.Public())
	})
}

// A ledger is read only as seal writes it: what was read, written again, is
// the file itself.
func FuzzReadLedger(f *testing.F) {
	_, _, ledger, _, _ := fuzzLog(f)
	f.Add(ledger)
	f.Add(ledger[:len(ledger)/2])
	f.Add([]byte("{\"vpnw-ledger\":1,\"log\":\"a\"}\n{\"n\":1,\"leaf\":\"00\"}\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		led, err := ReadLedger(bytes.NewReader(b), "l")
		if err != nil || led.Problem != nil {
			return
		}
		out := append(appendHeader(nil, led.Log), '\n')
		cp := 0
		for n := 0; n <= len(led.Leaves); n++ {
			if n > 0 {
				out = append(appendEntry(out, n, led.Leaves[n-1]), '\n')
			}
			for cp < len(led.Checkpoints) && led.Checkpoints[cp].Size == n {
				out = append(led.Checkpoints[cp].AppendJSON(out), '\n')
				cp++
			}
		}
		if !bytes.Equal(out, b) || cp != len(led.Checkpoints) {
			t.Fatalf("read as\n%s\nfrom\n%s", out, b)
		}
	})
}

// Whatever seal accepts verifies, and every line of it has a proof.
func FuzzSealVerify(f *testing.F) {
	k := testKey(f, 1)
	f.Add(text(agentLines(5)), uint8(2))
	f.Add([]byte("{}\n[]\n\"x\"\n1\n{\"a\":\"é\"}"), uint8(0))
	f.Add([]byte("{}\r\n{}\n"), uint8(7))
	f.Fuzz(func(t *testing.T, records []byte, every uint8) {
		var buf bytes.Buffer
		s, _ := NewSealer(&buf, k, "f.jsonl", Options{Every: int(every)%9 + 1, Now: clock()})
		n, err := s.SealAll(bytes.NewReader(records), "f.jsonl", 0)
		if err != nil {
			return
		}
		recs, _, _ := HashRecords(bytes.NewReader(records), 0)
		led, err := ReadLedger(bytes.NewReader(buf.Bytes()), "f.jsonl.ledger")
		if err != nil || n != len(recs) {
			t.Fatalf("sealed %d of %d lines: %v", n, len(recs), err)
		}
		if p := Verify(recs, "f.jsonl", led, k.Public(), VerifyOptions{}).Problem; p != nil {
			t.Fatalf("sealed but doesn't verify: %v", p)
		}
		lines := bytes.Split(records, []byte("\n"))
		for i := range recs {
			p, err := Prove(led, "f.jsonl", i+1, lines[i])
			if err != nil {
				t.Fatalf("line %d: %v", i+1, err)
			}
			if q, err := ParseProof(p.JSON()); err != nil || q.Check(k.Public()) != nil {
				t.Fatalf("line %d: the proof doesn't hold: %v", i+1, err)
			}
		}
	})
}

// Without the key, no change to a sealed log verifies, except cutting both
// files back to a checkpoint; and with the last checkpoint as a witness, not
// even that.
func FuzzVerify(f *testing.F) {
	k, records, ledger, recLines, orig := fuzzLog(f)
	f.Add(records, ledger)
	f.Add(records[:len(records)/2], ledger)
	f.Add(bytes.Replace(records, []byte("h12."), []byte("h21."), 1), ledger)
	f.Add(records, bytes.Replace(ledger, []byte(`"cp":3`), []byte(`"cp":2`), 1))
	sizes := map[int]bool{0: true}
	for _, c := range orig.Checkpoints {
		sizes[c.Size] = true
	}
	last := orig.Checkpoints[len(orig.Checkpoints)-1]
	f.Fuzz(func(t *testing.T, records, ledger []byte) {
		recs, _, _ := HashRecords(bytes.NewReader(records), 0)
		led, err := ReadLedger(bytes.NewReader(ledger), "l")
		if err != nil {
			return
		}
		if Verify(recs, "r", led, k.Public(), VerifyOptions{}).Problem == nil {
			if !sizes[len(recs)] {
				t.Fatalf("verified %d records, which no checkpoint covers", len(recs))
			}
			for i, h := range recs {
				if h != LeafHash([]byte(recLines[i])) {
					t.Fatalf("record %d verified, but it isn't the one sealed", i+1)
				}
			}
		}
		w := []Witness{{CP: last, File: "w", Line: 1}}
		if Verify(recs, "r", led, k.Public(), VerifyOptions{Witness: w}).Problem == nil && len(recs) != len(recLines) {
			t.Fatalf("verified %d records against a witness of %d", len(recs), last.Size)
		}
	})
}

// A proof that checks says something true about the sealed log.
func FuzzProof(f *testing.F) {
	k, _, _, recLines, led := fuzzLog(f)
	for _, line := range []int{1, 13, 20} {
		p, err := Prove(led, "test.jsonl", line, []byte(recLines[line-1]))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(p.JSON())
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := ParseProof(b)
		if err != nil {
			return
		}
		if q, err := ParseProof(p.JSON()); err != nil || q.Line != p.Line || !bytes.Equal(q.Record, p.Record) {
			t.Fatalf("written again, it reads differently: %v", err)
		}
		if p.Check(k.Public()) == nil && (p.Line > len(recLines) || string(p.Record) != recLines[p.Line-1]) {
			t.Fatalf("a proof that line %d is %q holds", p.Line, p.Record)
		}
	})
}

// Only checkpoints the key signed come back from a witness file.
func FuzzReadWitness(f *testing.F) {
	k, _, ledger, _, orig := fuzzLog(f)
	f.Add(ledger)
	f.Add([]byte("Oct  5 10:00:00 gw ledger: " + string(orig.Checkpoints[0].AppendJSON(nil)) + "\n"))
	signed := map[string]bool{}
	for _, c := range orig.Checkpoints {
		signed[string(c.Message())] = true
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		ws, err := ReadWitness(bytes.NewReader(b), "w", k.Public())
		if err != nil {
			return
		}
		for _, w := range ws {
			if !signed[string(w.CP.Message())] {
				t.Fatalf("line %d: a checkpoint the key never signed", w.Line)
			}
		}
	})
}
