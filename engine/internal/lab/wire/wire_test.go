// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package wire

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"vpnw.com/vpnw/internal/lab"
)

var observer = netip.MustParseAddr("198.51.100.10")

func TestQueryAndAnswer(t *testing.T) {
	msg, err := Query(0xbeef, "D17.r-abc.Lab.Test.")
	if err != nil {
		t.Fatal(err)
	}
	q, err := ParseQuery(msg)
	if err != nil {
		t.Fatal(err)
	}
	if q.ID != 0xbeef || q.Name != "d17.r-abc.lab.test" || q.Type != TypeA || q.Class != ClassIN || q.End != len(msg) {
		t.Fatalf("%+v", q)
	}
	ans := Answer(msg, q, RcodeOK, observer, 5)
	r, err := ParseAnswer(ans)
	if err != nil || r.ID != 0xbeef || r.Rcode != RcodeOK || len(r.Addrs) != 1 || r.Addrs[0] != observer {
		t.Fatalf("answer: %v %+v", err, r)
	}
	if ans[2]&0x01 == 0 || ans[3]&0x80 == 0 {
		t.Fatal("RD should be copied and RA set")
	}
	nx := Answer(msg, q, RcodeNXDom, observer, 5)
	if r, err := ParseAnswer(nx); err != nil || r.Rcode != RcodeNXDom || len(r.Addrs) != 0 {
		t.Fatalf("nxdomain: %v %+v", err, r)
	}
	// A query for another type gets no record.
	other := append([]byte{}, msg...)
	other[len(other)-3] = 28 // AAAA
	q2, _ := ParseQuery(other)
	if r, _ := ParseAnswer(Answer(other, q2, RcodeOK, observer, 5)); len(r.Addrs) != 0 {
		t.Fatal("an AAAA question got an A record")
	}
	for _, name := range []string{"", ".", "a..b", strings.Repeat("a", 64) + ".test", strings.Repeat("abcdefg.", 32) + "test"} {
		if _, err := Query(1, name); err == nil {
			t.Errorf("Query(%q) should fail", name)
		}
	}
}

func TestParseQueryErrors(t *testing.T) {
	good, _ := Query(7, "d1.r.lab.test")
	mod := func(f func(b []byte) []byte) []byte { return f(append([]byte{}, good...)) }
	for want, msg := range map[string][]byte{
		"shorter than its header":    good[:5],
		"a DNS response":             mod(func(b []byte) []byte { b[2] |= 0x80; return b }),
		"opcode":                     mod(func(b []byte) []byte { b[2] |= 0x10; return b }),
		"2 questions":                mod(func(b []byte) []byte { b[5] = 2; return b }),
		"runs past the message":      good[:14],
		"label runs past":            mod(func(b []byte) []byte { b[12] = 60; return b[:20] }),
		"compressed or extended":     mod(func(b []byte) []byte { b[12] = 0xc0; return b }),
		"byte 0x2e":                  mod(func(b []byte) []byte { b[13] = '.'; return b }),
		"for the root":               append(append([]byte{}, good[:12]...), 0, 0, 1, 0, 1),
		"without its type and class": good[:len(good)-2],
	} {
		if _, err := ParseQuery(msg); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
	long := append([]byte{}, good[:12]...)
	for i := 0; i < 5; i++ {
		long = append(long, 63)
		long = append(long, bytes.Repeat([]byte{'a'}, 63)...)
	}
	long = append(long, 0, 0, 1, 0, 1)
	if _, err := ParseQuery(long); err == nil || !strings.Contains(err.Error(), "longer than 253") {
		t.Errorf("long name: %v", err)
	}
}

func TestParseAnswerErrors(t *testing.T) {
	q, _ := Query(7, "d1.r.lab.test")
	pq, _ := ParseQuery(q)
	good := Answer(q, pq, RcodeOK, observer, 5)
	for want, msg := range map[string][]byte{
		"shorter than its header":    good[:3],
		"a DNS query":                q,
		"record data runs past":      good[:len(good)-2],
		"answer runs past":           good[:len(good)-12],
		"ends inside a question":     append(func() []byte { b := append([]byte{}, good[:12]...); b[7] = 0; return b }(), 0, 0),
		"pointer runs past":          append(func() []byte { b := append([]byte{}, good[:12]...); b[6] = 0; return b }(), 0xc0),
		"extended DNS label":         append(func() []byte { b := append([]byte{}, good[:12]...); b[6] = 0; return b }(), 0x40),
		"name runs past the message": append(func() []byte { b := append([]byte{}, good[:12]...); b[6] = 0; return b }(), 5, 'a'),
	} {
		if _, err := ParseAnswer(msg); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
}

func TestProbeNamesAndTags(t *testing.T) {
	p := Probe{Kind: lab.DNS, Via: lab.Direct, Run: "r-3f9a1c", Seq: 17}
	if p.Name() != "d17.r-3f9a1c.lab.test" {
		t.Fatal(p.Name())
	}
	got, err := ParseName("D17.R-3F9A1C.lab.test.")
	if err != nil || got != p {
		t.Fatalf("%v %+v", err, got)
	}
	p.Via = lab.Proxy
	if got, err := ParseName(p.Name()); err != nil || got != p || !strings.HasPrefix(p.Name(), "p17.") {
		t.Fatalf("proxy name: %v %+v", err, got)
	}
	for _, name := range []string{"example.com", "d17.lab.test", "x17.r.lab.test", "d.r.lab.test", "d07.r.lab.test", "d1x.r.lab.test", "d1.r_x.lab.test", "d99999999999.r.lab.test"} {
		if _, err := ParseName(name); err == nil {
			t.Errorf("ParseName(%q) should fail", name)
		}
	}
	tp := Probe{Kind: lab.UDP, Via: lab.Direct, Run: "r-1", Seq: 0}
	if tp.Tag() != "vpnw-lab udp direct r-1 0\n" {
		t.Fatal(tp.Tag())
	}
	if got, err := ParseTag(tp.Tag()); err != nil || got != tp {
		t.Fatalf("%v %+v", err, got)
	}
	for _, tag := range []string{"", "hello", "vpnw-lab icmp direct r 1", "vpnw-lab tcp tunnel r 1", "vpnw-lab tcp direct R 1",
		"vpnw-lab tcp direct r -1", "vpnw-lab tcp direct r 1 extra", "vpnw-lab tcp direct " + strings.Repeat("r", 33) + " 1",
		"vpnw-lab tcp direct r " + strings.Repeat("1", 80)} {
		if _, err := ParseTag(tag); err == nil {
			t.Errorf("ParseTag(%q) should fail", tag)
		}
	}
	if CheckRun("") == nil || CheckRun("ok-1") != nil {
		t.Fatal("CheckRun")
	}
}

func TestFrames(t *testing.T) {
	nonce := []byte("12345678")
	b := AppendFrame(nil, Hello, nonce)
	typ, pl, err := ParseFrame(b)
	if err != nil || typ != Hello || !bytes.Equal(pl, nonce) {
		t.Fatalf("%v %d %q", err, typ, pl)
	}
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	if typ, pl, err := ParseFrame(AppendFrame(nil, Data, pkt)); err != nil || typ != Data || len(pl) != 20 {
		t.Fatalf("data: %v", err)
	}
	for want, f := range map[string][]byte{
		"not a tunnel frame":   []byte("VX\x01\x01"),
		"version":              {'V', 'L', 2, Hello},
		"8-byte payload":       AppendFrame(nil, Ping, []byte("1234")),
		"must carry an IPv4":   AppendFrame(nil, Data, make([]byte, 20)),
		"unknown tunnel frame": AppendFrame(nil, 9, nonce),
		"not a tunnel frame ":  nil,
	} {
		if _, _, err := ParseFrame(f); err == nil || !strings.Contains(err.Error(), strings.TrimSpace(want)) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
}

func FuzzParseQuery(f *testing.F) {
	q, _ := Query(1, "d1.r-a.lab.test")
	f.Add(q)
	f.Add([]byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1})
	f.Fuzz(func(t *testing.T, msg []byte) {
		q, err := ParseQuery(msg)
		if err != nil {
			return
		}
		again, err := Query(q.ID, q.Name)
		if err != nil {
			t.Fatalf("parsed name %q does not build a query: %v", q.Name, err)
		}
		q2, err := ParseQuery(again)
		if err != nil || q2.Name != q.Name || q2.ID != q.ID {
			t.Fatalf("round trip of %q: %v %+v", q.Name, err, q2)
		}
		r, err := ParseAnswer(Answer(msg, q, RcodeOK, observer, 1))
		if err != nil || r.ID != q.ID {
			t.Fatalf("our own answer does not parse: %v", err)
		}
	})
}

func FuzzParseAnswer(f *testing.F) {
	q, _ := Query(1, "d1.r-a.lab.test")
	pq, _ := ParseQuery(q)
	f.Add(Answer(q, pq, RcodeOK, observer, 5))
	f.Add(Answer(q, pq, RcodeNXDom, observer, 5))
	f.Fuzz(func(t *testing.T, msg []byte) {
		r, err := ParseAnswer(msg)
		if err == nil && len(r.Addrs) > len(msg)/14 {
			t.Fatalf("%d addresses from %d bytes", len(r.Addrs), len(msg))
		}
	})
}

func FuzzParseName(f *testing.F) {
	f.Add("d17.r-3f9a1c.lab.test")
	f.Add("p0.r.lab.test.")
	f.Fuzz(func(t *testing.T, name string) {
		p, err := ParseName(name)
		if err != nil {
			return
		}
		again, err := ParseName(p.Name())
		if err != nil || again != p {
			t.Fatalf("%q -> %+v -> %v %+v", name, p, err, again)
		}
	})
}

func FuzzParseTag(f *testing.F) {
	f.Add("vpnw-lab tcp direct r-3f9a1c 17\n")
	f.Add("vpnw-lab  dns   proxy r 0")
	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParseTag(s)
		if err != nil {
			return
		}
		again, err := ParseTag(p.Tag())
		if err != nil || again != p {
			t.Fatalf("%q -> %+v -> %v %+v", s, p, err, again)
		}
	})
}

func FuzzParseFrame(f *testing.F) {
	f.Add(AppendFrame(nil, Ping, []byte("12345678")))
	f.Add(AppendFrame(nil, Data, append([]byte{0x45}, make([]byte, 30)...)))
	f.Fuzz(func(t *testing.T, b []byte) {
		typ, pl, err := ParseFrame(b)
		if err != nil {
			return
		}
		if !bytes.Equal(AppendFrame(nil, typ, pl), b) {
			t.Fatalf("frame %x does not write back the same", b)
		}
	})
}
