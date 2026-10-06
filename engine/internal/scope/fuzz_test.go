// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"strings"
	"testing"
)

func FuzzParseFlowJSON(f *testing.F) {
	f.Add(`{"t":"2026-09-07T09:00:00.25Z","proto":"udp","src":"10.8.0.11","dst":"10.0.0.53","port":53}`)
	f.Add(`{ "port": 443, "dst": "10.0.1.20", "src": "10.8.0.12", "proto": "tcp", "t": "2026-09-07T09:00:00Z", "bytes": 12 }`)
	f.Add(`{"t":"x"}`)
	f.Fuzz(func(t *testing.T, line string) {
		fl, err := ParseFlowJSON(line)
		if err != nil {
			return
		}
		again, err := ParseFlowJSON(string(fl.AppendJSON(nil)))
		if err != nil || !again.Time.Equal(fl.Time) || again.Src != fl.Src || again.Dst != fl.Dst || again.Port != fl.Port || again.Proto != fl.Proto {
			t.Fatalf("round trip of %q: %v %+v %+v", line, err, fl, again)
		}
	})
}

func FuzzParseConntrackLine(f *testing.F) {
	f.Add("[1757235600.250000]\t    [NEW] tcp      6 120 SYN_SENT src=10.8.0.11 dst=10.0.1.20 sport=51234 dport=443 [UNREPLIED] src=10.0.1.20 dst=10.8.0.11 sport=443 dport=51234")
	f.Add("[1757235600]    [NEW] ipv4     2 udp      17 30 src=10.8.0.12 dst=10.0.0.53 sport=40000 dport=53")
	f.Add("[1.5] [DESTROY] tcp 6 src=1.2.3.4")
	f.Fuzz(func(t *testing.T, line string) {
		fl, ok, err := ParseConntrackLine(line)
		if err == nil && ok {
			if e := fl.Check(); e != nil {
				t.Fatalf("%q: accepted a bad flow: %v", line, e)
			}
		}
	})
}

func FuzzParseDest(f *testing.F) {
	for _, s := range []string{"10.0.1.20:443/tcp", "10.0.3.0/24:8000-8100/udp", "0.0.0.0/0:1-65535/tcp", "a:b/c"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d, err := ParseDest(s)
		if err != nil {
			return
		}
		e, err := ParseDest(d.String())
		if err != nil || e != d {
			t.Fatalf("%q -> %s -> %v %+v", s, d, err, e)
		}
	})
}

func FuzzParsePeople(f *testing.F) {
	f.Add(peopleSrc)
	f.Add("version = 1\nvpn_net = \"10.8.0.0/24\"\n[people.a]\naddresses = [\"10.8.0.1\"]\n")
	f.Fuzz(func(t *testing.T, src string) {
		p, err := ParsePeople(src, "fuzz.toml")
		if err != nil {
			return
		}
		seen := map[string]string{}
		for _, per := range p.List {
			for _, a := range per.Addrs {
				if !p.VPNNet.Contains(a) {
					t.Fatalf("%s outside %s", a, p.VPNNet)
				}
				if other, dup := seen[a.String()]; dup {
					t.Fatalf("%s given to %s and %s", a, other, per.ID)
				}
				seen[a.String()] = per.ID
			}
		}
		p.ResolveKeys("wg0\txTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\t(none)\t(none)\t10.8.0.20/32\t0\t0\t0\toff\n", "dump")
	})
}

func FuzzParseDraft(f *testing.F) {
	people, err := ParsePeople(peopleSrc, "people.toml")
	if err != nil {
		f.Fatal(err)
	}
	f.Add("version = 1\ndefault = \"deny\"\n[groups.finance]\nallow = [\"10.0.1.20:443/tcp\"]\n[people.alice]\nallow = [\"10.0.3.0/24:1-1024/tcp\"]\nreview = [\"10.0.2.30:5432/tcp\"]\n")
	f.Add("version = 1\n[people.bob]\nallow = [\"10.0.0.0/8:53/udp\", \"10.0.0.53:53/udp\"]\n")
	f.Fuzz(func(t *testing.T, src string) {
		d, err := ParseDraft(src, "fuzz.toml", people)
		if err != nil {
			return
		}
		Compile(d, people)
		ExportAllowedIPs(d, people)
		if _, err := ExportNft(d, people, NftOptions{}); err != nil && !strings.Contains(err.Error(), "overlap") {
			t.Fatalf("export: %v", err)
		}
		e, err := ParseDraft(d.String(), "again.toml", people)
		if err != nil {
			t.Fatalf("a parsed draft does not parse again: %v\n%s", err, d)
		}
		if e.Count() != d.Count() {
			t.Fatalf("counts changed: %+v %+v", d.Count(), e.Count())
		}
	})
}
