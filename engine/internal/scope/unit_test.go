// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)

func mustDest(t *testing.T, s string) Dest {
	t.Helper()
	d, err := ParseDest(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDestRoundTrip(t *testing.T) {
	for _, s := range []string{
		"10.0.1.20:443/tcp", "10.0.0.53:53/udp", "10.0.3.0/24:8000-8100/tcp", "10.0.0.0/8:1-65535/udp", "0.0.0.0/0:22/tcp",
	} {
		d := mustDest(t, s)
		if d.String() != s {
			t.Errorf("%s: String() = %s", s, d)
		}
	}
	d := mustDest(t, "10.0.1.20:443/tcp")
	if !d.Single() || mustDest(t, "10.0.3.0/24:443/tcp").Single() || mustDest(t, "10.0.1.20:1-2/tcp").Single() {
		t.Error("Single() is wrong")
	}
}

func TestDestErrors(t *testing.T) {
	for s, want := range map[string]string{
		"10.0.1.20:443":         "missing /tcp",
		"10.0.1.20:443/icmp":    "want tcp or udp",
		"10.0.1.20/tcp":         "missing :PORT",
		"10.0.1.300:443/tcp":    "",
		"10.0.3.1/24:443/tcp":   "host bits set",
		"10.0.1.20:0/tcp":       "not a port",
		"10.0.1.20:65536/tcp":   "not a port",
		"10.0.1.20:90-80/tcp":   "runs backwards",
		"10.0.1.20:80-x/tcp":    "not a port",
		"[::1]:443/tcp":         "",
		"2001:db8::/32:443/tcp": "only IPv4",
		"10.0.1.0/33:443/tcp":   "",
		"example.com:443/tcp":   "",
	} {
		_, err := ParseDest(s)
		if err == nil {
			t.Errorf("%q: no error", s)
			continue
		}
		if want != "" && !strings.Contains(err.Error(), want) {
			t.Errorf("%q: error %q, want it to mention %q", s, err, want)
		}
	}
}

func TestDestMatch(t *testing.T) {
	d := mustDest(t, "10.0.3.0/24:8000-8100/tcp")
	a := netip.MustParseAddr
	cases := []struct {
		dst   string
		port  uint16
		proto Proto
		want  bool
	}{
		{"10.0.3.1", 8000, TCP, true}, {"10.0.3.255", 8100, TCP, true}, {"10.0.3.1", 7999, TCP, false},
		{"10.0.3.1", 8101, TCP, false}, {"10.0.4.1", 8050, TCP, false}, {"10.0.3.1", 8050, UDP, false},
	}
	for _, c := range cases {
		if got := d.Match(a(c.dst), c.port, c.proto); got != c.want {
			t.Errorf("%s:%d/%s: got %v", c.dst, c.port, c.proto, got)
		}
	}
}

func TestFlowJSONRoundTrip(t *testing.T) {
	f := Flow{Time: t0.Add(250 * time.Millisecond), Proto: UDP, Src: netip.MustParseAddr("10.8.0.11"), Dst: netip.MustParseAddr("10.0.0.53"), Port: 53}
	line := string(f.AppendJSON(nil))
	want := `{"t":"2026-09-07T09:00:00.25Z","proto":"udp","src":"10.8.0.11","dst":"10.0.0.53","port":53}`
	if line != want {
		t.Fatalf("got %s\nwant %s", line, want)
	}
	g, err := ParseFlowJSON(line)
	if err != nil || g != f {
		t.Fatalf("round trip: %v %+v", err, g)
	}
	// Any key order, spaces and unknown keys are fine.
	g, err = ParseFlowJSON(`{ "port": 53, "dst": "10.0.0.53", "bytes": 120, "src": "10.8.0.11", "note": "x", "proto": "udp", "t": "2026-09-07T09:00:00.25Z" }`)
	if err != nil || g != f {
		t.Fatalf("reordered: %v %+v", err, g)
	}
}

func TestFlowJSONErrors(t *testing.T) {
	good := `"t":"2026-09-07T09:00:00Z","proto":"tcp","src":"10.8.0.11","dst":"10.0.1.20","port":443`
	for line, want := range map[string]string{
		``:                         "not a JSON object",
		`[]`:                       "not a JSON object",
		`{` + good + `,}`:          "trailing comma",
		`{` + good + `,"port":80}`: "appears twice",
		`{"proto":"tcp","src":"10.8.0.11","dst":"10.0.1.20","port":443}`: `missing "t"`,
		`{` + strings.Replace(good, `"tcp"`, `"icmp"`, 1) + `}`:          "want tcp or udp",
		`{` + strings.Replace(good, `443`, `"443"`, 1) + `}`:             "must be a number",
		`{` + strings.Replace(good, `443`, `70000`, 1) + `}`:             "not a port number",
		`{` + strings.Replace(good, `443`, `0`, 1) + `}`:                 "port 0",
		`{` + strings.Replace(good, `10.8.0.11`, `fe80::1`, 1) + `}`:     "only IPv4",
		`{` + strings.Replace(good, `10.8.0.11`, `10.8.0`, 1) + `}`:      "src",
		`{` + strings.Replace(good, `T09`, `X09`, 1) + `}`:               `"t"`,
		`{"t":"a\"b"}`: "escapes",
		`{"t" "x"}`:    "expected :",
		`{"t":"2026-09-07T09:00:00Z" "proto":"tcp"}`: "expected ,",
		`{"port":true}`:          "only strings and numbers",
		`{"port":}`:              "missing value",
		`{"t":"abc`:              "not a JSON object",
		`{"t":12}`:               "must be a string",
		`{"proto":6}`:            "must be a string",
		`{"src":1}`:              "must be a string",
		`{x:1}`:                  "expected a string",
		`{"t":"` + "\x01" + `"}`: "control character",
	} {
		_, err := ParseFlowJSON(line)
		if err == nil {
			t.Errorf("%s: no error", line)
		} else if !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error %q, want %q", line, err, want)
		}
	}
}

func TestReadFlows(t *testing.T) {
	var buf bytes.Buffer
	fw := NewFlowWriter(&buf)
	f := Flow{Time: t0, Proto: TCP, Src: netip.MustParseAddr("10.8.0.11"), Dst: netip.MustParseAddr("10.0.1.20"), Port: 443}
	for i := 0; i < 3; i++ {
		fw.Write(f)
	}
	fw.Flush()
	buf.WriteString("\n# a comment\n")
	var got []Flow
	st, err := ReadFlows(&buf, "flows.jsonl", func(f Flow) error { got = append(got, f); return nil })
	if err != nil || st.Flows != 3 || st.Skipped != 2 || len(got) != 3 {
		t.Fatalf("%v %+v", err, st)
	}
	_, err = ReadFlows(strings.NewReader("\n{bad}\n"), "x.jsonl", func(Flow) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "x.jsonl:2:") {
		t.Fatalf("want an error at line 2, got %v", err)
	}
	long := strings.Repeat("x", MaxLine+10)
	_, err = ReadFlows(strings.NewReader(long), "long.jsonl", func(Flow) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Fatalf("want a line-length error, got %v", err)
	}
}

func TestProto(t *testing.T) {
	if TCP.String() != "tcp" || UDP.String() != "udp" || Proto(1).String() != "proto-1" {
		t.Error("Proto.String")
	}
	if _, err := ParseProto("sctp"); err == nil {
		t.Error("sctp accepted")
	}
	k := Key{netip.MustParseAddr("10.0.1.20"), 443, TCP}
	if k.String() != "10.0.1.20:443/tcp" {
		t.Error(k.String())
	}
}

func TestConntrack(t *testing.T) {
	cases := []struct {
		line string
		ok   bool
		want string
	}{
		{"[1757235600.250000]\t    [NEW] tcp      6 120 SYN_SENT src=10.8.0.11 dst=10.0.1.20 sport=51234 dport=443 [UNREPLIED] src=10.0.1.20 dst=10.8.0.11 sport=443 dport=51234",
			true, `{"t":"2025-09-07T09:00:00.25Z","proto":"tcp","src":"10.8.0.11","dst":"10.0.1.20","port":443}`},
		{"[1757235600]    [NEW] ipv4     2 udp      17 30 src=10.8.0.12 dst=10.0.0.53 sport=40000 dport=53 [UNREPLIED] src=10.0.0.53 dst=10.8.0.12 sport=53 dport=40000",
			true, `{"t":"2025-09-07T09:00:00Z","proto":"udp","src":"10.8.0.12","dst":"10.0.0.53","port":53}`},
		{"[1757235600.1] [UPDATE] tcp      6 60 SYN_RECV src=10.8.0.11 dst=10.0.1.20 sport=51234 dport=443", false, ""},
		{"[1757235600.1] [NEW] icmp     1 30 src=10.8.0.11 dst=10.0.1.20 type=8 code=0 id=1", false, ""},
		{"[1757235600.1] [NEW] ipv6     10 tcp      6 120 SYN_SENT src=fd00::1 dst=fd00::2 sport=1 dport=443", false, ""},
	}
	for _, c := range cases {
		f, ok, err := ParseConntrackLine(c.line)
		if err != nil || ok != c.ok {
			t.Errorf("%s: ok=%v err=%v", c.line, ok, err)
			continue
		}
		if ok && string(f.AppendJSON(nil)) != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.line, f.AppendJSON(nil), c.want)
		}
	}
	for line, want := range map[string]string{
		"    [NEW] tcp 6 120 SYN_SENT src=1.2.3.4": "no [timestamp]",
		"[123":                     "unterminated",
		"[1x] [NEW] tcp":           "want seconds",
		"[x] [NEW] tcp":            "no [timestamp]",
		"[1.0123456789] [NEW] tcp": "too many digits",
		"[1.-5] [NEW] tcp":         "bad fraction",
		"[1]":                      "no event",
		"[1] [NEW]":                "missing protocol",
		"[1] [NEW] tcp 6 120 SYN_SENT src=10.8.0.11 dst=10.0.1.20":        "missing src=",
		"[1] [NEW] tcp 6 120 SYN_SENT src=10.8.0 dst=10.0.1.20 dport=443": "src:",
		"[1] [NEW] tcp 6 120 SYN_SENT src=10.8.0.1 dst=x dport=443":       "dst:",
		"[1] [NEW] tcp 6 120 SYN_SENT src=10.8.0.1 dst=10.0.0.1 dport=0":  "not a port",
	} {
		_, _, err := ParseConntrackLine(line)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: error %v, want %q", line, err, want)
		}
	}
	in := "[1757235600.25] [NEW] tcp 6 120 SYN_SENT src=10.8.0.11 dst=10.0.1.20 sport=1 dport=443\n\n[1757235601] [DESTROY] tcp 6 src=10.8.0.11 dst=10.0.1.20 sport=1 dport=443\n"
	n := 0
	st, err := ReadConntrack(strings.NewReader(in), "ct.log", func(Flow) error { n++; return nil })
	if err != nil || st.Flows != 1 || st.Ignored != 2 || n != 1 {
		t.Fatalf("%v %+v", err, st)
	}
	if _, err := ReadConntrack(strings.NewReader("garbage\n"), "ct.log", func(Flow) error { return nil }); err == nil || !strings.Contains(err.Error(), "ct.log:1:") {
		t.Fatalf("want an error at line 1, got %v", err)
	}
}

const peopleSrc = `# test people
version = 1
vpn_net = "10.8.0.0/24"

[people.alice]
name = "Alice Martin"
addresses = ["10.8.0.11"]
groups = ["finance", "managers"]

[people.bob]
addresses = ["10.8.0.12", "10.8.0.13"]
groups = ["finance"]

[people.carol]
wireguard_keys = ["xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="]
groups = ["engineering"]
`

func testPeople(t *testing.T) *People {
	t.Helper()
	p, err := ParsePeople(peopleSrc, "people.toml")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPeople(t *testing.T) {
	p := testPeople(t)
	if p.VPNNet.String() != "10.8.0.0/24" || len(p.List) != 3 {
		t.Fatalf("%+v", p)
	}
	if got := strings.Join(p.GroupOrder, ","); got != "finance,managers,engineering" {
		t.Errorf("group order %s", got)
	}
	if len(p.Groups["finance"]) != 2 || p.ByAddr(netip.MustParseAddr("10.8.0.13")).ID != "bob" || p.Get("alice").Name != "Alice Martin" {
		t.Error("lookups")
	}
	if u := p.Unresolved(); len(u) != 1 || u[0] != "carol" {
		t.Fatalf("unresolved %v", u)
	}
	dump := "wg0\tprivkey=\tpubkey=\t51820\toff\n" +
		"wg0\txTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\t(none)\t203.0.113.7:4242\t10.8.0.20/32,10.99.0.0/16\t0\t0\t0\toff\n" +
		"wg0\tHIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=\t(none)\t(none)\t(none)\t0\t0\t0\toff\n\n"
	if err := p.ResolveKeys(dump, "dump"); err != nil {
		t.Fatal(err)
	}
	if c := p.Get("carol"); len(c.Addrs) != 1 || c.Addrs[0].String() != "10.8.0.20" || p.ByAddr(c.Addrs[0]) != c {
		t.Fatalf("carol %+v", c)
	}
	// The single-interface format has no interface column.
	p = testPeople(t)
	if err := p.ResolveKeys("priv\tpub\t51820\toff\nxTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\t(none)\t(none)\t10.8.0.21/32\t0\t0\t0\toff\n", "dump"); err != nil {
		t.Fatal(err)
	}
	if p.Get("carol").Addrs[0].String() != "10.8.0.21" {
		t.Fatal("single-interface dump")
	}
	for dump, want := range map[string]string{
		"a\tb\n": "not a line",
		"wg0\txTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\t(none)\t(none)\tbad\t0\t0\t0\toff\n":          "allowed IP",
		"wg0\tother\t(none)\t(none)\t10.8.0.20/32\t0\t0\t0\toff\n":                                        "not in the dump",
		"wg0\txTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\t(none)\t(none)\t10.9.0.1/32\t0\t0\t0\toff\n":  "outside vpn_net",
		"wg0\txTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\t(none)\t(none)\t10.8.0.11/32\t0\t0\t0\toff\n": "belongs to both",
	} {
		p := testPeople(t)
		if err := p.ResolveKeys(dump, "dump"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: error %v, want %q", dump, err, want)
		}
	}
}

func TestPeopleErrors(t *testing.T) {
	base := "version = 1\nvpn_net = \"10.8.0.0/24\"\n"
	for src, want := range map[string]string{
		"vpn_net = \"10.8.0.0/24\"\n":                                   "missing version",
		"version = 2\nvpn_net = \"10.8.0.0/24\"\n":                      "version must be 1",
		"version = 1\n":                                                 "missing vpn_net",
		"version = 1\nvpn_net = 5\n":                                    "must be a string",
		"version = 1\nvpn_net = \"10.8.0.1/24\"\n":                      "host bits",
		"version = 1\nvpn_net = \"fd00::/64\"\n":                        "IPv4 range",
		base + "colour = \"red\"\n":                                     "unknown key \"colour\"",
		base + "[groups.x]\n":                                           "unknown table",
		base + "[people]\n":                                             "unknown table",
		base + "[people.\"a b\"]\naddresses = [\"10.8.0.1\"]\n":         "person name",
		base + "[people.a]\n":                                           "no addresses",
		base + "[people.a]\nname = 1\naddresses = [\"10.8.0.1\"]\n":     "name must be a string",
		base + "[people.a]\naddresses = \"10.8.0.1\"\n":                 "array of strings",
		base + "[people.a]\naddresses = [1]\n":                          "array of strings",
		base + "[people.a]\naddresses = [\"10.8.0\"]\n":                 "want an IPv4 address",
		base + "[people.a]\naddresses = [\"10.9.0.1\"]\n":               "outside vpn_net",
		base + "[people.a]\naddresses = [\"10.8.0.1\", \"10.8.0.1\"]\n": "listed twice",
		base + "[people.a]\naddresses = [\"10.8.0.1\"]\n[people.b]\naddresses = [\"10.8.0.1\"]\n": "belongs to both",
		base + "[people.a]\nwireguard_keys = [\"short\"]\n":                                       "44 characters",
		base + "[people.a]\nwireguard_keys = [\"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\"]\n[people.b]\nwireguard_keys = [\"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\"]\n": "also listed",
		base + "[people.a]\naddresses = [\"10.8.0.1\"]\ngroups = [\"a b\"]\n":                                                                                                       "group name",
		base + "[people.a]\naddresses = [\"10.8.0.1\"]\ngroups = [\"x\", \"x\"]\n":                                                                                                  "listed twice",
		base + "[people.a]\naddresses = [\"10.8.0.1\"]\nrole = \"x\"\n":                                                                                                             "unknown key \"role\"",
		"version = 1\nvpn_net = [\n": "people.toml",
	} {
		_, err := ParsePeople(src, "people.toml")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q:\n error %v\n want %q", src, err, want)
		}
	}
	if ValidName("") || ValidName(strings.Repeat("a", 65)) || !ValidName("a-b_C9") {
		t.Error("ValidName")
	}
}

func testDraft(t *testing.T, p *People) *Draft {
	t.Helper()
	d, err := ParseDraft(`version = 1
default = "deny"

[groups.finance]
allow = ["10.0.1.20:443/tcp", "10.0.0.53:53/udp"]

[people.alice]
allow = ["10.0.1.21:5432/tcp", "10.0.3.0/24:8000-8100/tcp"]
review = ["10.0.2.30:5432/tcp"]

[people.carol]
allow = ["10.0.2.10:22/tcp"]
`, "draft.toml", p)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDraftRoundTrip(t *testing.T) {
	p := testPeople(t)
	d := testDraft(t, p)
	d.Header = []string{"a header", ""}
	d.Groups["finance"].Allow[0].Note = "all 2 active members"
	text := d.String()
	if !strings.HasPrefix(text, "# a header\n#\nversion = 1\n") || !strings.Contains(text, "# all 2 active members") {
		t.Fatalf("unexpected text:\n%s", text)
	}
	e, err := ParseDraft(text, "again.toml", p)
	if err != nil {
		t.Fatal(err)
	}
	dests := func(d *Draft) string {
		var b strings.Builder
		for _, g := range d.GroupOrder {
			for _, r := range d.Groups[g].Allow {
				b.WriteString(g + " " + r.Dest.String() + "\n")
			}
		}
		for _, id := range d.PeopleOrder {
			for _, r := range d.People[id].Allow {
				b.WriteString(id + " " + r.Dest.String() + "\n")
			}
			for _, r := range d.People[id].Review {
				b.WriteString(id + " review " + r.Dest.String() + "\n")
			}
		}
		return b.String()
	}
	if dests(e) != dests(d) || e.String() == "" {
		t.Fatalf("round trip differs:\n%s\nvs\n%s", dests(e), dests(d))
	}
	c := d.Count()
	if c.GroupRules != 2 || c.PersonRules != 3 || c.Review != 1 || c.Groups != 1 || c.People != 2 {
		t.Fatalf("%+v", c)
	}
	if d.Describe() != "2 group rules for 1 group, 3 personal rules for 2 people, 1 under review" {
		t.Error(d.Describe())
	}
}

func TestDraftErrors(t *testing.T) {
	p := testPeople(t)
	for src, want := range map[string]string{
		"default = \"deny\"\n":                                         "missing version",
		"version = 3\n":                                                "version must be 1",
		"version = 1\ndefault = \"allow\"\n":                           "must be \"deny\"",
		"version = 1\nmode = 1\n":                                      "unknown key",
		"version = 1\n[groups.nobody]\nallow = []\n":                   "no one in the people file",
		"version = 1\n[people.zed]\nallow = []\n":                      "not in the people file",
		"version = 1\n[rules.x]\n":                                     "unknown table",
		"version = 1\n[groups.finance]\nreview = []\n":                 "unknown key \"review\"",
		"version = 1\n[people.alice]\ndeny = []\n":                     "unknown key \"deny\"",
		"version = 1\n[people.alice]\nallow = [\"10.0.1.20:443\"]\n":   "missing /tcp",
		"version = 1\n[people.alice]\nallow = \"10.0.1.20:443/tcp\"\n": "array of strings",
		"version = 1\n[people.alice]\nallow = [\"10.0.1.20:443/tcp\"]\nreview = [\"10.0.1.20:443/tcp\"]\n": "listed twice",
		"version = 1\n[people.alice\n": "draft.toml",
	} {
		_, err := ParseDraft(src, "draft.toml", p)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q:\n error %v\n want %q", src, err, want)
		}
	}
}

func TestDecideAndReplay(t *testing.T) {
	p := testPeople(t)
	p.ResolveKeys("wg0\txTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\t(none)\t(none)\t10.8.0.20/32\t0\t0\t0\toff\n", "dump")
	pol := Compile(testDraft(t, p), p)
	a := netip.MustParseAddr
	flow := func(src, dst string, port uint16, proto Proto) Flow {
		return Flow{Time: t0, Proto: proto, Src: a(src), Dst: a(dst), Port: port}
	}
	cases := []struct {
		f    Flow
		out  Outcome
		rule string
	}{
		{flow("10.8.0.11", "10.0.1.20", 443, TCP), Allowed, "group finance"},
		{flow("10.8.0.13", "10.0.0.53", 53, UDP), Allowed, "group finance"}, // bob's second address
		{flow("10.8.0.11", "10.0.1.21", 5432, TCP), Allowed, "person alice"},
		{flow("10.8.0.11", "10.0.3.9", 8050, TCP), Allowed, "person alice"}, // range rule
		{flow("10.8.0.11", "10.0.2.30", 5432, TCP), Denied, ""},             // under review
		{flow("10.8.0.12", "10.0.1.21", 5432, TCP), Denied, ""},             // alice's, not bob's
		{flow("10.8.0.20", "10.0.2.10", 22, TCP), Allowed, "person carol"},  // from the WireGuard key
		{flow("10.8.0.20", "10.0.1.20", 443, TCP), Denied, ""},              // carol is not in finance
		{flow("10.8.0.99", "10.0.1.20", 443, TCP), Denied, ""},              // no one's address
		{flow("192.168.1.5", "10.0.1.20", 443, TCP), NotVPN, ""},
		{Flow{Time: t0, Proto: Proto(1), Src: a("10.8.0.11"), Dst: a("10.0.1.20")}, Denied, ""},
	}
	r := NewReplay(pol)
	for _, c := range cases {
		v := r.Add(c.f)
		if v.Outcome != c.out || v.Rule != c.rule {
			t.Errorf("%+v: got %+v", c.f, v)
		}
		if v.Outcome == Denied && v.Reason == "" {
			t.Errorf("%+v: denied without a reason", c.f)
		}
	}
	if r.Flows != 11 || r.Allowed != 5 || r.Denied != 5 || r.NotVPN != 1 {
		t.Fatalf("replay totals %+v", r)
	}
	if r.People["alice"].Allowed != 3 || r.People["alice"].Denied != 2 {
		t.Fatalf("alice %+v", r.People["alice"])
	}
	keys := r.DeniedKeys()
	if len(keys) != 5 || keys[len(keys)-1].Person != "" && keys[0].Count != 1 {
		t.Fatalf("denied keys %+v", keys)
	}
	var unknown int
	for _, k := range keys {
		if k.Person == "" {
			unknown++
		}
	}
	if unknown != 1 {
		t.Fatalf("want one unknown source among %+v", keys)
	}
	if Allowed.String() != "allowed" || Denied.String() != "denied" || NotVPN.String() != "not-vpn" {
		t.Error("Outcome.String")
	}
}

func TestSetElements(t *testing.T) {
	d := func(s string) Dest { return mustDest(t, s) }
	got, err := setElements("x", []Dest{
		d("10.0.1.10:993/tcp"), d("10.0.1.0/28:1-1024/tcp"), d("10.0.1.0/28:1-1024/tcp"),
		d("10.0.1.20:443/tcp"), d("10.0.1.20:443/tcp"), d("10.0.2.0/24:22/tcp"), d("10.0.2.0/25:22/tcp"),
	})
	if err != nil {
		t.Fatal(err)
	}
	var s []string
	for _, e := range got {
		s = append(s, e.String())
	}
	if strings.Join(s, " ") != "10.0.1.0/28:1-1024/tcp 10.0.1.20:443/tcp 10.0.2.0/24:22/tcp" {
		t.Fatalf("got %v", s)
	}
	if _, err := setElements("person alice", []Dest{d("10.0.1.0/24:400-500/tcp"), d("10.0.1.0/25:450-600/tcp")}); err == nil ||
		!strings.Contains(err.Error(), "overlap") {
		t.Fatalf("want an overlap error, got %v", err)
	}
	used := map[string]bool{}
	if nftName("g_", "a-b", used) != "g_a_b" || nftName("g_", "a_b", used) != "g_a_b_2" {
		t.Error("nftName")
	}
}

func TestExportNft(t *testing.T) {
	p := testPeople(t)
	p.ResolveKeys("wg0\txTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\t(none)\t(none)\t10.8.0.20/32\t0\t0\t0\toff\n", "dump")
	d := testDraft(t, p)
	s, err := ExportNft(d, p, NftOptions{Source: "draft.toml"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table inet vpnw_scope\ndelete table inet vpnw_scope\ntable inet vpnw_scope {",
		"set g_finance_src {\n\t\ttype ipv4_addr\n\t\telements = {\n\t\t\t10.8.0.11, 10.8.0.12, 10.8.0.13\n",
		"10.0.1.20 . 443", "10.0.3.0/24 . 8000-8100",
		"ip saddr 10.8.0.0/24 jump from_vpn",
		"ct state established,related accept",
		"ip saddr @g_finance_src ip daddr . tcp dport @g_finance_tcp accept",
		"ip saddr @g_finance_src ip daddr . udp dport @g_finance_udp accept",
		"ip saddr { 10.8.0.11 } ip daddr . tcp dport @p_alice_tcp accept",
		"ip saddr { 10.8.0.20 } ip daddr . tcp dport @p_carol_tcp accept",
		"reject with icmpx type admin-prohibited\n\t}\n}\n",
		"# Made from draft.toml.",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if strings.Contains(s, "10.0.2.30") {
		t.Error("a review entry was exported")
	}
	w, _ := ExportNft(d, p, NftOptions{Watch: true, LogGroup: 5, Table: "t2"})
	if !strings.Contains(w, `log prefix "vpnw-scope would refuse" group 5`) || !strings.Contains(w, `counter accept comment "would be refused"`) ||
		strings.Contains(w, "reject") || !strings.Contains(w, "table inet t2 {") {
		t.Errorf("watch export:\n%s", w)
	}
	dr, _ := ExportNft(d, p, NftOptions{Drop: true, LogGroup: 3})
	if !strings.Contains(dr, "\t\tdrop\n") || !strings.Contains(dr, `log prefix "vpnw-scope refused" group 3`) {
		t.Errorf("drop export:\n%s", dr)
	}
	d.People["alice"].Allow = append(d.People["alice"].Allow, Rule{Dest: mustDest(t, "10.0.3.0/25:8050-9000/tcp")})
	if _, err := ExportNft(d, p, NftOptions{}); err == nil {
		t.Error("partial overlap exported")
	}
}

func TestExportAllowedIPs(t *testing.T) {
	p := testPeople(t)
	p.ResolveKeys("wg0\txTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\t(none)\t(none)\t10.8.0.20/32\t0\t0\t0\toff\n", "dump")
	d := testDraft(t, p)
	d.Person("bob").Allow = append(d.Person("bob").Allow, Rule{Dest: mustDest(t, "10.0.1.20:22/tcp")})
	s := ExportAllowedIPs(d, p)
	for _, want := range []string{
		"# alice (Alice Martin)\nAllowedIPs = 10.0.0.53/32, 10.0.1.20/32, 10.0.1.21/32, 10.0.3.0/24\n",
		"# bob\nAllowedIPs = 10.0.0.53/32, 10.0.1.20/32\n",
		"# carol\nAllowedIPs = 10.0.2.10/32\n",
		"They\n# enforce nothing",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	d.People["carol"].Allow = nil
	if !strings.Contains(ExportAllowedIPs(d, p), "# carol\n# nothing allowed") {
		t.Error("empty person")
	}
	got := minimalPrefixes([]netip.Prefix{netip.MustParsePrefix("10.0.1.5/32"), netip.MustParsePrefix("10.0.0.0/16"), netip.MustParsePrefix("10.1.0.1/32")})
	if len(got) != 2 || got[0].String() != "10.0.0.0/16" || got[1].String() != "10.1.0.1/32" {
		t.Fatalf("minimalPrefixes %v", got)
	}
}

func TestComma(t *testing.T) {
	for n, want := range map[int]string{0: "0", 999: "999", 1000: "1,000", 20232: "20,232", 1234567: "1,234,567", -4321: "-4,321"} {
		if got := Comma(n); got != want {
			t.Errorf("Comma(%d) = %s", n, got)
		}
	}
}

func TestDraftKeepsComments(t *testing.T) {
	p := testPeople(t)
	d := testDraft(t, p)
	d.Header = []string{"learned from 7 flows", "", "second line"}
	d.Groups["finance"].Allow[0].Note = "both active members, 2 days"
	d.People["alice"].Review[0].Note = "1 day, 2 connections"
	text := d.String()
	e, err := ParseDraft(text, "again.toml", p)
	if err != nil {
		t.Fatal(err)
	}
	if e.String() != text {
		t.Fatalf("comments lost:\n%s\nvs\n%s", e.String(), text)
	}
	dest := mustDest(t, "10.0.2.30:5432/tcp")
	if !e.Move("alice", dest, true) || len(e.People["alice"].Review) != 0 || len(e.People["alice"].Allow) != 3 {
		t.Fatalf("move to allow: %+v", e.People["alice"])
	}
	moved := e.String()
	if !strings.Contains(moved, `"10.0.2.30:5432/tcp",`) || !strings.Contains(moved, "# 1 day, 2 connections") || strings.Contains(moved, "review = [") {
		t.Fatalf("after the move:\n%s", moved)
	}
	if !e.Move("alice", dest, false) || e.String() != text {
		t.Fatalf("moving back does not restore the draft:\n%s", e.String())
	}
	if e.Move("alice", mustDest(t, "10.9.9.9:1/tcp"), true) || e.Move("nobody", dest, true) {
		t.Fatal("moved something that is not there")
	}
	// Notes that do not parse are ignored, not fatal.
	odd := "# top\nversion = 1\n[people.alice]\nallow = [\n  \"10.0.1.20:443/tcp\", # ok\n  \"x#y\",\n]\n"
	if _, err := ParseDraft(odd, "odd.toml", p); err == nil {
		t.Fatal("a bad rule was accepted")
	}
}
