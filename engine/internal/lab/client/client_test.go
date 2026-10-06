// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func options(mode string) Options {
	m, _ := FindMode(mode)
	o := Options{Mode: m, Server: netip.MustParseAddrPort("192.0.2.10:51820"), Dev: "eth0",
		DNS: netip.MustParseAddr("10.66.0.1"), HomeNet: netip.MustParsePrefix("192.168.1.0/24")}
	o.Defaults()
	return o
}

func TestModes(t *testing.T) {
	if len(Modes) != 4 || len(ModeNames()) != 4 {
		t.Fatal("four modes")
	}
	for _, name := range ModeNames() {
		m, err := FindMode(name)
		if err != nil || m.Name != name {
			t.Fatalf("%s: %v %+v", name, err, m)
		}
	}
	if _, err := FindMode("perfect"); err == nil || !strings.Contains(err.Error(), "correct, dns-leak, no-kill-switch, follows-routes") {
		t.Fatalf("unknown mode: %v", err)
	}
	// Each faulty mode differs from the correct one where its fault is.
	c := Modes["correct"]
	if !c.Strict || !c.KillSwitch || !c.PinDNS || !c.HoldDNS || c.LocalAccess || c.HomeDNSWhileDown || c.HoldRoutes {
		t.Fatalf("correct: %+v", c)
	}
	if d := Modes["dns-leak"]; !d.HomeDNSWhileDown || !d.LocalAccess || d.PinDNS || d.HoldDNS || !d.KillSwitch {
		t.Fatalf("dns-leak: %+v", d)
	}
	if n := Modes["no-kill-switch"]; n.KillSwitch || !n.Strict || !n.HoldDNS {
		t.Fatalf("no-kill-switch: %+v", n)
	}
	if f := Modes["follows-routes"]; f.Strict || !f.HoldRoutes || !f.PinDNS {
		t.Fatalf("follows-routes: %+v", f)
	}
}

func TestDefaults(t *testing.T) {
	o := options("correct")
	if o.Keepalive != 100*time.Millisecond || o.DeadAfter != time.Second || o.Retry != 300*time.Millisecond ||
		o.Settle != time.Second || o.Tick != 25*time.Millisecond || o.Tun != "tun0" || o.Mark != 0x51 || o.Table != 51820 {
		t.Fatalf("%+v", o)
	}
	o = Options{DeadAfter: 3 * time.Second, Tun: "wg9", Mark: 7, Table: 9}
	o.Defaults()
	if o.DeadAfter != 3*time.Second || o.Tun != "wg9" || o.Mark != 7 || o.Table != 9 {
		t.Fatalf("defaults replaced given values: %+v", o)
	}
}

func TestRules(t *testing.T) {
	head := "table inet vpnw_lab_client\ndelete table inet vpnw_lab_client\n"
	correct := Rules(options("correct"))
	for _, want := range []string{
		head + "table inet vpnw_lab_client {\n",
		`meta l4proto { tcp, udp } th dport 53 ip daddr != 10.66.0.1 drop`,
		`oifname "eth0" jump physical`,
		`meta mark 0x51 ip daddr 192.0.2.10 udp dport 51820 accept comment "the tunnel itself"`,
		`drop comment "kill switch"`,
	} {
		if !strings.Contains(correct, want) {
			t.Errorf("correct lacks %q:\n%s", want, correct)
		}
	}
	if strings.Contains(correct, "192.168.1.0/24") {
		t.Errorf("correct lets the local network through:\n%s", correct)
	}
	leak := Rules(options("dns-leak"))
	if !strings.Contains(leak, `ip daddr 192.168.1.0/24 accept comment "the local network"`) || strings.Contains(leak, "dport 53") {
		t.Errorf("dns-leak:\n%s", leak)
	}
	if got := Rules(options("no-kill-switch")); got != head {
		t.Errorf("no-kill-switch should only remove the table:\n%s", got)
	}
	follows := Rules(options("follows-routes"))
	if !strings.Contains(follows, "dport 53") || strings.Contains(follows, "physical") {
		t.Errorf("follows-routes pins DNS and has no firewall kill switch:\n%s", follows)
	}
}
