// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"fmt"
	"net/netip"
	"time"

	"vpnw.com/vpnw/internal/scope"
)

// DemoSeed is the seed behind the demo's numbers.
const DemoSeed = 20260907

// Demo days: two weeks to learn from, then the week after, replayed.
const (
	DemoLearnFrom   = 0  // Monday 7 September 2026
	DemoLearnTo     = 14 // up to Sunday 20 September, included
	DemoReplayFrom  = 14 // Monday 21 September
	DemoReplayTo    = 21 // up to Sunday 27 September, included
	DemoStolenLogin = "alice"
)

// DemoStolenAt is when the stolen login is tried: a Thursday evening in the
// replayed week.
var DemoStolenAt = time.Date(2026, 9, 24, 21, 47, 0, 0, time.UTC)

func svc(port uint16, proto scope.Proto, name string) Service {
	return Service{Port: port, Proto: proto, Name: name}
}

func use(system string, port uint16, proto scope.Proto, p float64, min, max int) Use {
	return Use{System: system, Port: port, Proto: proto, P: p, Min: min, Max: max}
}

// Demo returns the demo office: 30 people in five groups and 12 internal
// systems.
func Demo() *Office {
	t, u := scope.TCP, scope.UDP
	o := &Office{
		Name:     "demo office",
		VPNNet:   netip.MustParsePrefix("10.8.0.0/24"),
		Start:    time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC),
		PresentP: 0.92,
		Systems: []System{
			{"dns", netip.MustParseAddr("10.0.0.53"), []Service{svc(53, u, "dns"), svc(53, t, "dns over tcp")}},
			{"mail", netip.MustParseAddr("10.0.1.10"), []Service{svc(993, t, "imaps"), svc(587, t, "submission")}},
			{"intranet", netip.MustParseAddr("10.0.1.11"), []Service{svc(443, t, "https")}},
			{"files", netip.MustParseAddr("10.0.1.12"), []Service{svc(445, t, "smb")}},
			{"erp", netip.MustParseAddr("10.0.1.20"), []Service{svc(443, t, "https")}},
			{"payroll", netip.MustParseAddr("10.0.1.21"), []Service{svc(5432, t, "postgres")}},
			{"git", netip.MustParseAddr("10.0.2.10"), []Service{svc(443, t, "https"), svc(22, t, "ssh")}},
			{"ci", netip.MustParseAddr("10.0.2.11"), []Service{svc(443, t, "https")}},
			{"staging-db", netip.MustParseAddr("10.0.2.30"), []Service{svc(5432, t, "postgres")}},
			{"crm", netip.MustParseAddr("10.0.3.10"), []Service{svc(443, t, "https")}},
			{"helpdesk", netip.MustParseAddr("10.0.3.20"), []Service{svc(443, t, "https")}},
			{"backup", netip.MustParseAddr("10.0.9.10"), []Service{svc(22, t, "ssh"), svc(8443, t, "console")}},
		},
	}
	common := []Use{
		use("dns", 53, u, 1, 20, 60),
		use("dns", 53, t, 0.6, 1, 2),
		use("mail", 993, t, 0.98, 2, 6),
		use("mail", 587, t, 0.6, 1, 4),
		use("intranet", 443, t, 0.7, 1, 8),
	}
	with := func(extra ...Use) []Use { return append(append([]Use{}, common...), extra...) }
	o.Groups = map[string][]Use{
		"finance":     with(use("files", 445, t, 0.6, 1, 10), use("erp", 443, t, 0.95, 3, 20)),
		"engineering": with(use("git", 443, t, 0.95, 5, 30), use("git", 22, t, 0.9, 2, 20), use("ci", 443, t, 0.85, 2, 15)),
		"sales":       with(use("crm", 443, t, 0.95, 3, 25), use("files", 445, t, 0.5, 1, 6)),
		"support":     with(use("crm", 443, t, 0.8, 1, 10), use("helpdesk", 443, t, 0.98, 5, 40), use("files", 445, t, 0.5, 1, 4)),
		"it":          with(use("backup", 22, t, 0.7, 1, 10), use("backup", 8443, t, 0.5, 1, 5), use("helpdesk", 443, t, 0.8, 1, 10), use("files", 445, t, 0.5, 1, 5)),
	}
	o.GroupList = []string{"finance", "engineering", "sales", "support", "it"}
	payroll := use("payroll", 5432, t, 0.7, 1, 12)
	staging := use("staging-db", 5432, t, 0.6, 1, 10)
	files := use("files", 445, t, 0.4, 1, 6)
	people := []struct {
		id, name, group string
		uses            []Use
	}{
		{"alice", "Alice Martin", "finance", []Use{payroll}},
		{"dmitri", "Dmitri Volkov", "finance", []Use{payroll}},
		{"fatima", "Fatima Haddad", "finance", nil},
		{"grace", "Grace Okafor", "finance", nil},
		{"henrik", "Henrik Larsen", "finance", nil},
		{"ben", "Ben Carter", "engineering", []Use{files}},
		{"chen", "Chen Wei", "engineering", []Use{staging}},
		{"diego", "Diego Alvarez", "engineering", []Use{files}},
		{"elena", "Elena Rossi", "engineering", []Use{staging}},
		{"farid", "Farid Nazari", "engineering", nil},
		{"hiro", "Hiro Tanaka", "engineering", []Use{files}},
		{"ines", "Ines Duarte", "engineering", nil},
		{"jonas", "Jonas Weber", "engineering", nil},
		{"kira", "Kira Novak", "engineering", []Use{staging}},
		{"leo", "Leo Fischer", "engineering", []Use{files}},
		{"maya", "Maya Levi", "engineering", []Use{files}},
		{"nils", "Nils Berg", "engineering", []Use{staging}},
		{"olivia", "Olivia Brown", "sales", nil},
		{"pablo", "Pablo Ruiz", "sales", nil},
		{"quinn", "Quinn Murphy", "sales", nil},
		{"rosa", "Rosa Silva", "sales", nil},
		{"sam", "Sam Taylor", "sales", nil},
		{"hana", "Hana Kim", "sales", nil},
		{"tomas", "Tomas Kral", "support", nil},
		{"uma", "Uma Patel", "support", nil},
		{"victor", "Victor Dubois", "support", nil},
		{"wanda", "Wanda Nowak", "support", nil},
		{"yusuf", "Yusuf Demir", "support", nil},
		{"zoe", "Zoe Adams", "it", nil},
		{"omar", "Omar Said", "it", nil},
	}
	for i, p := range people {
		m := Member{ID: p.id, Name: p.name, Groups: []string{p.group}, Uses: p.uses,
			Addr: netip.MustParseAddr(fmt.Sprintf("10.8.0.%d", 11+i))}
		switch p.id {
		case "hana":
			m.StartDay = DemoReplayFrom // joins in the replayed week
		case "diego":
			m.OnCall = []int{5} // Saturday of the first week
		case "nils":
			m.OnCall = []int{13} // Sunday of the second week
		}
		o.Members = append(o.Members, m)
	}
	o.Events = []Event{
		{Person: "quinn", Day: 2, System: "erp", Port: 443, Proto: t, Conns: 2},     // sales opens the ERP once
		{Person: "jonas", Day: 8, System: "crm", Port: 443, Proto: t, Conns: 1},     // an engineer looks at the CRM once
		{Person: "zoe", Day: 10, System: "payroll", Port: 5432, Proto: t, Conns: 3}, // IT checks the payroll database once
		{Person: "quinn", Day: 16, System: "erp", Port: 443, Proto: t, Conns: 3},    // ... and again in the replayed week
	}
	o.Changes = []Change{
		{Person: "farid", FromDay: DemoReplayFrom, Use: staging}, // a new need in the replayed week
	}
	o.index()
	return o
}
