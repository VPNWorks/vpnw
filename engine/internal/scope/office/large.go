// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"fmt"
	"net/netip"
	"time"

	"vpnw.com/vpnw/internal/scope"
)

// Large returns a bigger made-up office for measurements: n people in
// groups of about 25, about one internal system per seven people, and
// habits drawn at random from seed. It uses the 10.8.0.0/16 VPN range.
func Large(n int, seed uint64) *Office {
	r := &rng{s: seed}
	t, u := scope.TCP, scope.UDP
	o := &Office{
		Name:     fmt.Sprintf("large office (%d people)", n),
		VPNNet:   netip.MustParsePrefix("10.8.0.0/16"),
		Start:    time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC),
		PresentP: 0.92,
		Groups:   map[string][]Use{},
		Systems: []System{
			{"dns", netip.MustParseAddr("10.0.0.53"), []Service{svc(53, u, "dns"), svc(53, t, "dns over tcp")}},
			{"mail", netip.MustParseAddr("10.0.1.10"), []Service{svc(993, t, "imaps"), svc(587, t, "submission")}},
			{"intranet", netip.MustParseAddr("10.0.1.11"), []Service{svc(443, t, "https")}},
		},
	}
	common := []Use{
		use("dns", 53, u, 1, 20, 60),
		use("dns", 53, t, 0.6, 1, 2),
		use("mail", 993, t, 0.98, 2, 6),
		use("mail", 587, t, 0.6, 1, 4),
		use("intranet", 443, t, 0.7, 1, 8),
	}
	ports := []Service{
		svc(443, t, "https"), svc(22, t, "ssh"), svc(5432, t, "postgres"), svc(3306, t, "mysql"),
		svc(8080, t, "http-alt"), svc(445, t, "smb"), svc(389, t, "ldap"), svc(6379, t, "redis"),
		svc(9200, t, "search"), svc(123, u, "ntp"), svc(514, u, "syslog"),
	}
	nsys := n / 7
	if nsys < 10 {
		nsys = 10
	}
	for i := 0; i < nsys; i++ {
		s := System{Name: fmt.Sprintf("sys%03d", i+1), Addr: netip.AddrFrom4([4]byte{10, 1, byte(i / 250), byte(i%250 + 1)})}
		k := 1 + r.intn(2)
		for j := 0; j < k; j++ {
			sv := ports[r.intn(len(ports))]
			if !s.Offers(sv.Port, sv.Proto) {
				s.Services = append(s.Services, sv)
			}
		}
		o.Systems = append(o.Systems, s)
	}
	randomUse := func(pmin, pmax float64) Use {
		s := o.Systems[3+r.intn(nsys)]
		sv := s.Services[r.intn(len(s.Services))]
		return use(s.Name, sv.Port, sv.Proto, pmin+(pmax-pmin)*r.float(), 1, 1+r.intn(15))
	}
	ngroups := n / 25
	if ngroups < 2 {
		ngroups = 2
	}
	for g := 0; g < ngroups; g++ {
		name := fmt.Sprintf("g%03d", g+1)
		uses := append([]Use{}, common...)
		k := 4 + r.intn(7)
		for j := 0; j < k; j++ {
			uses = append(uses, randomUse(0.3, 1))
		}
		o.Groups[name] = uses
		o.GroupList = append(o.GroupList, name)
	}
	for i := 0; i < n; i++ {
		m := Member{
			ID:     fmt.Sprintf("p%05d", i+1),
			Name:   fmt.Sprintf("Person %d", i+1),
			Groups: []string{o.GroupList[r.intn(ngroups)]},
			Addr:   netip.AddrFrom4([4]byte{10, 8, byte((i + 11) / 256), byte((i + 11) % 256)}),
		}
		if r.intn(10) == 0 {
			if g := o.GroupList[r.intn(ngroups)]; g != m.Groups[0] {
				m.Groups = append(m.Groups, g)
			}
		}
		for j := r.intn(4); j > 0; j-- {
			m.Uses = append(m.Uses, randomUse(0.2, 0.8))
		}
		o.Members = append(o.Members, m)
	}
	for i := 0; i < n/20; i++ {
		m := o.Members[r.intn(n)]
		s := o.Systems[3+r.intn(nsys)]
		sv := s.Services[r.intn(len(s.Services))]
		o.Events = append(o.Events, Event{Person: m.ID, Day: r.intn(14), System: s.Name, Port: sv.Port, Proto: sv.Proto, Conns: 1 + r.intn(3)})
	}
	o.index()
	return o
}
