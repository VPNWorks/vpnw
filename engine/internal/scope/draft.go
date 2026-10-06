// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"vpnw.com/vpnw/internal/config"
)

// Rule is one destination in a draft, with the evidence behind it.
type Rule struct {
	Dest Dest
	Note string // written as a comment: how often and by whom it was used
}

// RuleSet is what one group or one person may reach. Review holds
// destinations that were seen too rarely to allow without a person's
// decision; they stay blocked until moved into Allow.
type RuleSet struct {
	Allow  []Rule
	Review []Rule
}

// Draft is a set of rules for a VPN: rules per group, applying to every
// member, and rules per person. Anything not allowed is denied.
type Draft struct {
	Header      []string
	Groups      map[string]*RuleSet
	GroupOrder  []string
	People      map[string]*RuleSet
	PeopleOrder []string
}

// NewDraft returns an empty draft.
func NewDraft() *Draft {
	return &Draft{Groups: map[string]*RuleSet{}, People: map[string]*RuleSet{}}
}

// Group returns the rule set of a group, creating it if needed.
func (d *Draft) Group(name string) *RuleSet {
	rs, ok := d.Groups[name]
	if !ok {
		rs = &RuleSet{}
		d.Groups[name] = rs
		d.GroupOrder = append(d.GroupOrder, name)
	}
	return rs
}

// Person returns the rule set of a person, creating it if needed.
func (d *Draft) Person(id string) *RuleSet {
	rs, ok := d.People[id]
	if !ok {
		rs = &RuleSet{}
		d.People[id] = rs
		d.PeopleOrder = append(d.PeopleOrder, id)
	}
	return rs
}

// Counts sums the rules in a draft.
type Counts struct {
	GroupRules, PersonRules, Review int
	Groups, People                  int // with at least one allow rule
}

// Count returns the draft's rule counts.
func (d *Draft) Count() Counts {
	var c Counts
	for _, g := range d.GroupOrder {
		if n := len(d.Groups[g].Allow); n > 0 {
			c.GroupRules += n
			c.Groups++
		}
	}
	for _, p := range d.PeopleOrder {
		rs := d.People[p]
		c.PersonRules += len(rs.Allow)
		c.Review += len(rs.Review)
		if len(rs.Allow) > 0 {
			c.People++
		}
	}
	return c
}

func lessDest(a, b Dest) bool {
	if a.Net.Addr() != b.Net.Addr() {
		return a.Net.Addr().Less(b.Net.Addr())
	}
	if a.Net.Bits() != b.Net.Bits() {
		return a.Net.Bits() < b.Net.Bits()
	}
	if a.Lo != b.Lo {
		return a.Lo < b.Lo
	}
	if a.Hi != b.Hi {
		return a.Hi < b.Hi
	}
	return a.Proto < b.Proto
}

// SortRules puts rules in address, port and protocol order.
func SortRules(r []Rule) {
	sort.Slice(r, func(i, j int) bool { return lessDest(r[i].Dest, r[j].Dest) })
}

// WriteTo writes the draft in its file format.
func (d *Draft) WriteTo(w io.Writer) (int64, error) {
	var b strings.Builder
	for _, h := range d.Header {
		if h == "" {
			b.WriteString("#\n")
		} else {
			b.WriteString("# " + h + "\n")
		}
	}
	b.WriteString("version = 1\ndefault = \"deny\"\n")
	list := func(key string, rules []Rule) {
		if len(rules) == 0 {
			return
		}
		width := 0
		for _, r := range rules {
			if n := len(r.Dest.String()); n > width {
				width = n
			}
		}
		b.WriteString(key + " = [\n")
		for _, r := range rules {
			s := `"` + r.Dest.String() + `",`
			if r.Note != "" {
				s += strings.Repeat(" ", width+4-len(s)) + "  # " + r.Note
			}
			b.WriteString("  " + s + "\n")
		}
		b.WriteString("]\n")
	}
	for _, g := range d.GroupOrder {
		rs := d.Groups[g]
		b.WriteString("\n[groups." + g + "]\n")
		list("allow", rs.Allow)
	}
	for _, p := range d.PeopleOrder {
		rs := d.People[p]
		if len(rs.Allow) == 0 && len(rs.Review) == 0 {
			continue
		}
		b.WriteString("\n[people." + p + "]\n")
		list("allow", rs.Allow)
		list("review", rs.Review)
	}
	n, err := io.WriteString(w, b.String())
	return int64(n), err
}

// String returns the draft in its file format.
func (d *Draft) String() string {
	var b strings.Builder
	d.WriteTo(&b)
	return b.String()
}

// ParseDraft reads a draft and checks it against the people file: every
// group must have members and every person must exist.
func ParseDraft(src, file string, people *People) (*Draft, error) {
	doc, err := config.Parse(src)
	if err != nil {
		if ce, ok := err.(*config.Error); ok {
			ce.File = file
		}
		return nil, err
	}
	d := NewDraft()
	root := doc.Tables[""]
	for _, k := range root.Order {
		v := root.Keys[k]
		switch k {
		case "version":
			if v.Kind != config.KInt || v.Int != 1 {
				return nil, errAt(file, v.Line, "version must be 1")
			}
		case "default":
			if v.Kind != config.KString || v.Str != "deny" {
				return nil, errAt(file, v.Line, "default must be \"deny\": Scope allows only what its rules list")
			}
		default:
			return nil, errAt(file, v.Line, "unknown key %q at the top level (known: version, default)", k)
		}
	}
	if _, ok := root.Keys["version"]; !ok {
		return nil, errAt(file, 1, "missing version = 1")
	}
	for _, name := range doc.Order[1:] {
		t := doc.Tables[name]
		section, id, ok := strings.Cut(name, ".")
		var rs *RuleSet
		switch {
		case ok && section == "groups":
			if len(people.Groups[id]) == 0 {
				return nil, errAt(file, t.Line, "no one in the people file is in group %q", id)
			}
			rs = d.Group(id)
		case ok && section == "people":
			if people.Get(id) == nil {
				return nil, errAt(file, t.Line, "%q is not in the people file", id)
			}
			rs = d.Person(id)
		default:
			return nil, errAt(file, t.Line, "unknown table [%s]; rules go in [groups.NAME] and [people.NAME]", name)
		}
		seen := map[Dest]string{}
		for _, k := range t.Order {
			v := t.Keys[k]
			if k != "allow" && !(k == "review" && section == "people") {
				known := "allow, review"
				if section == "groups" {
					known = "allow"
				}
				return nil, errAt(file, v.Line, "unknown key %q in [%s] (known: %s)", k, name, known)
			}
			list, err := stringList(file, v, k)
			if err != nil {
				return nil, err
			}
			for _, s := range list {
				dest, err := ParseDest(s)
				if err != nil {
					return nil, errAt(file, v.Line, "%v", err)
				}
				if where, dup := seen[dest]; dup {
					return nil, errAt(file, v.Line, "%s is listed twice in [%s] (also in %s)", dest, name, where)
				}
				seen[dest] = k
				if k == "allow" {
					rs.Allow = append(rs.Allow, Rule{Dest: dest})
				} else {
					rs.Review = append(rs.Review, Rule{Dest: dest})
				}
			}
		}
	}
	d.recoverComments(src)
	return d, nil
}

// recoverComments brings back what the TOML reader drops: the comment lines
// at the top of the file, and the note after each rule, so a draft keeps its
// evidence when it is read, changed and written again.
func (d *Draft) recoverComments(src string) {
	lines := strings.Split(src, "\n")
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if !strings.HasPrefix(t, "#") {
			break
		}
		d.Header = append(d.Header, strings.TrimSpace(strings.TrimPrefix(t, "#")))
	}
	var rs *RuleSet
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			section, id, _ := strings.Cut(strings.Trim(t, "[] "), ".")
			rs = nil
			if section == "groups" {
				rs = d.Groups[id]
			} else if section == "people" {
				rs = d.People[id]
			}
			continue
		}
		if rs == nil || !strings.HasPrefix(t, `"`) {
			continue
		}
		end := strings.IndexByte(t[1:], '"')
		hash := strings.Index(t, "#")
		if end < 0 || hash < 0 || hash < end {
			continue
		}
		dest, err := ParseDest(t[1 : end+1])
		if err != nil {
			continue
		}
		note := strings.TrimSpace(t[hash+1:])
		for _, list := range [][]Rule{rs.Allow, rs.Review} {
			for i := range list {
				if list[i].Dest == dest && list[i].Note == "" {
					list[i].Note = note
				}
			}
		}
	}
}

// Move moves a destination between a person's allow and review lists, with
// its note, and reports whether it was found.
func (d *Draft) Move(person string, dest Dest, allow bool) bool {
	rs := d.People[person]
	if rs == nil {
		return false
	}
	from, to := &rs.Review, &rs.Allow
	if !allow {
		from, to = &rs.Allow, &rs.Review
	}
	for i, r := range *from {
		if r.Dest == dest {
			*from = append((*from)[:i:i], (*from)[i+1:]...)
			*to = append(*to, r)
			SortRules(*to)
			return true
		}
	}
	return false
}

// Describe returns a short text summary of a draft.
func (d *Draft) Describe() string {
	c := d.Count()
	return fmt.Sprintf("%s for %s, %s for %s, %s under review",
		plural(c.GroupRules, "group rule", "group rules"), plural(c.Groups, "group", "groups"),
		plural(c.PersonRules, "personal rule", "personal rules"), plural(c.People, "person", "people"), Comma(c.Review))
}
