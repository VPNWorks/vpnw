#!/usr/bin/env python3
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

"""Plant realistic bugs in Scope, one at a time, and check that its tests
catch each one. A bug the suite misses is a missing test. Run from the engine
directory:

    python3 tools/planted_bugs_scope.py            # all bugs
    python3 tools/planted_bugs_scope.py 3 7        # only bugs 3 and 7

Each bug is a (file, exact text, replacement, what it would break) tuple.
The file is restored after every run, even on Ctrl-C.
"""
import subprocess
import sys

S = "internal/scope/"
BUGS = [
    (S + "dest.go",
     "return proto == d.Proto && port >= d.Lo && port <= d.Hi && d.Net.Contains(dst)",
     "return proto == d.Proto && port >= d.Lo && port < d.Hi && d.Net.Contains(dst)",
     "the last port of a range is left out"),
    (S + "dest.go",
     "\t\td.Net = p\n",
     "\t\td.Net = netip.PrefixFrom(p.Addr(), 32)\n",
     "an address range in a rule shrinks to its first address"),
    (S + "flow.go",
     "\tcase \"udp\":\n\t\treturn UDP, nil",
     "\tcase \"udp\", \"icmp\":\n\t\treturn UDP, nil",
     "an unknown protocol is read as udp"),
    (S + "conntrack.go",
     "\t\tcase \"dport\":",
     "\t\tcase \"sport\":",
     "conntrack input takes the source port for the destination port"),
    (S + "people.go",
     "\t\t\t\t\tif !p.VPNNet.Contains(a) {\n\t\t\t\t\t\treturn nil, errAt(file, v.Line, \"address %s is outside vpn_net %s\", a, p.VPNNet)",
     "\t\t\t\t\tif false && !p.VPNNet.Contains(a) {\n\t\t\t\t\t\treturn nil, errAt(file, v.Line, \"address %s is outside vpn_net %s\", a, p.VPNNet)",
     "a person's address outside the VPN range is accepted"),
    (S + "people.go",
     "if other, dup := p.byAddr[a]; dup && other != per {",
     "if other, dup := p.byAddr[a]; dup && other != per && false {",
     "two people may share an address, and one silently takes it"),
    (S + "people.go",
     "if pre.Addr().Is4() && pre.Bits() == 32 {",
     "if pre.Addr().Is4() {",
     "a WireGuard route to a whole range is taken as the person's address"),
    (S + "draft.go",
     "\t\t\t\tif k == \"allow\" {",
     "\t\t\t\tif k == \"allow\" || k == \"review\" {",
     "entries under review are allowed"),
    (S + "learn.go",
     "return e != nil && len(e.days) >= l.opt.MinDays",
     "return e != nil && len(e.days) > l.opt.MinDays",
     "a destination used on exactly the minimum number of days goes under review"),
    (S + "learn.go",
     "\t\t\tif n >= need {",
     "\t\t\tif n >= need-1 {",
     "a group rule no longer needs every active member"),
    (S + "learn.go",
     "if !l.opt.To.IsZero() && !f.Time.Before(l.opt.To) {",
     "if !l.opt.To.IsZero() && f.Time.After(l.opt.To) {",
     "the first instant after the window is learned from"),
    (S + "learn.go",
     "\tif !l.people.VPNNet.Contains(f.Src) {",
     "\tif false && !l.people.VPNNet.Contains(f.Src) {",
     "flows from outside the VPN range are counted as unknown VPN addresses"),
    (S + "learn.go",
     "\t\t\t\tcovered[per][k] = true\n",
     "",
     "what a group rule covers is repeated as personal rules"),
    (S + "sim.go",
     "return Verdict{Outcome: Denied, Reason: fmt.Sprintf(\"%s is in the VPN range but belongs to no one in the people file\", f.Src)}",
     "return Verdict{Outcome: Allowed, Reason: fmt.Sprintf(\"%s is in the VPN range but belongs to no one in the people file\", f.Src)}",
     "a VPN address that belongs to no one is allowed everywhere"),
    (S + "sim.go",
     "\t\tfor _, g := range per.Groups {",
     "\t\tfor _, g := range per.Groups[:1] {",
     "the simulator ignores a person's second group"),
    (S + "sim.go",
     "\t\tif r.dest.Match(f.Dst, f.Port, f.Proto) {",
     "\t\tif false && r.dest.Match(f.Dst, f.Port, f.Proto) {",
     "the simulator ignores address and port ranges"),
    (S + "sim.go",
     "\t\t} else {\n\t\t\tpr.Denied++",
     "\t\t} else {\n\t\t\tpr.Allowed++",
     "the replay counts a person's blocked flows as allowed"),
    (S + "export.go",
     "}{{\"tcp\", tcp}, {\"udp\", udp}} {",
     "}{{\"tcp\", tcp}, {\"tcp\", udp}} {",
     "udp rules are exported as tcp"),
    (S + "export.go",
     "\t\tb.WriteString(\"\\t\\treject with icmpx type admin-prohibited\\n\")",
     "\t\tb.WriteString(\"\\t\\taccept\\n\")",
     "the exported rules let everything through at the end"),
    (S + "export.go",
     "ct state established,related accept",
     "ct state established,related,new accept",
     "every new connection is accepted before the rules are checked"),
    (S + "export.go",
     "\t\tfor _, per := range p.Groups[g] {\n\t\t\tsrcs = append(srcs, per.Addrs...)",
     "\t\tfor _, per := range p.Groups[g][1:] {\n\t\t\tsrcs = append(srcs, per.Addrs...)",
     "each group's first member is missing from its source set"),
    (S + "export.go",
     "\t\t\tif contains(r, d) {",
     "\t\t\tif contains(d, r) {",
     "an address inside an allowed range is exported twice and nftables refuses the set"),
    (S + "export.go",
     "\t\tb.WriteString(e.d.Net.String())\n",
     "\t\tb.WriteString(e.d.Net.Addr().String())\n",
     "an address range is exported as its first address"),
    (S + "export.go",
     "ip saddr %s jump from_vpn\\n\\t}\\n\", p.VPNNet)",
     "ip saddr %s jump from_vpn\\n\\t}\\n\", p.VPNNet.Addr())",
     "only the VPN range's first address goes through the rules"),
    (S + "export.go",
     "\t\tfor _, g := range per.Groups {\n\t\t\tadd(d.Groups[g])\n\t\t}\n",
     "",
     "AllowedIPs leave out what a person's groups allow"),
    (S + "record/nflog_linux.go",
     "Port:  binary.BigEndian.Uint16(b[ihl+2 : ihl+4]),",
     "Port:  binary.BigEndian.Uint16(b[ihl : ihl+2]),",
     "the recorder reads the source port as the destination port"),
    (S + "record/nflog_linux.go",
     "Src:   netip.AddrFrom4([4]byte(b[12:16])),",
     "Src:   netip.AddrFrom4([4]byte(b[16:20])),",
     "the recorder takes the destination address as the source"),
    (S + "record/nflog_linux.go",
     "ct state new meta l4proto { tcp, udp } log group",
     "ct state new meta l4proto tcp log group",
     "the recorder never sees udp"),
]


def run_suite():
    unit = subprocess.run(["go", "test", "-count=1", "./internal/scope/...", "./cmd/vpnw-scope/"], capture_output=True, text=True)
    if unit.returncode != 0:
        return False
    it = subprocess.run(["go", "test", "-count=1", "./test/scope/"], capture_output=True, text=True)
    return it.returncode == 0


def main():
    pick = {int(a) for a in sys.argv[1:]}
    caught = missed = skipped = 0
    for i, (f, find, repl, desc) in enumerate(BUGS, 1):
        if pick and i not in pick:
            continue
        orig = open(f).read()
        if orig.count(find) != 1:
            print(f"  [{i:2}] SKIPPED, anchor not found exactly once: {desc}")
            skipped += 1
            continue
        open(f, "w").write(orig.replace(find, repl, 1))
        try:
            ok = run_suite()
        finally:
            open(f, "w").write(orig)
        if ok:
            print(f"  [{i:2}] MISSED: {desc}")
            missed += 1
        else:
            print(f"  [{i:2}] caught: {desc}")
            caught += 1
    total = caught + missed + skipped
    print(f"\n{caught} of {total} planted bugs caught" + (f", {skipped} skipped" if skipped else ""))
    sys.exit(0 if missed == 0 and skipped == 0 else 1)


if __name__ == "__main__":
    main()
