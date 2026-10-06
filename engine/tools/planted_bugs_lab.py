#!/usr/bin/env python3
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

"""Plant realistic bugs in Lab, one at a time, and check that its tests catch
each one. A bug the suite misses is a missing test. Run from the engine
directory:

    python3 tools/planted_bugs_lab.py            # all bugs
    python3 tools/planted_bugs_lab.py 3 7        # only bugs 3 and 7

Each bug is a (file, exact text, replacement, what it would break) tuple.
The file is restored after every run, even on Ctrl-C or SIGTERM. For each bug the unit
tests run first; if they all pass, the kernel tests run too, every app
through every scenario. A bug counts as caught only if a test fails.
"""
import os
import signal
import subprocess
import sys


def interrupted(signum, frame):
    # SIGTERM restores the file too, as Ctrl-C does.
    raise KeyboardInterrupt


signal.signal(signal.SIGTERM, interrupted)

L = "internal/lab/"
BUGS = [
    # The verdict.
    (L + "verdict.go",
     "\tcase a.At == AtHomeDNS:\n\t\treturn Outside\n\tcase a.At == AtVPNDNS, a.Src == h.Exit:",
     "\tcase a.At == AtVPNDNS, a.At == AtHomeDNS, a.Src == h.Exit:",
     "a query that reached the home router's resolver counts as through the tunnel"),
    (L + "verdict.go",
     "case a.At == AtVPNDNS, a.Src == h.Exit:",
     "case a.At == AtVPNDNS, a.Src == h.Exit, a.Src == h.Home:",
     "an arrival from the home network's address counts as through the tunnel"),
    (L + "verdict.go",
     "} else if p.Outcome == Lost {",
     "} else {",
     "a probe seen outside the tunnel and then through it counts as through"),
    (L + "verdict.go",
     "p.Leak.Sub(v.Windows[n-1].End) > gap",
     "p.Leak.Sub(v.Windows[n-1].End) > gap/8",
     "a leak window breaks apart at every probe"),
    (L + "verdict.go",
     "w.Open = v.Stop.IsZero() || v.Stop.Sub(w.End) <= gap",
     "w.Open = v.Stop.IsZero()",
     "a leak still going when the run stops is reported as over"),
    (L + "verdict.go",
     "if limit.IsZero() || p.First.Before(limit) {",
     "if limit.IsZero() || p.First.After(limit) {",
     "an app that carried nothing through the tunnel before the fault is judged anyway"),
    # Recordings and timetables.
    (L + "event.go",
     "if err != nil || n < 0 || n > max {",
     "if err != nil || n > max {",
     "negative sequence numbers and seeds are accepted"),
    (L + "event.go",
     "\t\tcase c == '\"' || c == '\\\\':",
     "\t\tcase c == '\\\\':",
     "a note with a quote mark writes a broken line"),
    (L + "scenario.go",
     "r := splitmix(uint64(seed))",
     "r := splitmix(uint64(time.Now().UnixNano()))",
     "the seed is ignored, so the fault moves from run to run"),
    # Wire formats.
    (L + "wire/probe.go",
     "\tcase 'p':\n\t\tp.Via = lab.Proxy",
     "\tcase 'p':\n\t\tp.Via = lab.Direct",
     "a name asked through the proxy is read as a direct probe"),
    (L + "wire/dns.go",
     "b[2] = 0x80 | query[2]&0x01",
     "b[2] = query[2] & 0x01",
     "DNS answers go out marked as queries"),
    (L + "wire/tunnel.go",
     "b[FrameHeader]>>4 != 4",
     "b[FrameHeader]>>4 != 6",
     "the tunnel refuses every IPv4 packet"),
    # Netlink.
    (L + "netlink/netlink_linux.go",
     "return append(body, attr(rtaTable, u32(uint32(table)))...), nil",
     "return body, nil",
     "routes for the client's own table land in the main table"),
    (L + "netlink/netlink_linux.go",
     "\t\tnative.PutUint32(hdr[8:], fibRuleInv)\n",
     "",
     "a \"not fwmark\" rule loses its \"not\""),
    # The test world.
    (L + "world/world_linux.go",
     "snat to 192.0.2.20",
     "snat to 192.0.2.10",
     "the VPN's NAT uses the server's address, not the exit address"),
    (L + "world/world_linux.go",
     "oifname \"wan0\" ip saddr 192.168.1.0/24 masquerade",
     "oifname \"lan0\" ip saddr 192.168.1.0/24 masquerade",
     "the home router stops translating addresses"),
    (L + "world/world_linux.go",
     "\t\tip daddr 192.0.2.10 drop\n",
     "\t\tip daddr 192.0.2.20 drop\n",
     "a silent server still takes the client's packets in and passes them on"),
    (L + "world/world_linux.go",
     "\t\terr := netlink.AddRoute(netlink.Route{Dst: netip.MustParsePrefix(\"0.0.0.0/0\"), Gateway: RouterAddr, Dev: DeviceLink})",
     "\t\tvar err error",
     "the device gets no default route when its link comes back"),
    (L + "world/world_linux.go",
     "var PushedRoute = netlink.Route{Dst: ObservedNet,",
     "var PushedRoute = netlink.Route{Dst: netip.MustParsePrefix(\"203.0.113.0/24\"),",
     "the pushed route misses the observers' range"),
    (L + "world/world_linux.go",
     "if a.p.Run != run {",
     "if a.p.Run == run {",
     "arrivals of other runs end up in the recording, and this run's are lost"),
    # The stand-in clients.
    (L + "client/client_linux.go",
     "Mark: c.o.Mark, Invert: true}}",
     "Mark: c.o.Mark, Invert: false}}",
     "strict routing sends only the client's own packets to the tunnel's table"),
    (L + "client/client.go",
     "\"the tunnel itself\\\"\\n\", o.Mark, o.Server.Addr()",
     "\"the tunnel itself\\\"\\n\", o.Mark+1, o.Server.Addr()",
     "the kill switch blocks the client's own tunnel"),
    (L + "client/client_linux.go",
     "if now.Sub(c.lastHeard) > c.o.DeadAfter {",
     "if now.Sub(c.lastHeard) > 10*c.o.DeadAfter {",
     "the client waits ten seconds before it notices a silent server"),
    (L + "client/client_linux.go",
     "err != nil || a != c.o.DNS {",
     "err != nil {",
     "the correct client stops putting its resolver back after the network changes it"),
    (L + "client/client_linux.go",
     "\tif c.o.Mode.HomeDNSWhileDown {",
     "\tif !c.o.Mode.HomeDNSWhileDown {",
     "every client but dns-leak points DNS at the home router while it reconnects"),
    # The probe.
    (L + "probe/probe.go",
     "wire.Probe{Kind: lab.DNS, Via: lab.Direct, Run: o.Run, Seq: k})",
     "wire.Probe{Kind: lab.DNS, Via: lab.Proxy, Run: o.Run, Seq: k})",
     "direct DNS probes ask for the proxy's names"),
    (L + "probe/probe.go",
     "}(wire.Probe{Kind: lab.TCP, Via: lab.Direct, Run: o.Run, Seq: k})",
     "}(wire.Probe{Kind: lab.UDP, Via: lab.Direct, Run: o.Run, Seq: k})",
     "TCP probes are tagged as UDP"),
    # The bench.
    (L + "bench/bench_linux.go",
     "syscall.Kill(-r.app.cmd.Process.Pid, syscall.SIGKILL)\n\t} else {",
     "syscall.Kill(r.app.cmd.Process.Pid, syscall.SIGKILL)\n\t} else {",
     "killing the Agent leaves its workload running"),
    (L + "bench/bench_linux.go",
     "return w.SetDNS(world.RouterDNS2)",
     "return w.SetDNS(world.TunnelPeer)",
     "the DNS change hands out the VPN's own resolver"),
]


def run_suite():
    env = dict(os.environ, VPNW_LAB_PARALLEL=os.environ.get("VPNW_LAB_PARALLEL", "6"))
    unit = subprocess.run(["go", "test", "-count=1", "-failfast", "./internal/lab/...", "./cmd/vpnw-lab/"], capture_output=True, text=True)
    if unit.returncode != 0:
        return False
    kernel = subprocess.run(["go", "test", "-count=1", "-failfast", "./test/lab/"], capture_output=True, text=True, env=env)
    return kernel.returncode == 0


def main():
    pick = {int(a) for a in sys.argv[1:]}
    caught = missed = skipped = 0
    for i, (f, find, repl, desc) in enumerate(BUGS, 1):
        if pick and i not in pick:
            continue
        orig = open(f).read()
        if orig.count(find) != 1:
            print(f"  [{i:2}] SKIPPED, anchor not found exactly once: {desc}", flush=True)
            skipped += 1
            continue
        open(f, "w").write(orig.replace(find, repl, 1))
        try:
            ok = run_suite()
        finally:
            open(f, "w").write(orig)
        if ok:
            print(f"  [{i:2}] MISSED: {desc}", flush=True)
            missed += 1
        else:
            print(f"  [{i:2}] caught: {desc}", flush=True)
            caught += 1
    total = caught + missed + skipped
    print(f"\n{caught} of {total} planted bugs caught" + (f", {skipped} skipped" if skipped else ""))
    sys.exit(0 if missed == 0 and skipped == 0 else 1)


if __name__ == "__main__":
    main()
