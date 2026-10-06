#!/usr/bin/env python3
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

"""Plant realistic bugs in security-relevant code, one at a time, and check
that the test suite catches each one. A bug the suite misses is a missing
test. Run from the engine directory:

    python3 tools/planted_bugs.py            # all bugs
    python3 tools/planted_bugs.py 3 7        # only bugs 3 and 7

Each bug is a (file, exact text, replacement, what it would break) tuple.
The file is restored after every run, even on Ctrl-C.
"""
import os
import subprocess
import sys

BUGS = [
    ("internal/policy/policy.go",
     "return len(host) > len(r.Host) && strings.HasSuffix(host, r.Host)",
     "return len(host) > len(r.Host) && strings.HasSuffix(host, r.Host[1:])",
     "*.example.com also matches badexample.com (the dot is dropped)"),
    ("internal/policy/policy.go",
     "case KindExact:\n\t\treturn host == r.Host",
     "case KindExact:\n\t\treturn strings.HasSuffix(host, r.Host)",
     "an exact rule for github.com also matches evilgithub.com"),
    ("internal/policy/private.go",
     '\t{"169.254.0.0/16", "link-local address (169.254.0.0/16), where cloud metadata services live"},\n',
     "",
     "deny_private forgets the link-local range, where cloud metadata lives"),
    ("internal/policy/policy.go",
     "if why, bad := PrivateReason(ip); bad {",
     "if why, bad := PrivateReason(ip); false && bad {",
     "deny_private is not checked on the addresses a name resolved to"),
    ("internal/policy/policy.go",
     "if p.Default == Allow {\n\t\treturn p.DenyPrivate || p.addrDeny\n\t}",
     "if p.Default == Allow {\n\t\treturn false\n\t}",
     "with default allow, names are no longer resolved for deny_private"),
    ("internal/policy/policy.go",
     "\tfor _, ip := range addrs {\n\t\tfor i := range p.Deny {",
     "\tfor _, ip := range addrs[:1] {\n\t\tfor i := range p.Deny {",
     "only the first address of a name is checked (DNS with a private second answer)"),
    ("internal/policy/private.go",
     "if nat64.Contains(ip16) {",
     "if false && nat64.Contains(ip16) {",
     "a private IPv4 address wrapped in NAT64 form (64:ff9b::/96) is let through"),
    ("internal/policy/policy.go",
     "if numericLabel(labels[len(labels)-1]) {",
     "if false && numericLabel(labels[len(labels)-1]) {",
     "numeric host names such as 2130706433 (127.0.0.1) are accepted as names"),
    ("internal/policy/policy.go",
     "if p.DenyPrivate && p.Default == Allow {",
     "if false && p.DenyPrivate && p.Default == Allow {",
     "a path that resolves at its exit silently weakens deny_private"),
    ("internal/broker/broker.go",
     "if !d.Allow {\n\t\t\tb.denied.Add(1)",
     "if false && !d.Allow {\n\t\t\tb.denied.Add(1)",
     "the broker connects even when the policy says deny"),
    ("internal/broker/broker.go",
     'case "host", "proxy-connection", "proxy-authorization", "connection", "keep-alive":',
     'case "host", "proxy-connection", "connection", "keep-alive":',
     "proxy credentials are forwarded to the destination server"),
    ("internal/broker/broker.go",
     'want := byte(0x00)\n\tif b.Token != "" {\n\t\twant = 0x02\n\t}',
     "want := byte(0x00)",
     "the SOCKS5 port stops asking for the per-run token"),
    ("internal/config/config.go",
     "if v.Int != 1 {",
     "if v.Int != 1 && v.Int != 2 {",
     "a configuration file of an unknown version is accepted"),
    ("internal/process/sandbox_guard.go",
     'return len(ifs) == 1 && ifs[0] == "lo"',
     "return len(ifs) >= 1",
     "the sandbox starts even with a network interface other than loopback"),
    ("internal/process/sandbox_linux.go",
     "\tif os.Geteuid() != 0 {\n\t\tif err := dropCapabilities(); err != nil {",
     "\tif false && os.Geteuid() != 0 {\n\t\tif err := dropCapabilities(); err != nil {",
     "the program keeps the capability the sandbox helper needed"),
    ("internal/process/sandbox_linux.go",
     'if os.Getenv("VPNW_SANDBOX_UNIX") != "allow" {',
     'if false && os.Getenv("VPNW_SANDBOX_UNIX") != "allow" {',
     "the Unix-socket filter is never installed, so a program can reach the Docker socket"),
    ("internal/process/seccomp_linux.go",
     "\tafUnix = 1\n",
     "\tafUnix = 2\n",
     "the filter checks the wrong address family and lets Unix sockets through"),
    ("internal/process/seccomp_linux.go",
     "/* 2 */ stmt(bpfRET|bpfK, deny), // another architecture's numbering",
     "/* 2 */ stmt(bpfRET|bpfK, secRetAllow), // another architecture's numbering",
     "32-bit system calls walk around the filter"),
    ("internal/process/process.go",
     '"http_proxy": true, "https_proxy": true, "all_proxy": true, "no_proxy": true,',
     '"http_proxy": true, "https_proxy": true, "all_proxy": true,',
     "a NO_PROXY setting survives and tells programs to go around vpnw"),
    ("internal/path/path.go",
     'u += "***@"',
     'u += p.User + ":" + p.Pass + "@"',
     "a proxy password appears in events and messages"),
    ("internal/learn/learn.go",
     "case d.opened > 0:",
     "case d.opened > 0 || d.denied > 0:",
     "learn allows destinations that were denied during the trace"),
    ("internal/broker/broker.go",
     "\t\tb.opened.Add(1)\n",
     "",
     "the run summary stops counting connections that opened"),
    ("cmd/vpnw/main.go",
     "if pol != nil && st.Denied > 0 && res.Code == 0 && !o.noDenyExit {",
     "if false && pol != nil && st.Denied > 0 && res.Code == 0 && !o.noDenyExit {",
     "guard exits 0 after a denial, so scripts and CI never notice"),
    ("cmd/vpnw/main.go",
     "\t\terr := p.Health(ctx)\n",
     "\t\t_ = ctx\n\t\tvar err error\n",
     "a dead proxy is not caught before the program starts"),
    # Agent 0.2.0: proxies over TLS, a list of exits with failover, the run's
    # ID sent to the exit.
    ("internal/path/tls.go",
     "\t\tServerName:         host,\n",
     "\t\tServerName:         host,\n\t\tInsecureSkipVerify: true,\n",
     "a proxy's TLS certificate is no longer checked"),
    ("internal/path/tls.go",
     "\t\t\tpx.TLS.RootCAs = roots\n",
     "\t\t\t_ = roots\n",
     "the CA file is read but not used, so exits with a private CA are refused"),
    ("internal/path/tls.go",
     "\tt := strings.TrimSpace(string(b))\n",
     "\tt := string(b)\n",
     "the newline at the end of a token file is taken as part of the token"),
    ("internal/path/tls.go",
     '\tcase "407":\n\t\treturn errors.New("the exit refused the token")\n',
     "",
     "the health check passes an exit that refuses the token"),
    ("internal/path/tls.go",
     '"VPNW-Conn: " + strconv.FormatUint(x.conn.ID, 10)',
     '"VPNW-Conn: " + strconv.FormatUint(x.conn.ID+1, 10)',
     "the connection ID sent to the exit is off by one, so the records do not join"),
    ("internal/path/tls.go",
     'return x.conn.Run + "/" + strconv.FormatUint(x.conn.ID, 10)',
     'return strconv.FormatUint(x.conn.ID, 10) + "/" + x.conn.Run',
     "the SOCKS5 user name carries the run and connection IDs the wrong way round"),
    ("internal/path/path.go",
     "\tif p.TLS != nil {\n\t\tex = &exitIDs{conn: info}\n\t}\n",
     "\tex = &exitIDs{conn: info}\n",
     "the run's ID goes to every proxy, not only to exits reached over TLS"),
    ("internal/path/path.go",
     'if i := strings.LastIndex(raw, "@"); i > j {',
     'if i := strings.Index(raw, "@"); i > j {',
     "a password is shown when an @ comes before :// in a broken proxy URL"),
    ("internal/path/exits.go",
     "if err == nil || !isDown(err) || ctx.Err() != nil {",
     "if err == nil || ctx.Err() != nil {",
     "a refusal from an exit moves the list on to the next exit"),
    ("internal/path/exits.go",
     "\t\tif e.cur == i {\n\t\t\te.cur = next\n\t\t}\n",
     "",
     "after a switch, every new connection tries the dead exit first again"),
    ("internal/path/exits.go",
     "\tfor i := range e.List {\n\t\terr := <-results[i]",
     "\tfor i := len(e.List) - 1; i >= 0; i-- {\n\t\terr := <-results[i]",
     "the health check picks the last exit that answers instead of the first"),
    ("internal/path/exits.go",
     "if info != nil && info.Switched != nil && len(e.List) > 1 {",
     "if false && info != nil && info.Switched != nil && len(e.List) > 1 {",
     "a switch between exits leaves no event in the record"),
    ("internal/broker/broker.go",
     "ci := &path.Conn{Run: b.runID(), ID: id,",
     'ci := &path.Conn{Run: "", ID: id,',
     "the run's ID is not sent to the exit"),
    ("internal/broker/broker.go",
     '\t\tif ci.Exit != "" {\n\t\t\tof["exit"] = ci.Exit\n\t\t}\n',
     "",
     "the Agent's record no longer says which exit carried a connection"),
    ("cmd/vpnw/main.go",
     'p, err = path.Build("proxy", o.proxy, path.Options{',
     'p, err = path.Build("proxy", o.proxy[len(o.proxy)-1:], path.Options{',
     "a second --proxy replaces the first instead of making a list of exits"),
]

# Packages of the engines that share the module but have their own suites
# and planted bugs: Scope, Ledger, Lab and Exit, and the test network.
OTHERS = ("scope", "testnet", "ledger", "lab", "exit")


def run_suite():
    # The Agent's own packages.
    pkgs = [p for p in subprocess.run(["go", "list", "./internal/..."], capture_output=True, text=True, check=True).stdout.split()
            if not any(o in p for o in OTHERS)]
    unit = subprocess.run(["go", "test", "-count=1"] + pkgs, capture_output=True, text=True)
    if unit.returncode != 0:
        return False
    it = subprocess.run(["go", "test", "-count=1", "./test/integration/"], capture_output=True, text=True)
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
