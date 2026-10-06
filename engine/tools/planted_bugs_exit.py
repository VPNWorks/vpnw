#!/usr/bin/env python3
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

"""Plant realistic bugs in VPN Works Exit, one at a time, and check that its
tests catch each one. A bug the suite misses is a missing test. Run from the
engine directory:

    python3 tools/planted_bugs_exit.py            # all bugs
    python3 tools/planted_bugs_exit.py 3 7        # only bugs 3 and 7

Each bug is a (file, exact text, replacement, what it would break) tuple.
The file is restored after every run, even on Ctrl-C.
"""
import subprocess
import sys

X = "internal/exit/"
S = "internal/exit/server/"
C = "cmd/vpnw-exit/"
BUGS = [
    (S + "http.go",
     '\t_, pass, ok := strings.Cut(string(raw), ":")',
     '\tpass, _, ok := strings.Cut(string(raw), ":")',
     "the user name in Proxy-Authorization is taken for the token"),
    (S + "http.go",
     "\tcl := s.Config.Lookup(tok)\n\tif cl == nil {\n\t\ts.refuseAuth(peer, \"http-connect\"",
     "\tcl := s.Config.Lookup(tok)\n\tif cl == nil && tok != \"\" {\n\t\ts.refuseAuth(peer, \"http-connect\"",
     "a CONNECT that carries no token at all is not refused"),
    (S + "http.go",
     "\t\ttok = bearer(h.get(\"Authorization\"))",
     "\t\ttok = h.get(\"Authorization\")",
     "the health check keeps \"Bearer \" in front of the token, so a good token is refused"),
    (S + "http.go",
     "\t\t\t\tif seen[name] {",
     "\t\t\t\tif seen[name] && false {",
     "a request may carry two tokens or two run IDs, and the exit reads the first"),
    (S + "http.go",
     's.refuseAuth(peer, "http-connect", host, port, tokenReason(tok))',
     's.refuseAuth(peer, "http-connect", host, port, tokenReason(tok)+": "+tok)',
     "a refused token is written into the exit's record"),
    (X + "decide.go",
     "return plan.Request(cl.Policy, host, port, false, lookup)",
     "return plan.Request(cl.Policy, host, port, true, lookup)",
     "the exit decides as if names resolved elsewhere, so deny_private never sees where a name points"),
    (S + "server.go",
     "\tcase \"denied\":\n\t\treturn deny(pl.Rule, pl.Reason, pl.Text)\n",
     "",
     "the exit connects even when the client's policy refuses the destination"),
    (S + "server.go",
     "d := &path.Direct{Dialer: net.Dialer{LocalAddr: &net.TCPAddr{IP: src.AsSlice()}}}",
     "d := &path.Direct{}",
     "connections leave from the exit machine's default address, not the client's fixed one"),
    (X + "decide.go",
     "\t\t\tif x == a {",
     "\t\t\tif x == a || a.IsValid() {",
     "a client may leave from any address it asks for, another client's among them"),
    (S + "server.go",
     '\t\tf["client_run"], f["client_conn"] = ids.Run, ids.Conn\n\t}\n\ts.emit(events.ConnectionAttempt, id, f)\n\tdeny',
     '\t\tf["client_run"] = ids.Run\n\t}\n\ts.emit(events.ConnectionAttempt, id, f)\n\tdeny',
     "the exit's record leaves out the client's connection ID, so the records do not join"),
    (X + "ids.go",
     "\treturn FromHeaders(parts[0], parts[1], src)",
     "\treturn FromHeaders(parts[1], parts[0], src)",
     "the SOCKS5 user name's run and connection IDs are read the wrong way round"),
    (S + "server.go",
     "\tif req[1] != 0x01 {\n\t\ts.unsupported(",
     "\tif req[1] != 0x01 && req[1] != 0x02 {\n\t\ts.unsupported(",
     "SOCKS5 BIND is taken for CONNECT"),
    (S + "server.go",
     "\ts.downBytes.Add(down)\n",
     "",
     "the exit's totals stop counting the bytes sent back to clients"),
    (X + "config.go",
     "\t\tif o, dup := owner[cl.Source]; dup {",
     "\t\tif o, dup := owner[cl.Source]; dup && false {",
     "two clients may be given one fixed address"),
    (X + "config.go",
     "\t\t\tif err != nil || len(b) != 32 {",
     "\t\t\tif err != nil {",
     "a token hash of the wrong length is accepted"),
    (X + "config.go",
     "\t\tif !known(k, clientKeys) {",
     "\t\tif false && !known(k, clientKeys) {",
     "an unknown key in a client's table, such as a misspelled allow, is ignored"),
    (X + "config.go",
     "\tcase inline && cl.PolicyFile != \"\":",
     "\tcase false && inline && cl.PolicyFile != \"\":",
     "a client with a policy file and policy keys of its own silently uses the keys"),
    (X + "join.go",
     "\t\t\tcase final.port != c.port ||",
     "\t\t\tcase false && final.port != c.port ||",
     "the join accepts an exit record for another destination"),
    (X + "join.go",
     '\t\t\trow.Note = problem("%s to %s: the Agent reached exit %s, but no exit record has it"',
     '\t\t\trow.Note = fmt.Sprintf("%s to %s: the Agent reached exit %s, but no exit record has it"',
     "a connection the exits never recorded is not reported"),
    (X + "join.go",
     "\t\tcase x.clientRun != \"\" && runs[x.clientRun]:",
     "\t\tcase false && x.clientRun != \"\" && runs[x.clientRun]:",
     "an exit record of a connection the Agent never made goes unnoticed"),
    (C + "main.go",
     "\tfor _, a := range cfg.Sources() {\n\t\tl, err := net.Listen(",
     "\tfor _, a := range cfg.Sources()[:0] {\n\t\tl, err := net.Listen(",
     "serve starts although a source address is not on this machine"),
    (C + "main.go",
     "\tif refused > 0 {\n\t\treturn exitFound",
     "\tif refused < 0 {\n\t\treturn exitFound",
     "decide exits 0 although it refused a request"),
]


def run_suite():
    unit = subprocess.run(["go", "test", "-count=1", "./internal/exit/...", "./cmd/vpnw-exit/"], capture_output=True, text=True)
    if unit.returncode != 0:
        return False
    it = subprocess.run(["go", "test", "-count=1", "./test/exit/"], capture_output=True, text=True)
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
