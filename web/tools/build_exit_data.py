#!/usr/bin/env python3
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

"""Turn the recorded run of the Exit demo into the page's replay data.

Input: the folder written by
    VPNW_EXIT_RECORD=DIR go test -run TestDemoScenario ./test/exit/
Output: a JavaScript file that sets window.VPNW_EXIT_DATA: the records as
they were written (the page's engine joins them itself), the configuration
and policy files, the stand-in DNS table, and a timeline in which each step
of the run is matched with what it left in the Agent's record, in the
exit's record and at the partner's server. Nothing is made up here: every
field of the timeline is copied from one of the recorded files.

    python3 build_exit_data.py RECORDING_DIR OUT.js
"""
import datetime
import json
import os
import sys

REC, OUT = sys.argv[1], sys.argv[2]


def read(name):
    with open(os.path.join(REC, name)) as f:
        return f.read()


def jsonl(name):
    return [json.loads(l) for l in read(name).splitlines() if l.strip()]


def ts(s):
    s = s.replace("Z", "+00:00")
    if "." in s:
        head, rest = s.split(".", 1)
        frac = "".join(c for c in rest if c.isdigit())
        tz = rest[len(frac):]
        s = head + "." + frac[:6].ljust(6, "0") + tz
    return datetime.datetime.fromisoformat(s)


marks = json.loads(read("marks.json"))
start = ts(marks["start"])


def rel(t):
    return round((ts(t) - start).total_seconds() * 1000)


# Which exit listens where, from the configuration files.
exit_names = {}
for name in ("exit-de", "exit-nl"):
    for line in read(name + ".toml").splitlines():
        if line.startswith("listen"):
            exit_names[line.split('"')[1]] = name


def agent_conns(name):
    """The connections in one Agent's record, in order."""
    out, by = [], {}
    run = None
    for e in jsonl(name + ".jsonl"):
        f = e.get("fields") or {}
        if e["type"] == "run.start":
            run = e["run"]
        c = e.get("conn", 0)
        if not c:
            continue
        if e["type"] == "connection.attempt":
            by[c] = {"run": e["run"], "conn": c, "t": rel(e["ts"]), "host": f.get("host") or f.get("ip"), "port": f.get("port")}
            out.append(by[c])
            continue
        a = by.get(c)
        if a is None:
            continue
        if e["type"] in ("policy.allow", "policy.deny"):
            a["decision"] = "allow" if e["type"] == "policy.allow" else "deny"
            a["rule"], a["text"], a["reason"] = f.get("rule"), f.get("text", ""), f.get("reason")
        elif e["type"] == "path.switch":
            a["switch"] = {"from": exit_names.get(f["from"], f["from"]), "to": exit_names.get(f["to"], f["to"]),
                           "ms": f.get("ms"), "error": f.get("error"), "t": rel(e["ts"])}
        elif e["type"] == "connection.open":
            a["opened"], a["exit"], a["ms"] = True, exit_names.get(f.get("exit"), f.get("exit")), f.get("ms")
        elif e["type"] == "connection.error":
            a["error"], a["exit"] = f.get("error"), exit_names.get(f.get("exit"), f.get("exit"))
    return run, out


exit_conns = []
for name in ("exit-de", "exit-nl"):
    by = {}
    for e in jsonl(name + ".jsonl"):
        f = e.get("fields") or {}
        c = e.get("conn", 0)
        if not c:
            continue
        if e["type"] == "connection.attempt":
            by[c] = {"exit": name, "conn": c, "t": rel(e["ts"]), "client": f.get("client"), "clientRun": f.get("client_run", ""),
                     "clientConn": f.get("client_conn", 0), "host": f.get("host") or f.get("ip"), "port": f.get("port"),
                     "proto": f.get("proto"), "peer": f.get("peer"), "outcome": ""}
            exit_conns.append(by[c])
            continue
        x = by.get(c)
        if x is None:
            continue
        if e["type"] == "dns.result":
            x["dns"] = f.get("ips") or f.get("error")
        elif e["type"] in ("policy.allow", "policy.deny"):
            x["rule"], x["text"], x["reason"] = f.get("rule"), f.get("text", ""), f.get("reason")
            if e["type"] == "policy.deny":
                x["outcome"] = "refused"
        elif e["type"] == "connection.open":
            x["outcome"], x["source"], x["ip"] = "open", f.get("source"), f.get("ip")
        elif e["type"] == "connection.error":
            x["outcome"], x["error"] = "failed", f.get("error")

hits = jsonl("servers.jsonl")


def server_hit(x, after):
    for h in hits:
        if h["Src"] == x.get("source") and h["Dst"] == x.get("ip") and h["Port"] == x.get("port") and rel(h["At"]) >= after - 5:
            return {"src": h["Src"], "dst": h["Dst"], "port": h["Port"], "t": rel(h["At"])}
    return None


runs, queues = {}, {}
for name in ("agent-1", "agent-2"):
    runs[name], queues[name] = agent_conns(name)
tampered = [x for x in exit_conns if x["client"] == "agent-2" and x["clientRun"] not in runs.values()]

timeline = []
for s in jsonl("steps.jsonl"):
    item = {"t": rel(s["t"]), "actor": s["actor"], "kind": s["what"], "target": s.get("target", ""), "result": s["result"]}
    if s["actor"] in queues:
        a = queues[s["actor"]].pop(0)
        item["agent"] = a
        item["target"] = "%s:%s" % (a["host"], a["port"])
        item["url"] = s["target"]
        finals = [x for x in exit_conns if x["clientRun"] == a["run"] and x["clientConn"] == a["conn"] and x["outcome"]]
        x = finals[-1] if finals else None
        item["exit"] = x
        if x and x["outcome"] == "open":
            item["server"] = server_hit(x, a["t"])
        if a.get("decision") == "deny":
            item["outcome"] = "refused at the Agent"
        elif x and x["outcome"] == "refused":
            item["outcome"] = "refused at the exit"
        elif a.get("opened"):
            item["outcome"] = "reached"
        else:
            item["outcome"] = "failed"
    elif s["actor"] == "tampered":
        x = tampered.pop(0)
        item["exit"] = x
        item["outcome"] = "refused at the exit" if x["outcome"] == "refused" else x["outcome"]
    else:
        item["outcome"] = "exit stopped"
    timeline.append(item)

data = {
    "recorded": marks["start"][:10],
    "startUTC": marks["start"],
    "killed": rel(marks["killed"]),
    "end": rel(marks["end"]),
    "runs": runs,
    "timeline": timeline,
    "files": {n: read(n) for n in ("agent-1.toml", "agent-2.toml", "ci.toml", "exit-de.toml", "exit-nl.toml")},
    "records": {n: read(n) for n in ("agent-1.jsonl", "agent-2.jsonl", "exit-de.jsonl", "exit-nl.jsonl")},
    "dns": json.loads(read("dns.json")),
}
js = ("/* VPN Works Exit demo: a run recorded on %s in a private test network, replayed by\n"
      " * the page. Made by web/tools/build_exit_data.py from web/exit/recording/. */\n"
      "window.VPNW_EXIT_DATA = %s;\n") % (data["recorded"], json.dumps(data, separators=(",", ":")))
with open(OUT, "w") as f:
    f.write(js)
print("wrote %s: %d bytes, %d steps" % (OUT, len(js), len(timeline)))
