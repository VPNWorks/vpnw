#!/usr/bin/env python3
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

"""Turn the recorded Linux demo runs into the browser demo's replay data.

Input: the recordings directory written by `run-demo.sh --record=DIR`: one
transcript per step (N-name.txt) and one JSON Lines trace per vpnw command
(N-name-K.jsonl). Output: a JavaScript file with every step's transcript
lines and network events on one timeline.

Every vpnw line in a transcript is matched to the event in its trace that
produced it, so the diagram moves exactly when the line appears. The agent's
own lines are placed after the connection they report on. The replay is
slowed down for reading: the real runs each took about a tenth of a second.
The transcripts are kept exactly as recorded.

    python3 build_timeline.py RECORDINGS_DIR KIT_DEMO_DIR OUT.js
"""
import datetime
import glob
import json
import os
import re
import sys

REC, KIT, OUT = sys.argv[1], sys.argv[2], sys.argv[3]

# Narration, the same words as run-demo.sh.
SCENES = [
    ("trace", "See what the agent does", "net",
     "A coding agent runs a task. Its task file hides an instruction to send a deploy token to evil.example. "
     "First, run it under vpnw trace. Nothing is blocked yet, but every connection is recorded.",
     "Five connections. The ticket failed: tracker.office.internal is an internal name, unknown on the public "
     "internet. And the token went to evil.example. Nothing stopped it, but now there is a record."),
    ("learn", "Learn a policy from the trace", "policy",
     "vpnw learn turns the trace from step 1 into a draft policy: what the agent reached is allowed, everything "
     "else is denied.",
     "The draft allows evil.example too, because the agent went there, which is why a person reads it. It also "
     "notes the tracker, which the agent tried but could not reach on this path. The reviewed policy, agent.toml, "
     "drops evil.example and adds the tracker."),
    ("guard", "Guard: enforce the policy", "net",
     "The same agent, the same poisoned task, now under vpnw guard with the reviewed policy.",
     "The token is blocked and the attempt is logged. The rest of the agent's work goes through, except the "
     "ticket, which still fails because the tracker lives inside the office network. vpnw exits with 120 when it denied a "
     "connection, so a script or CI job notices."),
    ("route", "Route: this agent, through the office", "net",
     "vpnw run sends one program through the path you choose. Only this command goes through the office exit, "
     "not the whole machine. Then the agent again, with route, policy and record in one command.",
     "Every allowed step works, the ticket included. The token still goes nowhere: the policy is checked before "
     "the path is used."),
    ("seal", "Sealed: an agent that ignores proxy settings", "net",
     "Proxy settings are only a request. A program can skip them and connect directly. First without vpnw, then "
     "inside it.",
     "Inside vpnw, the program has no network of its own, and a seccomp filter stops it from opening a Unix socket "
     "to ask a local service such as Docker to connect for it. Its only way out is vpnw, and it never used it."),
    ("private", "Private addresses: the cloud metadata service", "net",
     "An agent tricked into reading a cloud metadata service can leak the machine's credentials. deny_private "
     "refuses loopback, private networks and the link-local range where those services live, even when the "
     "default is allow.",
     "Blocked before any connection was made. The program got a 403 from vpnw explaining why."),
]

GAP_LINE = 300      # ms between transcript lines
GAP_EVENT = 170     # ms for a network event that prints no line
GAP_CMD = 650       # after the command line itself
GAP_DENY = 800      # extra pause after a denial
TAIL = 900

LINE_RE = re.compile(r"^vpnw (\d\d):(\d\d):(\d\d)\.(\d{3})  (.*)$")
CONN_RE = re.compile(r"^#(\d+)\s+(.*)$")


def ms_of_day(h, m, s, ms):
    return ((int(h) * 60 + int(m)) * 60 + int(s)) * 1000 + int(ms)


def event_ms(ts):
    # "2026-09-29T11:15:58.83401443Z" -> ms of day (UTC), with fractions
    t = datetime.datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")
    frac = ts[20:-1] if "." in ts else "0"
    return (t.hour * 3600 + t.minute * 60 + t.second) * 1000 + float("0." + frac) * 1000


def parse_transcript(path):
    cmds, cur = [], None
    for raw in open(path).read().splitlines():
        if raw.startswith("$ "):
            cur = {"cmd": raw[2:], "lines": [], "exit": None}
            cmds.append(cur)
        elif raw.startswith("[exit ") and cur is not None:
            cur["exit"] = int(raw[6:-1])
        elif cur is not None:
            cur["lines"].append(raw)
    return cmds


def text_kind(rest):
    """Which trace event a vpnw text line reports, as (type, conn)."""
    m = CONN_RE.match(rest)
    if m:
        conn, body = int(m.group(1)), m.group(2)
        if body.startswith("→"):
            return "connection.attempt", conn
        if body.startswith("dns ") and (" = " in body or " failed:" in body):
            return "dns.result", conn
        if body.startswith("dns "):
            return "dns.query", conn
        if body.startswith("open"):
            return "connection.open", conn
        if body.startswith("close"):
            return "connection.close", conn
        if body.startswith("DENY"):
            return "policy.deny", conn
        if body.startswith("allow"):
            return "policy.allow", conn
        if body.startswith("error"):
            return "connection.error", conn
        return None, conn
    word = rest.split()[0]
    return {"trace": "run.start", "guard": "run.start", "run": "run.start", "start": "process.start",
            "exit": "process.exit", "summary": "run.end"}.get(word), 0


def net_event(e):
    """The fields the diagram needs from one trace event."""
    f = e.get("fields", {})
    t = e["type"]
    out = {"type": t, "conn": e.get("conn", 0), "path": e.get("path", "")}
    for k in ("host", "ip", "port", "proto", "rule", "reason", "error", "bytes_up", "bytes_down", "code", "mode"):
        if k in f:
            out[k] = f[k]
    if t == "dns.result" and "ips" in f:
        out["ips"] = f["ips"]
    if t == "run.start":
        out["remote_dns"] = f.get("remote_dns", False)
        if "policy" in f:
            out["policy"] = f["policy"].get("name")
    if t == "run.end":
        for k in ("connections", "opened", "denied", "failed"):
            out[k] = f.get(k, 0)
    return out


def classify(line):
    s = line.strip()
    if line.startswith("vpnw "):
        return "vpnw"
    if s.startswith("agent: ") and s.endswith(": done"):
        return "ok"
    if s.startswith("agent: ") and (s.endswith(": blocked") or s.endswith("could not reach it")):
        return "bad"
    if s.startswith("sneaky: token sent") or s.startswith("sneaky: token handed") or s.startswith("sneaky: connected"):
        return "bad"
    if s.startswith("sneaky: "):
        return "ok"
    return "out"


def timeline(cmd, trace):
    """Merge one command's transcript lines and trace events, then space them out."""
    items = []  # (real_ms, order, item)
    if trace:
        evs = [json.loads(l) for l in open(trace) if l.strip()]
        base_ev = event_ms(evs[0]["ts"])  # run.start
        first_line = next((l for l in cmd["lines"] if LINE_RE.match(l)), None)
        offset = 0.0
        if first_line:  # a quiet `vpnw run` prints no lines of its own
            m = LINE_RE.match(first_line)
            offset = ms_of_day(*m.groups()[:4]) - base_ev
            offset = round(offset / 60000.0) * 60000.0  # the time zone: whole minutes
        by_key = {}
        for i, e in enumerate(evs):
            t = event_ms(e["ts"]) + offset
            ev = net_event(e)
            items.append([t, 2 * i, {"k": "ev", "e": ev}])
            by_key.setdefault((e["type"], e.get("conn", 0)), []).append(t)
        # Final event of each connection, for the program's own lines.
        final = {}
        for i, e in enumerate(evs):
            if e["type"] in ("connection.close", "policy.deny", "connection.error"):
                c = e.get("conn", 0)
                if c not in final or e["type"] != "connection.close":
                    final.setdefault(c, event_ms(e["ts"]) + offset)
        start_t = by_key.get(("process.start", 0), [base_ev + offset])[0]
        exit_t = by_key.get(("process.exit", 0), [None])[0]
        step = 0
        last_t = start_t
        for j, line in enumerate(cmd["lines"]):
            m = LINE_RE.match(line)
            if m:
                typ, conn = text_kind(m.group(5))
                ts = by_key.get((typ, conn))
                t = ts.pop(0) + 0.001 if ts else ms_of_day(*m.groups()[:4])
                items.append([t, 1000 + j, {"k": "line", "text": line, "c": "vpnw"}])
                last_t = max(last_t, t)
                continue
            s = line.strip()
            if s.startswith("agent: ") and s not in ("agent: starting the task", "agent: finished"):
                step += 1
                t = final.get(step, last_t) + 0.002
            elif s == "agent: starting the task":
                t = start_t + 0.001
            elif s == "agent: finished" and exit_t:
                t = exit_t - 0.5
            else:
                # curl output, sneaky lines, vpnw's own messages: after the last connection event so far
                t = max([final[c] for c in final] + [start_t]) + 0.003 if final else start_t + 0.001 + j * 0.001
            last_t = max(last_t, t)
            items.append([t, 1000 + j, {"k": "line", "text": line, "c": classify(line)}])
        # Keep the transcript's order. A program's line is placed after the
        # connection it reports on, but never after a line that followed it
        # in the recording (a connection can close after the next one began).
        lines = [x for x in items if x[2]["k"] == "line"]
        lines.sort(key=lambda x: x[1])
        for j in range(len(lines) - 2, -1, -1):
            if lines[j][2]["c"] != "vpnw" and lines[j][0] >= lines[j + 1][0]:
                lines[j][0] = lines[j + 1][0] - 0.0001
        for j in range(1, len(lines)):
            if lines[j][0] <= lines[j - 1][0]:
                lines[j][0] = lines[j - 1][0] + 0.0001
    else:
        for j, line in enumerate(cmd["lines"]):
            items.append([j, j, {"k": "line", "text": line, "c": classify(line)}])
    items.sort(key=lambda x: (x[0], x[1]))
    replayed = [it["text"] for _, _, it in items if it["k"] == "line"]
    if replayed != cmd["lines"]:
        raise SystemExit("replay order differs from the recording in: " + cmd["cmd"])
    out = [{"t": 0, "k": "cmd", "text": "$ " + cmd["cmd"]}]
    t = GAP_CMD
    prev_deny = False
    for real, _, it in items:
        if it["k"] == "line":
            t += GAP_LINE + (GAP_DENY if prev_deny else 0)
            prev_deny = "DENY" in it["text"] or it["c"] == "bad"
        else:
            t += GAP_EVENT if it["e"]["type"] in ("connection.attempt", "connection.open", "dns.result", "connection.close", "policy.deny", "connection.error") else 40
        it["t"] = int(t)
        out.append(it)
    # A net event and the line that reports it appear together.
    for i in range(1, len(out)):
        if out[i]["k"] == "line" and out[i - 1]["k"] == "ev":
            out[i - 1]["t"] = out[i]["t"] - 60
    return out, int(t) + TAIL


def main():
    scenes = []
    for n, (sid, title, panel, intro, outro) in enumerate(SCENES, 1):
        txt = glob.glob(os.path.join(REC, "%d-*.txt" % n))[0]
        cmds = parse_transcript(txt)
        traces = sorted(glob.glob(os.path.join(REC, "%d-*-*.jsonl" % n)))
        k = 0
        out_cmds = []
        for c in cmds:
            words = c["cmd"].split()
            uses_trace = words[0] == "vpnw" and words[1] in ("run", "trace", "guard")
            trace = traces[k] if uses_trace else None
            k += 1 if uses_trace else 0
            items, dur = timeline(c, trace)
            sealed = uses_trace
            workload = next((w for w in words if w.endswith(".py") or w == "curl"), "")
            path = "office" if "--via" in words else "direct"
            out_cmds.append({"cmd": c["cmd"], "exit": c["exit"], "sealed": sealed, "vpnw": words[0] == "vpnw",
                             "workload": workload, "path": path, "items": items, "ms": dur})
        scenes.append({"id": sid, "no": n, "title": title, "panel": panel, "intro": intro, "outro": outro,
                       "commands": out_cmds})
    data = {
        "recorded": "2026-09-29",
        "engine": "0.1.0",
        "scenes": scenes,
        "trace1": open(sorted(glob.glob(os.path.join(REC, "1-*-1.jsonl")))[0]).read(),
        "policy": open(os.path.join(KIT, "agent.toml")).read(),
        "office": open(os.path.join(KIT, "office.toml")).read(),
        "task": open(os.path.join(KIT, "task.txt")).read(),
    }
    js = ("/* VPN Works Alpha live demo: the recorded runs. Generated by tools/build_timeline.py from\n"
          " * the transcripts and traces that run-demo.sh --record wrote on Linux; the lines are kept\n"
          " * exactly as recorded. */\n"
          "window.VPNW_DEMO = " + json.dumps(data, ensure_ascii=False, separators=(",", ":")) + ";\n")
    open(OUT, "w").write(js)
    total = sum(c["ms"] for s in scenes for c in s["commands"])
    print("wrote %s: %d scenes, %d commands, %.1f s of replay, %d bytes" % (
        OUT, len(scenes), sum(len(s["commands"]) for s in scenes), total / 1000, len(js)))


if __name__ == "__main__":
    main()
