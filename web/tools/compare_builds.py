#!/usr/bin/env python3
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

"""Compare the answers of two browser-engine builds, as printed by
battery.js. Answers that are objects come back from the engine as JavaScript
objects whose keys follow Go's map order, which changes from run to run, so
each answer is compared as parsed JSON, keys sorted.

    python3 compare_builds.py tinygo.jsonl go.jsonl
"""
import json
import sys


def deep(x):
    if isinstance(x, str):
        try:
            y = json.loads(x)
        except ValueError:
            return x
        return deep(y) if isinstance(y, (dict, list)) else x
    if isinstance(x, list):
        return [deep(i) for i in x]
    if isinstance(x, dict):
        return {k: deep(v) for k, v in x.items()}
    return x


def load(path):
    return [json.dumps(deep(json.loads(line)), sort_keys=True) for line in open(path) if line.strip()]


a, b = load(sys.argv[1]), load(sys.argv[2])
diff = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
for i in diff[:10]:
    print("answer %d differs:\n  %s\n  %s" % (i + 1, a[i][:300], b[i][:300]))
if len(a) != len(b):
    print("different number of answers: %d and %d" % (len(a), len(b)))
if diff or len(a) != len(b):
    sys.exit(1)
print("%d answers, all the same" % len(a))
