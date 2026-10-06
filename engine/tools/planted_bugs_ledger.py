#!/usr/bin/env python3
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

"""Plant realistic bugs in Ledger, one at a time, and check that its tests
catch each one. A bug the suite misses is a missing test. Run from the engine
directory:

    python3 tools/planted_bugs_ledger.py            # all bugs
    python3 tools/planted_bugs_ledger.py 3 7        # only bugs 3 and 7

Each bug is a (file, exact text, replacement, what it would break) tuple.
The file is restored after every run, even on Ctrl-C or SIGTERM.
"""
import signal
import subprocess
import sys

L = "internal/ledger/"
C = "cmd/vpnw-ledger/"
BUGS = [
    (L + "hash.go",
     "\td.Write([]byte{leafPrefix})\n\td.Write(record)",
     "\td.Write(record)",
     "a record's hash has no leaf prefix, so a record can pose as a node of the tree"),
    (L + "hash.go",
     "b[0] = nodePrefix\n\tcopy(b[1:], left[:])\n\tcopy(b[33:], right[:])",
     "b[0] = nodePrefix\n\tcopy(b[1:], right[:])\n\tcopy(b[33:], left[:])",
     "the tree joins its two halves the wrong way round"),
    (L + "hash.go",
     "b[0] = chainPrefix\n\tcopy(b[1:], prev[:])",
     "b[0] = chainPrefix\n\tcopy(b[1:], leaf[:])",
     "a link of the chain ignores the link before it"),
    (L + "hash.go",
     "\t\t\tr = NodeHash(t.full[i], r)",
     "\t\t\tr = NodeHash(r, t.full[i])",
     "the root of a growing tree puts the smaller subtree on the left"),
    (L + "hash.go",
     "\tif m < k {\n\t\treturn append(AuditPath(leaves[:k], m), RootOf(leaves[k:]))",
     "\tif m <= k {\n\t\treturn append(AuditPath(leaves[:k], m), RootOf(leaves[k:]))",
     "proofs for the first leaf of a right subtree take the wrong side"),
    (L + "hash.go",
     "\t\tif fn&1 == 1 || fn == sn {",
     "\t\tif fn&1 == 1 {",
     "the proof checker fails for records on the right edge of an unbalanced tree"),
    (L + "hash.go",
     "\tif sn != 0 {\n\t\treturn Hash{}, errors.New(\"the path is too short for the tree\")\n\t}\n",
     "",
     "a proof with hashes missing from its path is not refused as too short"),
    (L + "key.go",
     "return \"k-\" + hex.EncodeToString(h[:4])",
     "return \"k-\" + hex.EncodeToString(h[1:5])",
     "key IDs are taken from the wrong bytes of the key's hash"),
    (L + "checkpoint.go",
     "\\nprev %s\\ntime %s\\nkey %s\\n\",\n\t\tc.Log, c.Seq, c.Size, c.Root, c.Chain, c.Prev, c.Time.UTC().Format(time.RFC3339), c.Key)",
     "\\nprev %s\\nkey %s\\n\",\n\t\tc.Log, c.Seq, c.Size, c.Root, c.Chain, c.Prev, c.Key)",
     "a checkpoint's time is not signed, so it can be moved"),
    (L + "checkpoint.go",
     "\tif c.Key != pub.ID {\n\t\treturn fmt.Errorf(\"signed by key %s, not by %s, the key given\", c.Key, pub.ID)",
     "\tif false && c.Key != pub.ID {\n\t\treturn fmt.Errorf(\"signed by key %s, not by %s, the key given\", c.Key, pub.ID)",
     "the verifier doesn't say which key signed: a wrong key reads as a forgery"),
    (L + "checkpoint.go",
     "\tif !ed25519.Verify(pub.Key, c.Message(), c.Sig) {",
     "\tif len(c.Sig) != ed25519.SignatureSize {",
     "signatures are never checked, only their length"),
    (L + "file.go",
     "\t\t\tcase c.Size != len(l.Leaves):",
     "\t\t\tcase c.Size > len(l.Leaves):",
     "a checkpoint moved after later records goes unnoticed"),
    (L + "file.go",
     "if want := len(l.Leaves) + 1; rec > want {",
     "if want := len(l.Leaves) + 1; rec > want+1 {",
     "a deleted line of the ledger goes unnoticed"),
    (L + "file.go",
     "\t\t\tif open {\n\t\t\t\tdone()\n\t\t\t}\n",
     "",
     "verify drops a last record that has no newline"),
    (L + "verify.go",
     "\tif c.Prev != prev {",
     "\tif c.Prev != prev && i == 0 {",
     "a checkpoint from another history can be spliced in after the first"),
    (L + "verify.go",
     "\trep.Problem = v.compare(trusted)\n\tif rep.Problem == nil {\n\t\trep.Problem = bad\n\t}",
     "\trep.Problem = bad\n\tif rep.Problem == nil {\n\t\trep.Problem = v.compare(trusted)\n\t}",
     "a damaged ledger hides the record that was changed before it"),
    (L + "verify.go",
     "\tcase recs < trusted:",
     "\tcase recs+1 < trusted:",
     "a records file with its last line cut off verifies"),
    (L + "verify.go",
     "\tcase recs > sealed && !tail:",
     "\tcase recs > sealed && tail:",
     "lines added after the last checkpoint pass as sealed"),
    (L + "verify.go",
     "\tfor _, w := range opt.Witness {",
     "\tfor _, w := range opt.Witness[:0] {",
     "checkpoints kept elsewhere are never compared, so a ledger cut back to a checkpoint passes"),
    (L + "verify.go",
     "\tcase j >= 0 && j == k:",
     "\tcase j >= 0 && j == k+1:",
     "two swapped lines are reported as something else"),
    (L + "verify.go",
     "\t\tif t.Root() == c.Root && t.Chain() == c.Chain {",
     "\t\tif false && t.Root() == c.Root && t.Chain() == c.Chain {",
     "a hash changed in the ledger is blamed on the records"),
    (L + "seal.go",
     "\tif err := CheckRecord(rec); err != nil {",
     "\tif err := CheckRecord(rec); err != nil && len(rec) == 0 {",
     "seal accepts lines that aren't JSON"),
    (L + "seal.go",
     "\t\tc.Seq, c.Prev = s.last.Seq+1, s.last.Hash()",
     "\t\tc.Seq = s.last.Seq + 1",
     "seal doesn't link a checkpoint to the one before"),
    (L + "seal.go",
     "\tif rep.Problem != nil {\n\t\treturn nil, rep.Problem\n\t}\n",
     "",
     "sealing again carries on from a ledger that doesn't verify"),
    (L + "seal.go",
     "\t\t\tif rec = rr.rest(); rec == nil {",
     "\t\t\tif rec = nil; rec == nil {",
     "seal leaves out a last line that has no newline"),
    (L + "seal.go",
     "\t\t\t\treturn n, err\n\t\t\t}\n\t\t\treturn n, s.Checkpoint()\n",
     "\t\t\t\treturn n, err\n\t\t\t}\n\t\t\treturn n, nil\n",
     "stopping seal --follow signs no last checkpoint"),
    (L + "seal.go",
     "\t\tif s.due() {\n\t\t\tif err := s.Checkpoint(); err != nil {\n\t\t\t\treturn n, err\n\t\t\t}\n\t\t}\n\t\tif err := shrunk(",
     "\t\tif err := shrunk(",
     "seal --follow signs no checkpoint while it waits for more lines"),
    (L + "seal.go",
     "\tif fi.Size() < pos {",
     "\tif fi.Size() < 0 {",
     "seal --follow doesn't notice the file being cut while it follows it"),
    (L + "proof.go",
     "\ti := len(led.Checkpoints) - 1\n",
     "\ti := 0\n",
     "prove uses the first checkpoint, which covers only the first records"),
    (L + "proof.go",
     "\tif LeafHash(p.Record) != p.Leaf {",
     "\tif LeafHash(p.Record) == (Hash{}) {",
     "check-proof never compares the record with the proof's hash"),
    (C + "main.go",
     "fi.Mode().Perm()&0o077 != 0",
     "fi.Mode().Perm()&0o007 != 0",
     "a private key readable by its group is used without a word"),
    (C + "main.go",
     "\t\tfmt.Fprintf(stdout, \"%v\\n%s is not intact.\\n\", rep.Problem, records)\n\t\treturn exitFound",
     "\t\tfmt.Fprintf(stdout, \"%v\\n%s is not intact.\\n\", rep.Problem, records)\n\t\treturn 0",
     "verify exits 0 when it finds tampering, so a script carries on"),
]


def run_suite():
    unit = subprocess.run(["go", "test", "-count=1", "./internal/ledger/...", "./cmd/vpnw-ledger/"], capture_output=True, text=True)
    if unit.returncode != 0:
        return False
    it = subprocess.run(["go", "test", "-count=1", "./test/ledger/"], capture_output=True, text=True)
    return it.returncode == 0


def main():
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(130))
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
