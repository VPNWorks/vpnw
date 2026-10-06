# VPN Works Ledger Alpha

vpnw-ledger 0.1.0 keeps a record of every connection that can't be changed without it showing. Anyone with the public key can check the whole record offline, or check one connection without seeing the others.

Version 0.1, October 6, 2026.

Ledger is one of three engines built in parallel for this release of VPN Works. It takes a log of connections, such as the trace vpnw writes for an agent or the flows vpnw-scope records at a gateway, and seals it. The log stays exactly as it is. A second file next to it, the ledger, holds a hash for every line and, at intervals, a checkpoint signed with Ed25519. From then on, if a line is changed, deleted, inserted or moved, or the end is cut off, the check names the line. A proof of one connection can go to someone who gets nothing else.

Everything here ran on one Linux machine, a virtual machine with two CPUs. The logs are a real trace of the Agent, real flows from Scope's recorder at a gateway in a private test network, and generated logs of a million records. No auditor has used Ledger yet, and no company's own log has been sealed with it.

> **VPN Works keeps network access narrow and on the record.** The Agent gives each AI agent a network of its own. Scope gives each person on a company VPN only the systems they use. Lab checks that VPN apps keep traffic inside the tunnel when things go wrong. Ledger makes every record tamper-evident. Exit checks the policy again at the far end. The Agent and Scope exist today; Lab, Ledger and Exit are new in this release.

## Key figures

| Figure | What it means |
|---|---|
| 12 of 12 | Ways of changing a sealed log, each named by the check at the exact line the test expects. The seven set out before the build (one byte edited, a line deleted, a line inserted, two lines swapped, the end cut off, an old checkpoint replayed, the wrong key) and five more, among them changes to the ledger alone |
| 32 of 32 | Deliberately planted bugs caught by the tests |
| 640,120 and 982,065 | Records sealed per second: a million Agent events, a million Scope flows. Verifying them: 646,182 and 814,813 per second |
| 2,215 bytes | A proof that one record is in a log of a million records, the record included. It holds 20 hashes and is checked in 2 ms |
| 1,280 lines | Ledger's own Go code that verify and check-proof run, file formats included, besides the configuration reader the engines share: what an auditor would read |

All figures come from the final run of `tools/measure-ledger.sh` on October 6, 2026 (UTC), with a minute of fuzzing per target, on an idle machine. Section 9 lists the files.

## 1. Ledger in brief

| Area | Status | Key figures |
|---|---|---|
| Engine | Complete for the Alpha scope | One Go program, `vpnw-ledger`, standard library only. 2,599 lines of Go in 12 files, the browser build included; the command and its engine are 2,102 of them (computed from source.txt). It shares the Agent's configuration reader and changes nothing in the Agent or Scope |
| Input | Working | Any JSON Lines file: vpnw's trace, vpnw-scope's flows, later Exit's records. The file is never changed |
| Sealing | Working | Once, again later (it checks what was sealed, then carries on), or following a growing file like `tail -f` |
| Checking | Working | The whole log offline, naming the first bad line; one record by its proof; checkpoints kept elsewhere as witnesses |
| Tests | Extensive, on one machine | 50 test functions, 74 with subtests. 12 of 12 tamper cases caught. 32 of 32 planted bugs caught. About 12.2 million fuzzed inputs (computed from fuzz.txt). 98.2% of statements covered |
| Speed | Measured on one machine | 640,120 to 982,065 records sealed a second, 646,182 to 814,813 verified. A checkpoint costs 26 µs |
| Platforms | Linux x86-64, run and tested | arm64 Linux compiles, not run yet. macOS and Windows compile, not run |
| Demo | In the browser | Six steps on the Agent's recorded trace, run by Ledger's own code compiled to WebAssembly. The page gives the same hashes and lines as the command line |
| Readiness | TRL 4 | "Technology validated in lab", on the European Commission's scale |

## 2. How it works

### 2.1 Two files

The records stay in their own JSON Lines file, one record per line, untouched. A record is one line's bytes without the newline. Seal refuses a line that isn't one JSON value in UTF-8, or that is longer than 64 KiB, and names the file and line.

Ledger writes the ledger next to it, `RECORDS.ledger`, also JSON Lines and readable by eye: a header, a line per record with its number and hash, and a checkpoint after the last record it covers. The start of the ledger of the demo trace, from a seal made by hand for this report. The hashes are those of demo.txt; the key, the time and the signature are new with every seal:

```
{"vpnw-ledger":1,"log":"1-trace-1.jsonl"}
{"n":1,"leaf":"e7441873e021ed8974870ed67384a5d566725ecbf4987432e0e05befdbf9d339"}
{"n":2,"leaf":"fd0d9321e8a6222d6021c0b5ad6195a0901984bfed820fb982eebc61b24a8ded"}
...
{"n":8,"leaf":"8eb8a4ce49c7b59bbd211089be6abd2e4c39b96dc0a81b2fc58a09755397d31f"}
{"cp":1,"size":8,"root":"3190285b489233c6176fdcfd5410f325bce542f840967f8c8ba0c2d2b7d7c990","chain":"80511d1bc442ee24f2caa4dfc497dfff44e770e415d6a84c4f10daae916abe53","prev":"0000000000000000000000000000000000000000000000000000000000000000","time":"2026-10-05T21:37:32Z","key":"k-562a82dd","log":"1-trace-1.jsonl","sig":"p8wJKybBBuopJDwMHAYZDLtnpbvwfVOM+/10Q1c/XYitE1rq40Qzea8UbVD2EO16O86G549PR4hT8RUShYgtBw=="}
```

Seal writes record lines together with the checkpoint that covers them, in one write, so a complete ledger always ends with a checkpoint. Every line has exactly one form: the reader refuses anything else, and the fuzz tests check that what it reads, written out again, is the file itself.

### 2.2 Hashes

Three hashes, all SHA-256, each starting with a byte that says what it is, so that a record can never pass for a node of the tree or a link of the chain:

| Hash | Of | Use |
|---|---|---|
| Leaf | `0x00` and the record | One per record, in the ledger |
| Node | `0x01`, the left subtree's root and the right one's | The Merkle tree over the leaves, as RFC 6962 defines it |
| Chain | `0x02`, the link before and the leaf | Links each record to everything before it; the link before the first is 32 zero bytes |

The tree gives the proofs of section 2.6: a record and 20 hashes show it is in a log of a million records (perf.txt). The chain is the plain "linked to the one before" property, easy to recompute by hand. The tests check the tree against the RFC 6962 test vectors.

### 2.3 Checkpoints

Seal signs a checkpoint every N records (1,000 by default, 8 in the demo), at the end of every seal, and, when following a file, whenever a record has waited 10 seconds. The signature covers this text, which anyone can rebuild from the checkpoint's line and check with any Ed25519 tool. An example, the last checkpoint of the seal above:

```
vpnw-ledger checkpoint v1
log 1-trace-1.jsonl
cp 4
size 28
root 022a83034e598c35315df8fd2b8206c5f11e7b7ee330b6f93a084db29e5c841c
chain f43fef60081d109389f0186a8e17f9856286c406ef2bef1db4137f959ba454f9
prev 24f67df13d5105bc972d12a0bf2979bfc1f6fda9db9858c3fd8b3f9adc101a48
time 2026-10-05T21:37:32Z
key k-562a82dd
```

A checkpoint covers every record before it twice, by the tree's root and by the chain. Checkpoint numbers count up by one and each covers more records than the one before. `prev` is the SHA-256 of the previous checkpoint's text, so none can be dropped, replayed or moved without the check seeing it. The key ID is `k-` and the first 8 hex digits of the public key's SHA-256. The log's name is signed too, so a proof says which log a record is in when one key signs several logs.

### 2.4 Verify

Verify needs the records, the ledger and the public key. It trusts nothing in the ledger that a good checkpoint doesn't vouch for, and reports the first problem, in this order:

1. **The checkpoints**, in order. Each must be signed by the key given, carry the hash of the one before, and match the root and chain of the hashes sealed before it. What a good checkpoint covers is trusted.
2. **The records**, against their trusted hashes. The first record that doesn't match is the answer, and verify says what happened to it: changed, deleted (one record or several), inserted, swapped with another line, or moved.
3. **The ledger's own first problem**, a bad checkpoint or a line not as seal writes it. When the hashes in the ledger don't give a checkpoint's root, verify recomputes the root from the records. If the records give it, the ledger was edited, and verify names the ledger line. If they don't, a record was changed in both files, and verify names the checkpoint and the records it covers.
4. **The ends**: records cut off at the end, sealed records that no checkpoint covers, and lines never sealed.
5. **Witnesses**: checkpoints kept elsewhere, given with `--witness`. The ledger must hold each one as it is.

The answer names the file and line, as in `1-trace-1.jsonl:25: the record doesn't match its sealed hash: it was changed`. Section 4.1 has one answer for each kind of change.

### 2.5 What the two files can't show, and the witness

One change can't be caught from the two files alone: both cut back to an earlier checkpoint, records and ledger together. What is left is a shorter log that checks out. That holds for any log that signs its own checkpoints. Whoever holds the private key can also seal a changed log again from the start.

The answer is a witness. Seal prints every checkpoint it signs on standard output, one line each, so a copy can go where the person holding the files can't reach: a remote system log (`vpnw-ledger seal --follow ... | logger -t ledger`), a ticket, the auditor's mail. `verify --witness FILE` reads checkpoints from any file, system log lines included, checks that the key signed them, and the ledger must hold each one. A ledger cut back before a witnessed checkpoint fails with "the end was cut off", and a ledger signed again differs from the witness at the first checkpoint it changed. The last row of the tamper matrix (section 4.1) is this case.

### 2.6 Proofs

`prove --line N` writes a proof that the record on line N is in the log: the record, its leaf hash, the audit path (RFC 6962's PATH) to the root of the ledger's last checkpoint, and that checkpoint, signed. `check-proof` needs the proof and the public key, nothing else: it checks the signature, the record's hash, and that the path leads from that hash at that line to the signed root. A proof at a million records holds 20 hashes and is 2,215 bytes, the record included.

### 2.7 Following a growing file

`seal --follow` reads the records file like `tail -f`. It seals each line once its newline is written, signs a checkpoint every N records and whenever a record has waited the interval, and on Ctrl-C or SIGTERM seals the complete lines already written and signs a last checkpoint. A line still being written is left for the next seal. If the file gets shorter while it is followed, seal stops with exit code 120.

Run again on a ledger that exists, seal first verifies everything sealed before, with the key it signs with, and only then carries on. If a sealed record changed, or the last sealed record grew after it was sealed, nothing more is sealed.

### 2.8 Keys

`keygen -o NAME` writes `NAME.key`, the 32-byte Ed25519 seed (mode 0600), and `NAME.pub`, the public key. Both are small files in the same strict TOML subset as the other VPN Works files, read by the Agent's configuration reader, so every error names the file and line. Seal refuses a private key that its group or others can read (on Unix), and keygen never writes over a key. Seal locks the ledger, so two seals can't write it at once (on Unix).

### 2.9 How it is built

| Part | File or package | Lines of Go |
|---|---|---|
| Hashes, the tree, audit paths | internal/ledger/hash.go | 212 |
| Key files | internal/ledger/key.go | 161 |
| Checkpoints: signed text, JSON line, strict reader | internal/ledger/checkpoint.go | 161 |
| The ledger file and reading records | internal/ledger/file.go | 330 |
| Verify | internal/ledger/verify.go | 277 |
| Proofs | internal/ledger/proof.go | 139 |
| Seal and follow | internal/ledger/seal.go | 233 |
| The tamper matrix, for the tests and the demo | internal/ledger/tamper | 170 |
| The command line | cmd/vpnw-ledger | 589 |
| The browser build | wasm/ledger | 327 |
| The configuration reader, shared with the Agent | internal/config | unchanged |

Lines of Go without tests, from source.txt. Each file starts with the two-line license header and a blank line, three lines counted here. What verify and check-proof run of Ledger's own code, with the file formats, is all of internal/ledger but seal.go: 1,280 lines. They also use the configuration reader the engines share, for key files, and the command line around them. The tests add 2,610 lines.

### 2.10 Changes from the design guidance

| The guidance | What Ledger does | Why |
|---|---|---|
| A ledger line per record, checkpoint lines at intervals | The same, but record lines are written together with the checkpoint that covers them | A complete ledger always ends with a checkpoint. A ledger that doesn't was cut, or seal was stopped while writing, and verify says so |
| The previous-checkpoint hash catches a replayed or moved checkpoint | It does, and `--witness` adds checkpoints kept elsewhere | Both files cut back to a checkpoint can't show in the two files (section 2.5) |
| A proof holds the record's leaf, its index, the audit path and the checkpoint | It holds the record too, and the line number instead of the index | The auditor reads the connection in the same file; line numbers are what people see. `check-proof` still takes the record from a separate file when given one |
| Checkpoint fields as listed | Plus the log's name, signed | A proof says which log a record is in when one key signs several logs |
| Verify names the first bad line | It also says which file changed when a checkpoint doesn't match | An auditor needs to know whether the record or the ledger was edited |

## 3. Using it

### 3.1 Commands

| Command | What it does |
|---|---|
| `vpnw-ledger keygen -o NAME` | Writes NAME.key, the private key that signs, and NAME.pub, the public key for whoever checks |
| `vpnw-ledger seal --key FILE RECORDS` | Writes RECORDS.ledger, or carries it on after checking it, and prints each checkpoint it signs. `--every N` sets the checkpoint interval in records, `--log NAME` the log's name, `--ledger FILE` another ledger path |
| `vpnw-ledger seal --follow --key FILE RECORDS` | Seals lines as they are written until stopped; `--interval D` (default 10s) is the longest a record waits for its checkpoint |
| `vpnw-ledger verify --pub FILE RECORDS` | Checks the records against the ledger and the public key, and names the first problem. `--witness FILE` adds checkpoints kept elsewhere |
| `vpnw-ledger prove --line N RECORDS` | Writes a proof that line N is in the log, to standard output or `-o FILE` |
| `vpnw-ledger check-proof --pub FILE PROOF [RECORD]` | Checks a proof with the public key alone; given a RECORD file, it checks that record instead of the proof's own |
| `vpnw-ledger version` | Prints the version |

### 3.2 Exit codes

| Code | Meaning |
|---|---|
| 0 | Intact, or done |
| 120 | The check found something: a line changed, deleted, inserted, moved or never sealed, an end cut off, a checkpoint that doesn't hold, or a proof that doesn't. Seal returns it too when the ledger it would carry on doesn't verify, or the file it follows gets shorter |
| 121 | A usage error, or an error in an input file, with the file and line where there is one, such as a line that isn't JSON or a private key others can read |
| 124 | Any other failure, such as a ledger another seal holds |

Ledger needs nothing particular from the machine, so it never returns 122.

### 3.3 An example

From the final run's demo.txt, then one byte changed in line 25 (the address the token went to):

```
$ vpnw-ledger keygen -o agent
$ vpnw-ledger seal --key agent.key --every 8 1-trace-1.jsonl
vpnw-ledger: sealed 28 new records of 1-trace-1.jsonl. 1-trace-1.jsonl.ledger holds 28 records under 4 checkpoints signed by k-b167e740.
$ vpnw-ledger verify --pub agent.pub 1-trace-1.jsonl
1-trace-1.jsonl is intact: 28 records, all sealed and signed. 4 checkpoints signed by k-b167e740; the last was signed 2026-10-06 03:43:01 UTC.
$ sed -i '25s/45.77.10.10/45.77.10.11/' 1-trace-1.jsonl
$ vpnw-ledger verify --pub agent.pub 1-trace-1.jsonl
1-trace-1.jsonl:25: the record doesn't match its sealed hash: it was changed
1-trace-1.jsonl is not intact.
$ echo $?
120
```

The four checkpoint lines seal prints are left out above. The last three commands were run again by hand for this report, on a fresh seal.

## 4. Tests

Every test runs on Linux against the real code. There are 50 test functions: 38 in internal/ledger (seven of them fuzz targets, run on their seed inputs), 3 for the tamper matrix, 7 for the command line, and 2 live tests that run the real vpnw and vpnw-scope. All pass.

| Suite | What it checks | Result |
|---|---|---|
| Unit tests | The tree against the RFC 6962 test vectors, and every leaf of every tree up to 70 leaves; key files; that every field of a checkpoint is signed; the ledger reader, line by line; reading records; seal, sealing again, and refusals; follow mode with a writer goroutine and a clock the test moves; each finding of verify; proofs for every line of logs of 1 to 37 records; the command line, its errors and exit codes | 48 test functions; all passed |
| Tamper matrix | 12 ways of changing a sealed log, through the engine and through `vpnw-ledger verify`, each with the exact file and line the answer must name | 12 of 12 caught |
| Live: the Agent | A program under `vpnw trace` opens 12 connections while `seal --follow` seals the trace as vpnw writes it; SIGTERM stops seal | 40 events sealed under 3 checkpoints; intact; the proof of line 22 checks |
| Live: Scope | 30 connections through a test gateway in network namespaces, recorded by `vpnw-scope record`, while `seal --follow` seals the flows | 30 flows sealed under 3 checkpoints; intact; the proof of line 30 checks |
| Race detector | Every suite above | Clean |
| Fuzzing | Seven readers and the properties of section 4.3, a minute each | 12,197,421 inputs (computed from fuzz.txt), no failure |
| Planted bugs | 32 deliberate bugs, one at a time | 32 of 32 caught |
| Coverage | All the tests together, with the command run by the live tests | 98.2% of statements |

Coverage by part: internal/ledger 99.2%, the tamper matrix 98.8%, the command line 95.9%.

### 4.1 The tamper matrix

The Agent's recorded run (28 events) sealed with a checkpoint every 8 records, then changed around line 25, its connection to evil.example, one case at a time. The table is tamper.txt, what `vpnw-ledger verify` printed; the records file is named trace.jsonl there.

| Case | What vpnw-ledger verify said | Caught |
|---|---|---|
| one byte edited | trace.jsonl:25: the record doesn't match its sealed hash: it was changed | yes |
| a line deleted | trace.jsonl:25: a record is missing here: the one sealed as line 25 was deleted | yes |
| a line inserted | trace.jsonl:25: this line was never sealed: it was inserted | yes |
| two lines swapped | trace.jsonl:25: lines 25 and 26 were swapped | yes |
| the end cut off | trace.jsonl:25: the file ends after line 24, but checkpoint 4 covers 28 records: the end was cut off | yes |
| an old checkpoint replayed | trace.jsonl.ledger:33: checkpoint 1 again, where checkpoint 4 should be: an old checkpoint was replayed or moved here | yes |
| the wrong key | trace.jsonl.ledger:10: checkpoint 1: signed by key k-1e979e76, not by k-2a7ff4dd, the key given | yes |
| a record and its sealed hash changed together | trace.jsonl.ledger:33: checkpoint 4 doesn't match records 25 to 28: one of them was changed, and its hash in the ledger with it | yes |
| a sealed hash changed | trace.jsonl.ledger:29: the hash sealed for record 25 was changed: the record itself still matches checkpoint 4 | yes |
| a checkpoint's time moved back | trace.jsonl.ledger:33: checkpoint 4: the signature doesn't match key k-1e979e76: the checkpoint was changed or forged | yes |
| a line added after the last checkpoint | trace.jsonl:29: this line was never sealed: it came after the last checkpoint | yes |
| both files cut back to a checkpoint, checked with a witness | trace.jsonl:25: the end was cut off: the ledger ends at checkpoint 3, but checkpoint 4 in witness.log line 1 covers 28 records; it was signed 2026-10-06 03:38:34 UTC | yes |

The keys are made new for each run, so key IDs and times differ between runs; the lines never do. The same matrix runs on a generated log of 100 records with a checkpoint every 10, changed around line 57, and in the browser demo. Without the witness, the last case verifies as intact: that is the limit of section 2.5, and a test keeps it in view.

### 4.2 Planted bugs

To check the tests themselves, 32 bugs were put into the code on purpose, one at a time, and the tests were run against each. A bug counts as caught only if a test fails. All 32 were caught.

| | Planted bug | Part |
|---|---|---|
| 1 | A record's hash has no leaf prefix, so a record can pose as a node of the tree | Hashes |
| 2 | The tree joins its two halves the wrong way round | Hashes |
| 3 | A link of the chain ignores the link before it | Hashes |
| 4 | The root of a growing tree puts the smaller subtree on the left | Hashes |
| 5 | Proofs for the first leaf of a right subtree take the wrong side | Hashes |
| 6 | The proof checker fails for records on the right edge of an unbalanced tree | Hashes |
| 7 | A proof with hashes missing from its path isn't refused as too short | Hashes |
| 8 | Key IDs are taken from the wrong bytes of the key's hash | Keys |
| 9 | A checkpoint's time isn't signed, so it can be moved | Checkpoints |
| 10 | The verifier doesn't say which key signed: a wrong key reads as a forgery | Checkpoints |
| 11 | Signatures are never checked, only their length | Checkpoints |
| 12 | A checkpoint moved after later records goes unnoticed | Ledger reader |
| 13 | A deleted line of the ledger goes unnoticed | Ledger reader |
| 14 | Verify drops a last record that has no newline | Reading records |
| 15 | A checkpoint from another history can be spliced in after the first | Verify |
| 16 | A damaged ledger hides the record that was changed before it | Verify |
| 17 | A records file with its last line cut off verifies | Verify |
| 18 | Lines added after the last checkpoint pass as sealed | Verify |
| 19 | Checkpoints kept elsewhere are never compared, so a ledger cut back to a checkpoint passes | Verify |
| 20 | Two swapped lines are reported as something else | Verify |
| 21 | A hash changed in the ledger is blamed on the records | Verify |
| 22 | Seal accepts lines that aren't JSON | Seal |
| 23 | Seal doesn't link a checkpoint to the one before | Seal |
| 24 | Sealing again carries on from a ledger that doesn't verify | Seal |
| 25 | Seal leaves out a last line that has no newline | Seal |
| 26 | Stopping `seal --follow` signs no last checkpoint | Follow |
| 27 | `seal --follow` signs no checkpoint while it waits for more lines | Follow |
| 28 | `seal --follow` doesn't notice the file being cut while it follows it | Follow |
| 29 | Prove uses the first checkpoint, which covers only the first records | Proofs |
| 30 | `check-proof` never compares the record with the proof's hash | Proofs |
| 31 | A private key its group can read is used without a word | Command line |
| 32 | Verify exits 0 when it finds tampering, so a script carries on | Command line |

### 4.3 Fuzzing

Each target got a minute of Go's fuzzer, with no failure. Each checks a property, more than "no crash":

| Target | What must hold | Inputs |
|---|---|---|
| FuzzParseKey | A key file that reads gives a key whose ID matches it, and a private key that signs | 2,301,180 |
| FuzzParseCheckpoint | A checkpoint is read only in the one form seal writes | 1,978,291 |
| FuzzReadLedger | A ledger that reads cleanly, written out again, is the file itself | 1,554,443 |
| FuzzReadWitness | Only checkpoints the key really signed come back from a witness file | 1,907,854 |
| FuzzSealVerify | Whatever seal accepts verifies, and every line of it has a proof that checks | 1,247,926 |
| FuzzVerify | Without the key, no change to a sealed log verifies except both files cut back to a checkpoint; with the last checkpoint as a witness, not even that | 1,375,275 |
| FuzzProof | A proof that checks says something true about the sealed log | 1,832,452 |

### 4.4 Defects found and fixed

Building and testing Ledger turned up these defects. All are fixed, and each is covered by a test or by the measurement script.

| | Defect | Found by | Effect before the fix |
|---|---|---|---|
| 1 | A missing `--key` or `--pub` ended with exit code 124 | The command line's error table | A script would read a usage error as a failure |
| 2 | A proof laid out again by a JSON tool, with its keys reordered, was refused | The proof file test | An auditor who opened and saved a proof in a JSON tool couldn't check it |
| 3 | Checkpoint 1 in the place of checkpoint 2 gave "checkpoint 1 again, after checkpoint 1" | Reading the tests' output | A confusing message; it now says "where checkpoint 2 should be" |
| 4 | A long line in a witness file gave the Go scanner's "token too long" | A unit test | An unclear error |
| 5 | Four gaps in the tests: a checkpoint moved after later records, a forged checkpoint hiding a record changed before it, a private key its group can read, and a follow test with no deadline | Planted bugs 12, 16, 31 and 22 | The first three bugs went uncaught; the fourth made the test wait 10 minutes |
| 6 | On phones, long "Next" labels were cut off inside their buttons | The demo's screenshots | Unreadable labels at 390 px. The page-wide overflow check passed, since text clipped inside a button doesn't widen the page; the demo check now measures every button's label |
| 7 | Two fuzz targets ran 6 inputs in 10 seconds | The first measurement run | Go spent the time shrinking each new whole-file input; the script now caps that at 100 runs an input |

### 4.5 What the tests don't cover yet

- **A long follow on a busy log.** The follow tests run for seconds, with hundreds of lines. A gateway's daily load, and log rotation (which Ledger doesn't follow), are untested.
- **A crash in the middle of a write.** A power loss can leave half a batch at the end of the ledger. Verify reports it, and seal won't carry on until the ledger is cut back to its last checkpoint by hand. This is not simulated in the tests.
- **Real witnesses.** The witness is any file of checkpoint lines; no remote log server took part.
- **Keys.** Keys are files on the sealing machine. No hardware key, no rotation, no revocation.
- **Size.** A million records per file is the largest measured.
- **Other machines.** One kernel (Linux 6.18) on x86-64. The arm64, macOS and Windows builds compile and haven't run.
- **Time.** Fuzzing ran a minute per target.
- **Independent review.** Every test was written by the people who wrote the code.

## 5. Speed and size

All figures from the same machine: two CPUs, Linux 6.18 on x86-64, Go 1.24.7. Each time is the median of three runs of the `vpnw-ledger` command, reading and writing files, and memory the highest of the three. Seal signs a checkpoint every 1,000 records, the default.

| Measure | Agent events | Scope flows |
|---|---|---|
| The log: 1,000,000 records | 188,502,480 bytes: the Agent's recorded run repeated as new runs, with new run IDs, times and connection numbers (generated) | 94,167,803 bytes: the first million flows of a generated 2,000-person office (generated) |
| Seal | 1.56 s, 640,120 records a second, peak memory 12 MB | 1.02 s, 982,065 records a second, peak memory 12 MB |
| The ledger | 87,302,720 bytes, 46% of the records; 1,000 checkpoints | 87,302,720 bytes, 93% of the records; 1,000 checkpoints |
| Verify | 1.55 s, 646,182 records a second, peak memory 163 MB | 1.23 s, 814,813 records a second, peak memory 156 MB |

| Measure | Result |
|---|---|
| A checkpoint at a million records | 26 µs: the root from the tree's 7 complete subtrees, the signed text, the Ed25519 signature and the JSON line (Go benchmark, median of three); 414 bytes per checkpoint line |
| A proof at 1,000 records (line 500) | 10 hashes; 1,517 bytes with the 182-byte record; made in 3 ms, checked in 2 ms |
| A proof at 1,000,000 records (line 500,000) | 20 hashes; 2,215 bytes with the 157-byte record; made in 852 ms (it reads the 87 MB ledger; peak memory 126 MB), checked in 2 ms |
| The demo trace, in the browser | 28 records sealed in 15 ms, in headless Chromium (demo-check.txt) |

Seal keeps only the tree's frontier and the batch waiting for its checkpoint, so its memory stays flat. Verify holds every hash in memory, 32 bytes a record for each of the two files, and prove holds the ledger's: at a million records, verify peaked at 156 MB and 163 MB and prove at 126 MB.

| Build | Size | Compressed (gzip -9) |
|---|---|---|
| Linux x86-64 | 2,715,832 bytes | 1,155,303 bytes |
| Linux arm64 | 2,621,624 bytes | 1,061,925 bytes |
| macOS, Intel and Apple silicon; Windows x86-64 | Compile, every command | |
| Browser engine (TinyGo, WebAssembly) | 901,281 bytes | 338,058 bytes |

TinyGo's WebAssembly target supports crypto/ed25519 and crypto/sha256; that was checked first, before the engine was written. Ed25519 is fast enough in the browser for the demo: the page makes its keys and seals the 28 records in 15 ms (demo-check.txt).

## 6. Features and limits

| Feature | What 0.1.0 supports | Limits |
|---|---|---|
| Input | Any JSON Lines file: one JSON value per line, in UTF-8, up to 64 KiB a line | Blank lines are refused. One file per ledger |
| Sealing | Once, again later, or following a growing file | Log rotation isn't followed. One seal per ledger, kept by a lock on Unix only |
| Checkpoints | Ed25519, every N records, at the end of every seal, and on an interval when following | The time comes from the sealing machine's clock |
| Checking | The whole log offline, naming the first bad line; one record by its proof | Verify holds 64 bytes per record in memory |
| Witnesses | Any file holding checkpoint lines, system logs included | No built-in way to send checkpoints out. No consistency proofs between two checkpoints yet (RFC 6962 section 2.1.2); a witness is compared whole |
| Keys | A private key file, refused if its group or others can read it, and a public key file | No rotation, revocation or hardware keys |
| Size | About 87 bytes of ledger per record (computed from perf.txt) | Hex hashes, readable by eye: the ledger is about as big as a file of Scope's short flows |
| Platforms | Linux x86-64 | arm64 compiles and hasn't run. macOS and Windows compile and haven't run |

## 7. The demo

The demo is the Agent's recorded run from step 1 of the Agent's own demo: a coding agent whose task file told it to send a deploy token to evil.example, and which did. The page seals that trace with a key it makes in the browser, and lets the visitor try to hide the connection. Ledger's own Go code, compiled to WebAssembly with TinyGo, does every hash, check and proof, and gives the same hashes and lines as the command line on the same file.

| Step | On the page | What it shows |
|---|---|---|
| 1 | The record | The 28 events of the run recorded on September 29, 2026. Lines 22 to 26 are the connection to evil.example: 865 bytes sent |
| 2 | Seal it | A key made in the page, and the trace sealed with a checkpoint every 8 records: 4 checkpoints, the same roots and chains as demo.txt, and the text the last checkpoint signs |
| 3 | Change it | Five changes, and free editing. The check names line 25 for a byte changed, a line deleted or two swapped, and line 22 for the whole connection deleted or the end cut off |
| 4 | Every kind of change | The twelve cases of the tamper matrix, run by the page's engine: all caught at the lines of section 4.1 |
| 5 | Prove one connection | A proof of line 25: 4 hashes, 1,087 bytes, checked with the public key alone. A changed record in the proof, and another key, fail |
| 6 | Cut at a checkpoint | Both files cut back to checkpoint 3 check out on their own; checkpoint 4, kept as a witness, catches the cut at line 25 |

What is real: the code, the recorded trace, and the results. What was made for the demo: the keys, made in the visitor's browser and never sent anywhere (so the key ID and signatures differ from the report's, while the hashes don't), and the run's servers and attacker, stand-ins in a private test network as in the Agent's demo. The page makes no network requests.

A headless Chromium check, `web/tools/check_ledger_demo.js`, plays the page at computer and phone widths and compares its hashes, lines and verdicts with the command line's: 67 checks, all passed, no horizontal overflow at 390 px, no console errors and no network requests (demo-check.txt). `web/tools/ledger_battery.js` runs the same engine under Node and prints the numbers of demo.txt and tamper.txt (demo-browser.txt).

## 8. Where it stands

### 8.1 Maturity by part

| Part | Maturity | Evidence | Gap to close |
|---|---|---|---|
| Hashes and the tree | Working, tested | RFC 6962 test vectors; every leaf of trees up to 70 leaves; 7 planted bugs caught | Consistency proofs between two checkpoints |
| Checkpoints and keys | Working | Each field shown to be signed; 4 planted bugs caught | Key rotation, revocation, hardware keys |
| Seal | Working | Sealing again, refusals; 4 planted bugs caught | Carrying on after a half-written batch |
| Follow | Working on one machine | A writer goroutine; the real vpnw trace and vpnw-scope flows; 3 planted bugs caught | Log rotation; a long run on a busy log |
| Verify | Working | 12 of 12 tamper cases; fuzzed; 9 planted bugs caught | A streaming verifier for logs of hundreds of millions of records |
| Proofs | Working | Every line of logs of 1 to 37 records; fuzzed; 2 planted bugs caught | None found so far |
| Witnesses | Working, by hand | The last tamper case; fuzzed; 1 planted bug caught | A built-in way to send checkpoints out |
| Browser demo | Working | Same hashes and lines as the command line; 67 headless checks | None found so far |
| Use by a real auditor | None | None | A pilot |

### 8.2 Readiness level

On the European Commission's technology readiness scale, which runs from TRL 1 to TRL 9, Ledger 0.1.0 sits at TRL 4, "technology validated in lab". It works and has sealed the real output of the Agent and of Scope's recorder as it was written, in a private test network, and every kind of change tried was caught. A pilot, where a team seals its agents' traces for some weeks and an auditor checks them, would take it to TRL 5.

### 8.3 How far from a first release

An estimate, and only an estimate: Ledger is about a third of the way to a first release. The core is small and checked. What's left: sealing built into vpnw and vpnw-scope as they write, instead of a second process; a way to send checkpoints to a witness, with consistency proofs; key rotation and revocation; recovery after a crash in the middle of a write; log rotation; a streaming verifier for very large logs; packages; and an outside review of the format and the code.

### 8.4 Technical risks

- **The key.** Whoever holds the private key can sign a new history. The key should belong to an account the agent doesn't run as, and witnesses limit the damage to checkpoints not yet sent out.
- **The cut at a checkpoint.** Without a witness, both files cut back to a checkpoint check out. Most of the protection against someone who holds the files rests on witnesses being used.
- **Size.** The ledger adds about 87 bytes a record (computed from perf.txt), about as much as a Scope flow. A binary ledger would be smaller; the design asked for one readable by eye.
- **Memory.** Verify and prove peaked at 126 MB to 163 MB for a million records (measured). Logs of hundreds of millions of records need a streaming verifier.
- **Time.** Checkpoint times come from the sealing machine's clock. They are signed, but nothing checks them against another clock; a witness keeps its own times.
- **A crash mid-write.** A power loss can leave half a batch, and seal then stops until someone cuts the ledger back to its last checkpoint.

## 9. Reproducing the figures

Every figure in this document comes from the final run of one script, `FUZZTIME=60s tools/measure-ledger.sh`, from the engine folder, on October 6, 2026 (UTC). It ran on an idle machine, one engine at a time, and took about 13 minutes. The script writes results/ledger-alpha:

| File | What it holds |
|---|---|
| environment.txt | Date, kernel, CPUs, and the Go, TinyGo, Python, nftables and Node versions |
| size.txt | Sizes for each build, compressed and not, the platforms that compile, and third-party modules: 0 |
| source.txt | Lines of Go per part and per file, and lines of tests |
| tests.txt, tests.json | Every test and subtest with its result |
| race.txt | The suites under the race detector |
| coverage.txt | Coverage per part and in total |
| fuzz.txt | Inputs per fuzz target |
| tamper.txt | The tamper matrix through the command line |
| live.txt | The live tests: the real vpnw trace and vpnw-scope flows, sealed as they were written |
| planted-bugs.txt | Each planted bug and whether a test caught it |
| perf.txt | Seal, verify, checkpoints and proofs at a million records |
| demo.txt | The demo trace sealed, verified and proved with the command line |
| demo-browser.txt, demo-check.txt | The browser engine's answers, and the headless check of the page |

The tools: tools/planted_bugs_ledger.py, tools/ledger_perf.py, web/tools/build_ledger_js.py, web/tools/ledger_battery.js and web/tools/check_ledger_demo.js. The demo's recording is recordings/1-trace-1.jsonl, made with the Agent's demo kit (kit/demo/run-demo.sh, step 1).

## 10. License

VPN Works is open source under the Apache License 2.0. Copyright VPNW.com 2026. The code is at https://github.com/VPNWorks/vpnw.

Contact: info@vpnw.com
