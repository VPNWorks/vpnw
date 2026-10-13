| Change | Verdict | What verify says |
|---|---|---|
| one byte of an event | CHANGED | run.ledger:6: the event doesn't match its hash: it was changed |
| an event's hash | CHANGED | run.ledger:6: the event doesn't match its hash: it was changed |
| a line removed | CHANGED | run.ledger:6: entry 5 is missing before this line: a line was removed |
| two lines removed | CHANGED | run.ledger:6: entries 5 to 6 are missing before this line: lines were removed |
| a line copied | CHANGED | run.ledger:7: entry 5 again, after entry 5: this line was added (inserted or copied) |
| two lines swapped | CHANGED | run.ledger:6: this line and the next were swapped (entry 5 comes after entry 6) |
| the header | CHANGED | run.ledger:1: the header names run r-abc124, but the events are run r-abc123's: the header was changed |
| a checkpoint | CHANGED | run.ledger:12: checkpoint 1 covers entry 9, but the entries before it end at 10: lines were removed, added or moved |
| a checkpoint removed | CHANGED | run.ledger:12: checkpoint 1, after entry 10, is missing before this line: it was removed |
| the last checkpoint removed | CHANGED | run.ledger:30: the end line counts 3 checkpoints, but there are 2: checkpoints were removed or added |
| a checkpoint added | CHANGED | run.ledger:31: checkpoint 4 doesn't match its hash: it was changed |
| the end removed, with the end's copy in the trace | CHANGED | run.ledger: last.jsonl:28 shows the run ended after checkpoint 3, but the ledger has no end line: the end was removed |
| the count of lost events | CHANGED | run.ledger:14: the count of lost events doesn't match its hash: it was changed |
| spaces added | CHANGED | run.ledger:6: not a line Ledger writes: it was changed |
| a line after the end | CHANGED | run.ledger:32: a line after the end line: it was added |
| bytes after the end, with no newline | CHANGED | run.ledger:32: a line after the end line: it was added |
| the first event's run | CHANGED | run.ledger:2: the event doesn't match its hash: it was changed |
| the end line | CHANGED | run.ledger:31: the end line counts 27 entries, but there are 26: lines were removed, added or moved |
| the end removed, no trace | cut short | run.ledger: the ledger stops after line 30 with no end line: the run was cut short there, or the end was removed |
| the end and the last lines removed, with copies | CHANGED | run.ledger: last.jsonl:21 holds a copy of checkpoint 2, after entry 20, but the ledger stops at checkpoint 1, entry 12: the end was cut off |
| rewritten from line 5 on, with the trace | CHANGED | run.ledger:6: the event differs from the same event in last.jsonl:5, and the hashes from here on were written again to hide it (the copy of checkpoint 1 in last.jsonl:11 doesn't match) |
| rewritten from line 5 on, with the kept head | CHANGED | run.ledger: the ledger's last hash is not the one you kept: it was rewritten |
22 kinds of change; verdicts:  21 CHANGED; 1 cut short;
