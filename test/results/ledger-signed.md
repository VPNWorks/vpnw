| Check | What must happen | What happened | Result |
|---|---|---|---|
| a first run with Ledger | vpnw makes this machine's key, and the ledger is signed by it | key made: true; ledger signed by it: true | passed |
| verify on the same machine | intact, every checkpoint and the end signed by this machine's key | signed by this machine's key, vpnw-ed25519:hmABvUwGDEMjJAaS0y7oCGXbFpYMTKqkMjQn2uQsLOg=: checkpoints 1 to 5 and the end | passed |
| verify on another machine, with no key given | intact, and it says the signatures weren't checked against a key it trusts | signed by vpnw-ed25519:hmABvUwGDEMjJAaS0y7oCGXbFpYMTKqkMjQn2uQsLOg=: checkpoints 1 to 5 and the end check out against it; give vpnw verify --key to check it's the key you trust | passed |
| verify there with --key and the public key | intact, checked against the key given | signed by the key you gave, vpnw-ed25519:hmABvUwGDEMjJAaS0y7oCGXbFpYMTKqkMjQn2uQsLOg=: checkpoints 1 to 5 and the end | passed |
| the ledger written again after checkpoint 1, chain recomputed, signatures kept | CHANGED at checkpoint 2: it doesn't match its signature | CHANGED: forged-1.ledger:14: checkpoint 2 doesn't match its signature: the ledger was written again after it was signed | passed |
| its 6 signature lines removed | CHANGED: the first checkpoint has no signature | CHANGED: forged-2.ledger:7: checkpoint 1 has no signature after it: the signature was removed, or the line was added | passed |
| written again and signed with another key | CHANGED: signed by another key | CHANGED: forged-3.ledger:1: the ledger is signed by vpnw-ed25519:7OTR1juFlhoSwrkHQDETkroGbKsWiih59Xqsz7QqNH0=, not by the key you gave: it was written again with another key | passed |
| written again unsigned | CHANGED: --key asks for a signed ledger | CHANGED: forged-4.ledger:1: this ledger isn't signed, and --key asks for one signed by vpnw-ed25519:hmABvUwGDEMjJAaS0y7oCGXbFpYMTKqkMjQn2uQsLOg=: it was written unsigned, or written again without its signatures | passed |
| the checkpoint copies in the trace | each carries its signature | 5 copies, 5 with a signature | passed |
| ledger.sign=false, verified on the machine that signs its ledgers | CHANGED without --unsigned, since an unsigned ledger could be a rewrite; intact with it | exit 1, then with --unsigned exit 0; this ledger isn't signed | passed |
10 of 10 checks passed
