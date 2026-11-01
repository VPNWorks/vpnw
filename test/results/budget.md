| Step | What must happen | What happened | Result |
|---|---|---|---|
| the agent calls its API 3 times (localhost, 10 MB down, 20 connections) | all 3 go through | api ok: true | passed |
| it sends a 5 MB archive to the paste site (127.0.0.1, 256 KiB up) | cut at the budget: no more than 256 KiB leaves, the rest never does; the record says why | upload failed: true; bytes that left, request head included: 262144; body bytes the site got: 261944 of 5,000,000; connection.cut: up budget for 127.0.0.1: 256 KiB up | passed |
| it tries the upload again | refused before anything is sent: the budget is spent | upload refused: true, by "plugin:budget: byte budget spent: 256 KiB sent (budget for 127.0.0.1: 256 KiB up)" | passed |
| it sends to a host nobody listed (127.0.0.2) | refused; nothing reaches it | refused: true, by "plugin:budget: 127.0.0.2 is not on the budget allowlist"; requests that reached it: 0 | passed |
| the console | a CUT line naming the host and the budget | #4     CUT    127.0.0.1:34303  sent 256 KiB, the budget  budget for 127.0.0.1: 256 KiB up | passed |
| the ledger | holds the cut, sealed in its chain; vpnw verify says intact | connection.cut sealed: true; verify: intact: agent.ledger holds 33 entries of run r-b89a22, every one matching its hash, and ends normally | passed |
| the same ledger with the cut's direction edited | vpnw verify names the changed line | CHANGED: edited.ledger:25: the event doesn't match its hash: it was changed | passed |

Budget: `localhost down=10MB requests=20; 127.0.0.1 up=256KiB` (127.0.0.2 isn't listed)

The console:

```
vpnw: made a signing key for this machine in config/vpnw/signing.key; its public key, for vpnw verify --key elsewhere: vpnw-ed25519:Q/bsGIPlE0K2Q+PUJJfkVgg1v4k07WEyeMqN4yHmCzw=
vpnw guard  run r-b89a22  path direct  backend sealed  policy command line (default deny, 3 allow rules, 0 deny rules, deny_private false)
api 1 ok
api 2 ok
api 3 ok
vpnw #4     CUT    127.0.0.1:34303  sent 256 KiB, the budget  budget for 127.0.0.1: 256 KiB up
upload 1 FAILED URLError
vpnw #5     DENY   127.0.0.1:34303  byte budget spent: 256 KiB sent (budget for 127.0.0.1: 256 KiB up)
upload 2 FAILED HTTPError
other FAILED HTTPError
vpnw #6     DENY   127.0.0.2:36823  127.0.0.2 is not on the budget allowlist
vpnw exit   pid 12435  code 0  after 121 ms
vpnw summary  6 connections: 4 opened, 2 denied, 0 failed  sent 262.5 KB  received 207 B
vpnw: ledger: 33 entries sealed in agent.ledger, signed by vpnw-ed25519:Q/bsGIPlE0K2Q+PUJJfkVgg1v4k07WEyeMqN4yHmCzw=
vpnw: ledger: last hash eb90c629fccb805f3bd2b5e8949aaddcb7ec2e865ef52939529f316e1b9924f7
```

The cut, as the ledger sealed it:

```
{"n":24,"ev":{"v":1,"ts":"2026-11-01T09:07:31.350495947Z","type":"connection.cut","run":"r-b89a22","pid":12435,"path":"direct","conn":4,"fields":{"bytes":262144,"key":"127.0.0.1","limit":"up","reason":"budget for 127.0.0.1: 256 KiB up","rule":"plugin:budget"}},"h":"01f9ac8fca325a07d2c3a42fca1ae041ebb21358cfe6d0a21888e9507442d09c"}
```
7 of 7 steps passed
