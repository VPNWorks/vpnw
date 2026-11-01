| Step | What must happen | What happened | Result |
|---|---|---|---|
| the agent calls its API 3 times (localhost, 10 MB down, 20 connections) | all 3 go through | api ok: true | passed |
| it sends a 5 MB archive to the paste site (127.0.0.1, 256 KiB up) | cut at the budget: no more than 256 KiB leaves, the rest never does; the record says why | upload failed: true; bytes that left, request head included: 262144; body bytes the site got: 261944 of 5,000,000; connection.cut: up budget for 127.0.0.1: 256 KiB up | passed |
| it tries the upload again | refused before anything is sent: the budget is spent | upload refused: true, by "plugin:budget: byte budget spent: 256 KiB sent (budget for 127.0.0.1: 256 KiB up)" | passed |
| it sends to a host nobody listed (127.0.0.2) | refused; nothing reaches it | refused: true, by "plugin:budget: 127.0.0.2 is not on the budget allowlist"; requests that reached it: 0 | passed |
| the console | a CUT line naming the host and the budget | #4     CUT    127.0.0.1:39149  sent 256 KiB, the budget  budget for 127.0.0.1: 256 KiB up | passed |
| the ledger | holds the cut, sealed in its chain; vpnw verify says intact | connection.cut sealed: true; verify: intact: agent.ledger holds 33 entries of run r-9c5e56, every one matching its hash, and ends normally | passed |
| the same ledger with the cut's direction edited | vpnw verify names the changed line | CHANGED: edited.ledger:25: the event doesn't match its hash: it was changed | passed |

Budget: `localhost down=10MB requests=20; 127.0.0.1 up=256KiB` (127.0.0.2 isn't listed)

The console:

```
vpnw guard  run r-9c5e56  path direct  backend sealed  policy command line (default deny, 3 allow rules, 0 deny rules, deny_private false)
api 1 ok
api 2 ok
api 3 ok
upload 1 FAILED RemoteDisconnected
upload 2 FAILED HTTPError
vpnw #4     CUT    127.0.0.1:39149  sent 256 KiB, the budget  budget for 127.0.0.1: 256 KiB up
vpnw #5     DENY   127.0.0.1:39149  byte budget spent: 256 KiB sent (budget for 127.0.0.1: 256 KiB up)
other FAILED HTTPError
vpnw #6     DENY   127.0.0.2:34881  127.0.0.2 is not on the budget allowlist
vpnw exit   pid 13793  code 0  after 136 ms
vpnw summary  6 connections: 4 opened, 2 denied, 0 failed  sent 262.5 KB  received 207 B
vpnw: ledger: 33 entries sealed in agent.ledger
vpnw: ledger: last hash 06456e1e853fccb597227a6654ecb5cdc59a18e095ef3ce29a251ec4d435ceca
```

The cut, as the ledger sealed it:

```
{"n":24,"ev":{"v":1,"ts":"2026-11-01T07:28:53.213684611Z","type":"connection.cut","run":"r-9c5e56","pid":13793,"path":"direct","conn":4,"fields":{"bytes":262144,"key":"127.0.0.1","limit":"up","reason":"budget for 127.0.0.1: 256 KiB up","rule":"plugin:budget"}},"h":"d90379a64e79281da26e0175971e1ae33376999aa477ed7035bfb54e13c47e2b"}
```
7 of 7 steps passed
