# VPN Works Exit Alpha

**vpnw-exit 0.1.0, with Agent 0.2.0.** Fixed exit addresses for agents and CI jobs, with each connection checked again at the exit against the client's own policy, and a record at the exit that joins the client's.

Report version 0.1, October 6, 2026.

Exit is the far end of the tunnel. It runs on a server with fixed addresses and gives each client its own address to leave from, so a partner that lets traffic in by IP address can let that client in by its address. Before it connects anywhere, the exit decides the request again with the client's own policy, the same file the client's Agent uses, so a client that has been tampered with gets nothing its policy refuses. It keeps a record of every connection, tagged with the client's run and connection IDs, and its record joins the Agent's. On the client's side, Agent 0.2.0 reaches exits over TLS, moves to the next exit in its list when one stops answering, and sends its IDs with every request. [Agent 0.2.0](agent-0.2.0.md) has a note of its own.

Everything here ran on one Linux machine, a virtual machine with two CPUs, inside private network namespaces. The two "countries" are two namespaces with addresses from documentation ranges, and the partner's servers and the DNS server are stand-ins written for the tests. No exit has run on a real public address yet, and no WireGuard tunnel took part.

> **VPN Works keeps network access narrow and on the record.** The Agent gives each AI agent a network of its own. Scope gives each person on a company VPN only the systems they use. Lab checks that VPN apps keep traffic inside the tunnel when things go wrong. Ledger makes every record tamper-evident. Exit checks the policy again at the far end. The Agent and Scope exist today; Lab, Ledger and Exit are new in this release.

## Key figures

| Figure | What it means |
|---|---|
| 110 of 110 | Requests decided the same way by the Agent and by an exit: the same decision, rule and reason, under 5 policies, with one DNS server. The real vpnw, sealed, against the real vpnw-exit |
| 0 of 11 | Forbidden requests that reached a server when a tampered client, holding a valid token and checking nothing itself, sent them straight to an exit |
| 3 ms | From the start of a connection to having it open through the second exit, when the first exit's process had been killed. An exit that goes silent costs the list's limit, 3 seconds |
| 9 of 9 | Connections in the demo's run that reached an exit and joined the exit's record, across the failover |
| 22 of 22 | Planted bugs caught by Exit's tests. The Agent's tests caught 39 of 39 |
| 2.0 ms | Time an exit added to each new connection, with a full TLS handshake; 1.7 ms with a resumed TLS session |
| 58 KB | Memory per connected client, with 200 clients connected at once |

## 1. Exit in brief

| Area | Status | Key figures |
|---|---|---|
| Engine | Complete for the Alpha scope | One Go program, `vpnw-exit`, standard library only. 2,789 lines of Go in 12 files, the browser build included. It reuses the Agent's configuration reader, policy engine, request plan, direct path and event model |
| Front ends | Working | HTTP CONNECT and SOCKS5, both inside TLS. A client is known by its token; the exit keeps only the token's SHA-256 |
| Decisions | Working, checked against the Agent | The client's policy, through the Agent's own request plan, before any dial. 110 of 110 requests decided as by the Agent, end to end; 594 of 594 with the same steps recorded as by the Agent's broker, in a unit test |
| Fixed addresses | Working on Linux | An address per client, or a pool that clients share. A client can't leave from an address that isn't its own |
| Failover | Working, in Agent 0.2.0 | A list of exits. The health check picks the first that answers; when it stops answering, new connections move to the next |
| Records | Working | The Agent's event schema, version 1, tagged with the client's run and connection IDs. `vpnw-exit join` matches them with the Agent's record |
| Tests | Extensive, on one machine | 41 test functions, 71 with subtests. 22 of 22 planted bugs caught. 94.1% of statements covered. Five fuzz targets |
| Speed | Measured on one machine | 2.0 ms added to each new connection with full TLS, 1.7 ms with a resumed session. 777 MB/s through an exit. 58 KB per connected client |
| Platforms | Linux x86-64, run and tested | arm64 Linux, macOS and Windows compile, not run |
| Demo | In the browser | A recorded run with two agents and two exits, replayed. The exit's own code reads the configuration, decides and joins in the page |
| Readiness | TRL 4 | "Technology validated in lab", on the European Commission's scale |

## 2. How it works

### 2.1 One connection, end to end

1. A program runs under the Agent, for example `vpnw guard`, sealed. It asks for `api.partner.test:80`. The Agent decides with the program's policy. If the policy refuses, nothing leaves the machine.
2. If the policy allows it, the Agent opens TLS to the exit in use, checks the exit's certificate, and sends the request with the client's token and the IDs of its run and of this connection.
3. The exit hashes the token with SHA-256 and compares the hash with each client's in constant time. A wrong token gets 407, or a refused login over SOCKS5, and the attempt goes into the exit's record without the token.
4. The exit decides the request again with that client's policy, before it dials anything. Names resolve at the exit, so `deny_private` sees where a name really points. A refusal is answered with 403 and the rule and reason in two headers, or SOCKS5 reply 2.
5. If the policy allows it, the exit dials the addresses it just checked, from the client's fixed source address, and relays.
6. Both ends record the connection. The Agent's record says which exit carried it; the exit's record has the client's name, its run and connection IDs, the decision, the source address and the bytes each way.

### 2.2 Why the exit decides again

The Agent's decision happens on the client's machine. A hijacked client, or a script holding a copy of a client's token, can skip it. The exit holds the same policy and doesn't rely on the client having checked anything: demo step 4 shows a script with a stolen token asking an exit for the cloud metadata address, the attacker's server and the intranet, and getting none of them.

The second check also sees what the first can't. When names resolve at the exit, the Agent never learns where a name points, so it can't apply `deny_private` to a name. The exit resolves it, and refuses a name that points into a private range. Demo step 3 shows this with a partner's intranet name.

### 2.3 The same decision at both ends

The exit doesn't copy the Agent's policy code. It calls the Agent's own request plan (`internal/plan`) with the client's policy, read by the Agent's own configuration reader. Two tests check that this gives the same answers:

- **End to end** (`TestExitAgreesWithAgent`): 22 destinations under 5 policies (names, wildcards, addresses, ranges, ports, `deny_private`, default allow and default deny), each sent through the real vpnw, sealed, and straight to the real vpnw-exit by a client that checks nothing, with one DNS server for both. The Agent resolves names itself in this test, so both ends see the same addresses. 110 of 110 agree on the decision, the rule and the reason: 32 allowed, 76 denied, 2 names that don't resolve.
- **Step by step** (`TestExitDecidesAsTheAgent`): 27 hosts on 2 ports under 11 policies, asked of the exit's server and of the Agent's broker in one process, with the same DNS answers. The two records hold the same steps for every request: 594 of 594, with 214 allowed, 370 denied and 10 stopped before a decision.

### 2.4 Fixed addresses and pools

Each client has a `source`, its own address, or a `pool` of addresses that it shares with other clients. A pool client keeps one address of the pool from one connection to the next, picked from its name, and may ask for another address of its own pool. An address can belong to one client only, unless it sits in a pool; the configuration reader refuses anything else with the file and line. Every source address has to be on the exit's machine, or `serve` refuses to start (exit code 122).

### 2.5 Failover

The failover lives in the Agent. A path can name a list of exits, in order. Before the program starts, the Agent checks them all at once and uses the first in the list that answers its health check. When the exit in use stops answering, the connection being opened moves to the next exit, and every connection after it goes there too. An exit gets 3 seconds to accept a connection and finish TLS. An exit that answers with a refusal stays in use. Each move is a `path.switch` event in the Agent's record, with the time it took.

### 2.6 The joined record

`vpnw-exit join` reads Agent records and exit records and matches each connection that reached an exit with the exit's record of it, on the run and connection IDs. A connection only counts as joined when both records name the same destination and agree on the outcome. It lists what doesn't join: a connection the Agent says reached an exit that no exit recorded, or an exit record that claims a run's connection the run never made. Connections from clients without an Agent record, such as the tampered client in the demo, are counted apart. Exit code 120 says something didn't join.

### 2.7 How it is built

| Part | Package | Lines of Go |
|---|---|---|
| Configuration, tokens, IDs, source addresses, decisions, the join | internal/exit | 1,011 |
| The TLS listener, HTTP CONNECT and SOCKS5, the health check, dialing, relaying, the record | internal/exit/server | 1,033 |
| The command line | cmd/vpnw-exit | 547 |
| The browser build | wasm/exit | 198 |
| The Agent's configuration reader, policy engine, request plan, direct path and events | internal/config, policy, plan, path, events | shared, unchanged apart from Agent 0.2.0 |

Lines of Go without tests, from source.txt. The tests add 3,715 lines. The front ends are Exit's own because an exit serves many clients, each known by a token, while the Agent's broker serves one program.

## 3. Using it

### 3.1 Commands

| Command | What it does |
|---|---|
| `vpnw-exit serve --config FILE` | Takes HTTP CONNECT and SOCKS5 requests over TLS. `--out FILE` also writes the record as JSON lines; `-v` prints every step, `-q` only the start and the summary |
| `vpnw-exit check --config FILE` | Reads the configuration with its policy files, certificate and key, and says what each client may do |
| `vpnw-exit token` | Makes a token for a new client and prints the `token_sha256` line for the configuration. `--from FILE` hashes a token kept in a file |
| `vpnw-exit decide --config FILE --client NAME HOST:PORT...` | Says what the exit would do with requests from one client, without connecting anywhere. `--dns FILE` answers names from a file |
| `vpnw-exit join --agent FILE... --exit FILE...` | Matches Agent records with exit records and lists every connection that doesn't join |
| `vpnw-exit version` | Prints the version |

`decide` and `join` take `--json`.

### 3.2 Exit codes

| Code | Meaning |
|---|---|
| 0 | Done |
| 120 | `decide` refused a request, or `join` found a connection that doesn't join up |
| 121 | A usage error, or an error in an input file, with the file and line |
| 122 | Not possible on this machine: the listening address, or a source address that isn't on this machine |
| 124 | Any other failure |

### 3.3 An exit's configuration

The same strict TOML subset as the Agent's files, read by the same reader. Unknown keys are errors, and every error names the file and line.

```toml
version = 1
name    = "exit-de"
listen  = "198.51.100.2:8443"
cert    = "exit-de.crt"
key     = "exit-de.key"

[clients.agent-1]
token_sha256 = "1045911b83a575b819c639ccb0f9af76f67e585b085efcd1de019293d7a38ed0"
source       = "198.51.100.10"
policy       = "agent-1.toml"     # the Agent's own policy file for this client

[clients.ci]
token_sha256 = "576873c3f781893c12f21534c8980f7d69ed9db9f248cd10ecb0cded221ca591"
pool         = "shared"
default      = "deny"             # or the policy written here
allow        = ["api.partner.test"]

[pools.shared]
addresses = ["198.51.100.20", "198.51.100.21"]
```

`check` also warns about things that work but deserve a look, such as a client whose policy lets it reach private addresses.

### 3.4 The Agent's side

```toml
[network]
type       = "proxy"
urls       = ["https://198.51.100.2:8443", "https://203.0.113.2:8443"]
ca_file    = "ca.pem"
token_file = "agent-1.token"
```

The same on the command line: `vpnw guard --proxy https://198.51.100.2:8443 --proxy https://203.0.113.2:8443 --ca ca.pem --token-file agent-1.token -- ...`.

### 3.5 On the wire

| | HTTP CONNECT, inside TLS | SOCKS5, inside TLS |
|---|---|---|
| Token | `Proxy-Authorization: Basic`, the token as the password | The password of the user-and-password login |
| Run and connection IDs | `VPNW-Run: r-3f9a1c` and `VPNW-Conn: 17` | The user name, `r-3f9a1c/17` |
| Another address of the client's pool | `VPNW-Source: 198.51.100.21` | The user name, `r-3f9a1c/17/198.51.100.21` |
| Refused by the policy | 403, with `VPNW-Rule` and `VPNW-Reason` | Reply 2, connection not allowed |
| Wrong token | 407 | Login refused |
| Health check | `GET /health` with the token: 200 and the exit's name, or 407 | A login, then nothing |

A request that sends the token or an ID header twice is refused, so the exit never has to choose between two tokens or two run IDs. A client without an Agent can send no IDs at all; its connections are recorded and decided like any other.

## 4. Tests

Every test runs on Linux against the real code. There are 41 test functions: 32 in Exit's packages and 9 in the private test network, where the real vpnw and vpnw-exit binaries run in network namespaces. All suites pass.

| Suite | What it checks | Result |
|---|---|---|
| internal/exit | The configuration and its errors, tokens, IDs, source addresses, decisions, the join and what it reports | 8 test functions and 3 fuzz targets' seeds; all passed |
| internal/exit/server | Both front ends, TLS and relaying, refusals, tokens, source requests, the health check, dial failures, limits, the text output, and the exit against the Agent's broker step by step | 12 test functions and 2 fuzz targets' seeds; all passed |
| cmd/vpnw-exit | Every command, its output and exit codes | 7 test functions; all passed |
| The private test network | The real binaries, below | 9 test functions; all passed |
| Race detector | The whole suite under Go's race detector | Clean |
| Fuzzing | Five parsers and front ends, a minute each | 7.25 million inputs in all (computed: the sum of fuzz.txt), no failure |
| Planted bugs | 22 deliberate bugs, one at a time | 22 of 22 caught |
| Coverage | The unit tests, and the vpnw-exit binary while the network tests ran | 94.1% of statements |

Coverage by package: internal/exit 97.5%, cmd/vpnw-exit 96.4%, internal/exit/server 90.0%.

### 4.1 In the private test network

The network: the agents' namespace at 192.0.2.2, exit-de with addresses in 198.51.100.0/24, exit-nl in 203.0.113.0/24, and an "internet" with the partner's servers and a DNS server, joined by a router. The servers report the source address they saw. The Agents run sealed under `vpnw guard`, with a list of the two exits. A test CA and certificates are made in the test with Go's crypto/x509.

| Test | What happened | Result |
|---|---|---|
| Fixed addresses | Two agents fetch through exit-de; a CI job with no Agent connects 10 times | agent-1 left from 198.51.100.10, agent-2 from 198.51.100.11; the pool client kept 198.51.100.21 for 10 of 10. The partner saw these three addresses and no other |
| The Agent and the exit agree | 110 requests under 5 policies, as in section 2.3 | 110 of 110 agree on the decision, the rule and the reason |
| A tampered client | 11 forbidden requests sent straight to exit-de with valid tokens: 8 over HTTP CONNECT, 3 over SOCKS5 | 11 refused by the exit, 0 reached a server. An allowed request still left from the client's own address |
| Failover, exit killed | exit-de's process killed after the 3rd of 10 fetches | Connection 4 gave up on exit-de after 0 ms (connection refused) and was open through exit-nl 3 ms after its dial began. The next 6 went straight to exit-nl. 0 fetches failed |
| Failover, exit silent | exit-de's packets dropped partway through 10 fetches. The test loads the drop rule after the 3rd, and the fetches go on while it loads | Connection 7 was the first to meet the drop. It gave up after 3,026 ms, the list's 3-second limit, and was open through exit-nl 3,032 ms after its dial began. The next 3 went straight to exit-nl. 0 fetches failed |
| Health check | exit-de down before the start | The run started on exit-nl, and its run.start event says so |
| Refusals | A wrong token; an expired certificate, one from another CA and one for another name; agent-2 asking for agent-1's address; a configuration giving two clients one address | 407, a refused SOCKS5 login, and an Agent that doesn't start (exit 123). The Agent doesn't start and names the reason (exit 123). 403 with rule `source`, and SOCKS5 reply 2, with nothing at any server. Refused with its file and line (exit 121) |
| Records join | 3 Agent runs and a tampered request. One request refused at the Agent and one at the exit; exit-de killed before the last run, which started on exit-nl | 7 of 7 connections that reached an exit joined |
| The demo's run | Section 7 | 9 of 9 joined; the tampered client's 3 requests refused |

### 4.2 Planted bugs

To check the tests themselves, 22 bugs were put into Exit's code on purpose, one at a time, and the whole suite ran against each. A bug counts as caught only if a test fails. All 22 were caught. The Agent's 15 new planted bugs are listed in the Agent 0.2.0 note.

| | Planted bug | Part |
|---|---|---|
| 1 | The user name in Proxy-Authorization is taken for the token | Tokens |
| 2 | A CONNECT that carries no token at all is not refused | Tokens |
| 3 | The health check keeps "Bearer " in front of the token, so a good token is refused | Health check |
| 4 | A request may carry two tokens or two run IDs, and the exit reads the first | HTTP front end |
| 5 | A refused token is written into the exit's record | Record |
| 6 | The exit decides as if names resolved elsewhere, so `deny_private` never sees where a name points | Decisions |
| 7 | The exit connects even when the client's policy refuses the destination | Decisions |
| 8 | Connections leave from the exit machine's default address instead of the client's fixed one | Source addresses |
| 9 | A client may leave from any address it asks for, another client's among them | Source addresses |
| 10 | The exit's record leaves out the client's connection ID, so the records don't join | Record |
| 11 | The SOCKS5 user name's run and connection IDs are read the wrong way round | SOCKS5 front end |
| 12 | SOCKS5 BIND is taken for CONNECT | SOCKS5 front end |
| 13 | The exit's totals stop counting the bytes sent back to clients | Record |
| 14 | Two clients may be given one fixed address | Configuration |
| 15 | A token hash of the wrong length is accepted | Configuration |
| 16 | An unknown key in a client's table, such as a misspelled allow, is ignored | Configuration |
| 17 | A client with a policy file and policy keys of its own silently uses the keys | Configuration |
| 18 | The join accepts an exit record for another destination | Join |
| 19 | A connection the exits never recorded is not reported | Join |
| 20 | An exit record of a connection the Agent never made goes unnoticed | Join |
| 21 | serve starts although a source address is not on this machine | Command line |
| 22 | decide exits 0 although it refused a request | Command line |

### 4.3 Fuzzing

A minute per target, with no failure. Each new input the fuzzer keeps is shrunk with at most 100 runs, so the time goes to new inputs.

| Target | Inputs | Package |
|---|---|---|
| Exit configuration files, with the policies they name | 2,105,403 | internal/exit |
| Run and connection IDs, headers and SOCKS5 user names | 2,019,447 | internal/exit |
| Agent and exit records, joined | 1,244,216 | internal/exit |
| The HTTP CONNECT front end, from the first byte | 925,423 | internal/exit/server |
| The SOCKS5 front end, from the first byte | 957,874 | internal/exit/server |

The front ends' targets check more than crashes: every dial the exit makes must come from an address that belongs to the client whose token was sent, to a destination that client's policy allows. Agent 0.2.0 adds two fuzz targets of its own, for proxy URLs and for an exit's answers.

### 4.4 Defects found and fixed

| | Defect | Found by | Effect before the fix |
|---|---|---|---|
| 1 | The Agent showed a proxy password in an error, for a broken URL with an `@` before `://` | The Agent's new fuzz target for proxy URLs | A password could reach a terminal or a log. The code was already in 0.1.0 |
| 2 | The Agent copied control characters from a proxy's status line into errors and events | The Agent's new fuzz target for an exit's answers | A hostile proxy could put control characters into a terminal. Also already in 0.1.0 |
| 3 | The exit recorded a name's DNS answers at another point than the Agent's broker did | The step-by-step test against the broker | The two records of one request didn't line up |
| 4 | The demo's test log was written in local time, the records in UTC | The demo page, whose timeline came out three hours off | The page put steps next to the wrong records |
| 5 | The first per-connection figure measured the Python client: Nagle's algorithm met delayed ACKs | The figure itself, far above the Agent's 1 ms | A wrong figure. The client now sets TCP_NODELAY |
| 6 | Two tests depended on timing: one on the order of two records, one on 16 TLS handshakes finishing in 500 ms | Running every suite 25 times while other builds ran | A test failed now and then, on a busy machine |
| 7 | A test waited forever when `serve` started by mistake | Planted bug 21, caught only when Go's 10-minute test timeout ran out | Slow test runs; the test now stops `serve` after 20 seconds |
| 8 | The join fuzz target spent its time shrinking inputs | Its count in the first run of the script, far below the other targets' | Little fuzzing of the join |

### 4.5 What the tests don't cover yet

- **Real exits.** No exit has run on a real public address, behind a real provider's network, or with WireGuard to it. The two countries are namespaces on one machine.
- **Real partners.** The partner's servers are stand-ins that report the address they saw. No real allowlist has been tried.
- **IPv6.** The machine has no IPv6. The configuration reads IPv6 addresses, and a unit test checks the error a client with an IPv4 source address gets for an IPv6 destination, but no IPv6 connection has left an exit.
- **Load and time.** 200 clients at once in the measurements, and runs of seconds to minutes. No exit has run for days.
- **Other proxies.** Agent 0.2.0's TLS proxies were tested against vpnw-exit and the test's stand-ins only.
- **Other machines.** One kernel, Linux 6.18 on x86-64. The arm64, macOS and Windows builds compile but haven't run.
- **Fuzzing time.** A minute per target.
- **Independent review.** Every test was written by the people who wrote the code.

## 5. Speed and size

All from the run in section 9, on the machine described above, with no other engine's measurements running. The client is Python 3.11 with OpenSSL 3.0.13, talking TLS 1.3 to vpnw-exit on the same machine, so the figures are the exit's own cost, not a network's. Times are the median of three runs, memory the highest of three.

| Measure | Result |
|---|---|
| A new connection, bare: TCP to a local server and one small HTTP request | 0.581 ms |
| The same through the exit, full TLS handshake each time: TCP, TLS, CONNECT with the token, the exit's decision and its dial from the client's address, then the request | 2.625 ms, so 2.044 ms added |
| The same with a resumed TLS session | 2.291 ms, so 1.710 ms added; 2,999 of 3,000 sessions resumed |
| One 100 MB download | 1,977 MB/s bare, 777 MB/s through the exit |
| Memory of the exit, idle | 11.7 MB |
| With 200 clients connected, each with an open tunnel | 23.1 MB, so 58.0 KB per client |

| Build | Size | Compressed (gzip -9) |
|---|---|---|
| Linux x86-64 | 5,689,528 bytes | 2,358,326 bytes |
| Linux arm64 | 5,374,136 bytes | 2,142,472 bytes |
| macOS, Intel and Apple silicon; Windows x86-64 | Compile, not run | |
| Browser engine (TinyGo, WebAssembly) | 920,056 bytes | 343,596 bytes |

No third-party modules. The failover figures are in section 4.1, and the Agent's own figures, measured again, are in the Agent 0.2.0 note.

## 6. Features and limits

| Feature | What 0.1.0 supports | Limits |
|---|---|---|
| Protocols | HTTP CONNECT and SOCKS5 CONNECT, inside TLS 1.2 or 1.3 | TCP only: no SOCKS5 UDP or BIND, no plain HTTP proxying |
| Clients | A token each, kept as a SHA-256; a policy each, from a file or written in the configuration | Tokens only, no client certificates. The configuration is read at start, so a new client needs a restart |
| Addresses | A fixed address per client, or a pool; a client may ask for another address of its pool | Every address has to be on the exit's machine. IPv6 untested |
| Decisions | The Agent's policies and request plan, names resolved at the exit, the checked addresses dialed | Host names and addresses, as in the Agent; nothing about what is sent inside a connection |
| Failover | A list of exits in Agent 0.2.0, health checked before the start; a silent exit is given up on after 3 seconds | The list doesn't move back during a run. No balancing across exits |
| Records | Schema v1 events with the client's run and connection IDs; `join` | Records are files on each machine; nothing collects them yet |
| Health | `GET /health` over the same TLS listener, with the client's token | No metrics endpoint |
| Platforms | Linux x86-64 | Other builds compile but haven't run |

## 7. The demo

The demo replays a run recorded on October 5, 2026 (UTC) in the private test network, with the real binaries and real TLS: vpnw 0.2.0 for two agents, vpnw-exit 0.1.0 for exits in two "countries", exit-de and exit-nl. The test that records it is `TestDemoScenario`; the recording, its configuration files and the script that turns it into the page's data are in the repository. The run took 5.1 seconds. In the page, Exit's own Go code, compiled to WebAssembly with TinyGo, reads both exits' configuration, decides requests the visitor types in, decides the 12 recorded exit decisions again and joins the four records. The page makes no network requests.

| Step | On the page | What it shows |
|---|---|---|
| 1 | The setup | Two exits, three clients at each, and the 4 fixed addresses the partner allows for the agents, read from the exits' configuration by the exit's code in the page |
| 2 | Fixed addresses | 4 fetches through exit-de: agent-1 always from 198.51.100.10, agent-2 from 198.51.100.11, as the partner's servers reported |
| 3 | Checked at both ends | agent-1 asks for attacker.test: refused by the Agent, and nothing leaves. It asks for intranet.partner.test: allowed by name at the Agent, refused by the exit, which saw the name point to 10.50.0.5. Both records of that connection, side by side |
| 4 | A tampered client | A script with agent-2's token asks exit-de for the cloud metadata address, attacker.test and the intranet: 3 refused, 0 reached a server. The visitor can edit agent-2's policy and ask exit-de, decided by the exit's code in the page |
| 5 | An exit fails | exit-de is killed. Each agent's next connection gives up on exit-de at once and is open through exit-nl 5 and 9 ms after its dial began. 0 requests failed, and the partner now sees 203.0.113.10 and 203.0.113.11 |
| 6 | One joined record | 9 of 9 connections that reached an exit joined the exits' records; 1 stopped at the Agent; 3 came from the tampered client, with no Agent run. 12 of 12 recorded exit decisions made again in the page, with the same rule |

A headless Chromium check plays the page through at computer and phone widths and compares each step's numbers with the command line's reading of the same recording (`vpnw-exit join` and `vpnw-exit decide`, in demo.txt, demo-join.json and demo-decide.json). All 62 checks pass, with no horizontal overflow at 390 pixels, no network requests and no errors in the console.

## 8. Where it stands

### 8.1 Maturity by part

| Part | Maturity | Evidence | Gap to close |
|---|---|---|---|
| Decisions at the exit | Working, checked against the Agent | 110 of 110 end to end, 594 of 594 step by step; 2 planted bugs caught | Policies from real deployments |
| Front ends and tokens | Working | Fuzzed; the tampered client and refusal tests; 6 planted bugs caught | An outside review of the parsers |
| Configuration | Working | Fuzzed; every error with its file and line; 3 planted bugs caught | Changes without a restart |
| Fixed addresses | Working on Linux | The partner saw only the clients' own addresses; 3 planted bugs caught | Real public addresses; IPv6 |
| Failover, in the Agent | Working | Killed and silent exits; the health check; 4 of the Agent's planted bugs caught | Moving back to an exit that recovers; longer lists |
| Records and join | Working | 7 of 7 and 9 of 9 joined; fuzzed; 6 planted bugs caught | Collecting the records of many exits |
| Command line | Working | 7 test functions; 2 planted bugs caught | Packages and service files |
| Browser demo | Working | The same figures as the command line; 62 headless checks | None found so far |
| Use on real servers | None | None | A pilot |

### 8.2 Readiness level

On the European Commission's technology readiness scale, which runs from TRL 1 to TRL 9, Exit 0.1.0 sits at TRL 4, "technology validated in lab". It works with the real Agent and real TLS in a private test network, against stand-in servers. Exits on real public addresses, reached by real agents, would take it to TRL 5, "technology validated in relevant environment".

### 8.3 How far from a first release

An estimate, and only an estimate: Exit is about a quarter of the way to a first release. The core works: decisions that match the Agent's, fixed addresses, failover and the joined record. What's left is mostly about running it for real: exits on public addresses, WireGuard to them as the project planned, certificates and tokens that can change without a restart, IPv6, collecting records from several exits, packages, a pilot with a partner that allows traffic by address, and an outside review.

### 8.4 Against the alternatives

Fixed-address proxies are common and cheap, and cloud providers sell fixed outbound addresses too. They trust whatever reaches them. Exit's case rests on three things: it checks the client's own policy again at the far end, its record joins the client's on every connection, and clients move between exits on their own when one fails.

### 8.5 Technical risks Exit revealed

- **A stolen token.** The exit can't tell a stolen token from its client. The policy limits what the token can reach (demo step 4), and the record shows its use, but the token still opens everything the policy allows. Binding tokens to where clients connect from isn't in 0.1.0.
- **Shared addresses.** A partner that allows a pool address lets in every client of the pool. Pools fit clients that are allowed the same places.
- **Two countries, two addresses.** After a failover the partner sees another address, so it has to allow every exit's address for a client, as the demo's partner does.
- **Silent failures.** An exit that stops answering without a word costs the first connection after it 3 seconds. A shorter limit would give up on exits that are only slow.
- **DNS at the exit.** Decisions about names depend on the exit's resolver. The exit dials the addresses it checked and resolves nothing twice, but a resolver that lies can still steer a name to an address the policy allows.
- **The exit as a target.** An exit relays its clients' traffic and holds their policies. Traffic that isn't encrypted end to end can be read there.

## 9. Reproducing the figures

Every figure about Exit in this report comes from one run of `FUZZTIME=60s tools/measure-exit.sh`, from the engine folder, on October 6, 2026 (UTC). It ran on an idle machine, one engine at a time, took about 8.5 minutes and wrote `engine/results/exit-alpha/`. The demo's figures come from the recording in `web/exit/recording/`, made on October 5, 2026 by `VPNW_EXIT_RECORD=../web/exit/recording go test -run TestDemoScenario ./test/exit/`, as read by that run. The Agent's figures come from the Agent's own run, described in the Agent 0.2.0 note.

| File | What it holds |
|---|---|
| environment.txt | Date, kernel, CPUs, Go, TinyGo, Python, nftables and OpenSSL versions |
| size.txt | Sizes for each build, compressed and not, and the platforms that compile |
| source.txt | Lines of Go per part, and lines of tests |
| tests.txt, tests.json | Every test and subtest with its result |
| race.txt | The suite under the race detector |
| coverage.txt | Coverage per package and in total |
| fuzz.txt | Inputs per fuzz target |
| network.txt | The RESULT lines of the network tests |
| planted-bugs.txt | Each planted bug and whether a test caught it |
| perf.txt | Time per connection, throughput and memory per client |
| demo.txt, demo-join.json, demo-decide.json | The command line's reading of the demo's recording |
| demo-browser.txt, demo-check.txt | The browser engine's answers on the same recording, and the headless check of the page |

`python3 tools/planted_bugs_exit.py` alone plants the 22 bugs one at a time, and `python3 tools/exit_perf.py bin/vpnw-exit` alone measures the speed.

## 10. License

VPN Works is open source under the Apache License 2.0. Copyright VPNW.com 2026. The code is at https://github.com/VPNWorks/vpnw.

Contact: info@vpnw.com
