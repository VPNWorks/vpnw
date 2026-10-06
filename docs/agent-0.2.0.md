# Agent 0.2.0

Agent 0.2.0 is the Agent with the three changes Exit needs: proxies reached over TLS, a list of exits with failover, and the run's ID sent to the exit with every connection. Nothing else changed in what the Agent does. The run, trace, guard and learn commands behave as in 0.1.0 for every kind of path 0.1.0 had, and the checks that cover those parts came out as they did on September 29, 2026: 14 of 14 ways out of the sandbox blocked, with the 2 IPv6 rows skipped, and the 24 planted bugs of the Alpha all caught.

> **VPN Works keeps network access narrow and on the record.** The Agent gives each AI agent a network of its own. Scope gives each person on a company VPN only the systems they use. Lab checks that VPN apps keep traffic inside the tunnel when things go wrong. Ledger makes every record tamper-evident. Exit checks the policy again at the far end.

This note says what changed and what was measured again. Exit itself is described in [the Exit Alpha report](exit-alpha.md).

## What changed

### 1. Proxies over TLS

A path can now be a proxy reached over TLS:

| URL | What the Agent speaks to it |
|---|---|
| `https://HOST:PORT` | HTTP CONNECT, inside TLS |
| `socks5+tls://HOST:PORT` | SOCKS5, inside TLS |

- The proxy's certificate is always checked, against the system's certificates or a CA file of your own: `ca_file` in a configuration file, `--ca` on the command line. No setting turns the check off. TLS 1.2 is the oldest version accepted. Sessions are resumed, so later connections to the same exit skip the full handshake.
- The token is the URL's password (`https://vpnw:TOKEN@exit.example:8443`), or it sits in a token file: `token_file` in a configuration file, `--token-file` on the command line, one token of 1 to 255 printable characters. Over HTTP CONNECT it goes in `Proxy-Authorization`, over SOCKS5 as the password of the login. It's never printed or recorded: the Agent shows `***` in its place, as it already did for proxy passwords.
- Names go to the exit to be resolved, as with `http://` proxies, so the exit can check the client's rules for names. `dns = "local"` in a configuration file still resolves them on the Agent's machine.
- The health check before the program starts makes the TLS handshake and checks the token: an `https://` exit is asked `GET /health`, a `socks5+tls://` exit is logged in to. An expired certificate, one from another CA, one for another name, or a refused token stops the run before the program starts, with exit code 123 and the reason.

### 2. A list of exits, with failover

```toml
[network]
type = "proxy"
urls = ["https://exit-de.example:8443", "https://exit-nl.example:8443"]
ca_file = "ca.pem"
token_file = "agent.token"
```

On the command line, `--proxy` given more than once makes the same list. A path has either `url` (one proxy) or `urls` (a list of exits), and relative file names start from the configuration file's folder.

- Before the start, every exit in the list is checked at once, and the first in list order that answers is used. The run's first event, run.start, lists the exits, says which one is in use and why any before it were passed over.
- When the exit in use doesn't answer (it can't be reached, TLS fails, or it closes the connection before answering), the connection being opened moves to the next exit, and so does every connection after it. An exit gets 3 seconds to accept a connection and finish TLS. An exit that answers with a refusal stays in use, and the refusal goes to the program.
- Each move is recorded in a new event, `path.switch`, with the exit given up, the next one, the error, and the milliseconds spent on the exit given up. `connection.open` and `connection.error` have a new `exit` field that names the exit that carried the connection.
- The list doesn't move back during a run. The next run starts again from the top.

### 3. The run's ID goes to the exit

| Protocol | How the IDs travel |
|---|---|
| HTTP CONNECT | Two headers: `VPNW-Run: r-3f9a1c` and `VPNW-Conn: 17` |
| SOCKS5 | The login's user name is `r-3f9a1c/17`, and the token is the password |

The IDs go only to proxies reached over TLS. A plain `http://` or `socks5://` proxy gets exactly the requests 0.1.0 sent it. When a VPN Works exit refuses a request, its answer names the rule and the reason (headers `VPNW-Rule` and `VPNW-Reason`), and the Agent passes them on to the program, for example `the exit refused it (deny_private): intranet.partner.test resolved to 10.50.0.5: private network address (10.0.0.0/8)`.

### Version and event schema

`internal/version` says 0.2.0. The event schema stays at version 1: the new event type and the new field are additions, and no existing field changed.

## Other changes, and why

- **Two defects, found by the new fuzz targets and fixed with regression tests.** A proxy URL with an `@` before `://`, which is broken anyway, showed its password in the error message. And a proxy's status line went into error messages and events with any control characters it held; they're now replaced, and the text is cut at 300 characters. Both were in code that 0.1.0 had.
- **A false alarm in the proxy URL fuzz target, fixed in the test.** The first final run stopped FuzzFromURL after about 20 seconds on the input `://:0000@\x10000`. The error quotes that URL with the password hidden, as `"://***@\x10000"`, but Go's escape of the control byte followed by the host's digits reads `0000`, the input's password, and the check looked for the password in the whole message. It now looks inside each value the error quotes, and in a description only before the words about DNS; the input stays as a regression seed, and planted bugs 20 and 32 are still caught.
- **`config.PolicyFromTable`.** The function that reads a `[policy]` table is now exported, so Exit reads a client's policy written in its own configuration with the Agent's code.
- **`tools/measure.sh`** writes `results/agent-0.2.0/` (or the folder in `OUT`), so `results/alpha/` keeps the run of September 29. It leaves the packages of Ledger, Lab and Exit out of the Agent's figures, as it already did for Scope's, and it fuzzes the two new targets.
- **`tools/planted_bugs.py`** has 15 new bugs in the new code, and leaves the other engines' tests out of its runs.

## What was measured again

The figures in this section come from the final run of `FUZZTIME=60s tools/measure.sh`, made on October 6, 2026 (UTC) on an idle machine, with one engine measured at a time. It took 580 seconds, and its files are in `engine/results/agent-0.2.0/`, next to the run of September 29 in `engine/results/alpha/`. Both runs were on virtual machines with two CPUs and Linux 6.18 on x86-64, with Go 1.24.7, but not on the same machine. Two sets of figures come from elsewhere, and say so: the failover times, from Exit's final run, and the side-by-side comparison under "Speed, size and memory", from an earlier run.

### What has to stay the same

| Check | September 29, 0.1.0 | This run, 0.2.0 |
|---|---|---|
| Bypass matrix | 14 of 14 ways out blocked, 2 IPv6 rows skipped | The same, row by row: `bypass-matrix.md` is identical |
| The Alpha's 24 planted bugs | 24 of 24 caught | 24 of 24 caught |

### Tests

| | September 29, 0.1.0 | This run, 0.2.0 |
|---|---|---|
| Test functions | 57, and 97 with subtests | 81, and 143 with subtests; all pass, with the 2 IPv6 rows skipped |
| Planted bugs | 24 of 24 caught | 39 of 39 caught |
| Race detector | Clean | Clean |
| Coverage | 77.4% of statements | 80.0%; internal/path went from 72.2% to 86.9% |
| Fuzzing | 4 targets, 60 seconds each | 6 targets, 60 seconds each, no failures |

The new tests cover proxies over TLS in internal/path, with certificates made in the test (expired, from another CA, for another name, from a private CA), tokens, the health check, failover and the IDs; the broker's switch events; the new configuration keys; and two integration tests with the real binary. In the first, a sealed program fetches three times through a list of two stand-in exits over TLS, the first exit dies after one connection, and each exit is checked for the token and the IDs it got. In the second, an expired certificate and a refused token each stop the run before the program starts. Exit's own tests run the real vpnw against the real vpnw-exit in a private network.

During the build, the new unit tests ran 25 times over on a machine shared with two other builds, and one failed once: in `TestExitsFailoverConcurrent`, 16 TLS handshakes at once didn't all finish within the test's 500 ms limit for an exit. That test now uses the list's real limit of 3 seconds, and the other failover tests 1 second. The final run includes this change.

The 15 new planted bugs, each caught by at least one test:

| | Planted bug | Part |
|---|---|---|
| 25 | A proxy's TLS certificate is no longer checked | TLS |
| 26 | The CA file is read but not used, so exits with a private CA are refused | TLS |
| 27 | The newline at the end of a token file is taken as part of the token | Token |
| 28 | The health check passes an exit that refuses the token | Health check |
| 29 | The connection ID sent to the exit is off by one, so the records don't join | IDs |
| 30 | The SOCKS5 user name carries the run and connection IDs the wrong way round | IDs |
| 31 | The run's ID also goes to plain proxies, reached without TLS | IDs |
| 32 | A password is shown when an `@` comes before `://` in a broken proxy URL | Redaction |
| 33 | A refusal from an exit moves the list on to the next exit | Failover |
| 34 | After a switch, every new connection tries the dead exit first again | Failover |
| 35 | The health check picks the last exit that answers instead of the first | Health check |
| 36 | A switch between exits leaves no event in the record | Events |
| 37 | The run's ID isn't sent to the exit | IDs |
| 38 | The Agent's record no longer says which exit carried a connection | Events |
| 39 | A second `--proxy` replaces the first instead of making a list of exits | Command line |

Fuzzing, a minute per target:

| Target | Inputs | Package |
|---|---|---|
| Configuration files | 3,100,292 | internal/config |
| Policy rules | 2,862,995 | internal/policy |
| Decisions | 2,668,595 | internal/policy |
| The broker's front end | 1,161,734 | internal/broker |
| Proxy URLs (new) | 1,357,439 | internal/path |
| An exit's answers (new) | 1,211,052 | internal/path |

### Failover

The time a switch takes was measured in Exit's network tests, with the real binaries, in Exit's final run (`engine/results/exit-alpha/network.txt`). When an exit's process is killed, the Agent gave up on it after 0 ms (the connection was refused at once) and had the connection open through the next exit 3 ms after its dial began. When an exit stops answering without a word, so that its packets are dropped, the Agent waits out the 3-second limit: 3,026 ms to give up, and the connection was open through the next exit 3,032 ms after its dial began. In both tests every fetch succeeded.

### Speed, size and memory

| Measure | September 29, 0.1.0 | This run, 0.2.0 |
|---|---|---|
| Start-up and exit of /bin/true, sealed, time added | 9.32 ms | 7.52 ms |
| The same with the env backend | 2.93 ms | 2.32 ms |
| Each new connection, sealed, time added | 1.105 ms | 0.997 ms |
| One 100 MB download, sealed | 789 MB/s (bare: 1,251) | 1,195 MB/s (bare: 2,095) |
| 3,008 requests from 64 threads, sealed | 755 a second (bare: 2,000) | 961 a second (bare: 2,177) |
| Memory while a program runs, resident | vpnw 4.1 MB, helper 4.2 MB | vpnw 5.3 MB, helper 5.4 MB |
| Linux x86-64 binary | 3,612,856 bytes, 1,515,249 compressed | 5,558,456 bytes, 2,315,293 compressed |
| Linux arm64 binary | 3,473,592 bytes, 1,391,935 compressed | 5,243,064 bytes, 2,105,416 compressed |
| Browser engine (TinyGo, WebAssembly) | 827,566 bytes | 829,693 bytes |
| Lines of Go, tests not counted | 5,459 in 24 files | 6,263 in 26 files |

Compressed means `gzip -9`. The times of the two runs can't be compared to the millisecond, since the machines differ: the bare download alone went from 1,251 to 2,095 MB/s. The binary grew by 1.9 MB (computed from the two size.txt files) because it now carries Go's TLS and certificate code, and that's where the extra memory comes from too. To tell the versions apart from the machines, both binaries ran in turn on one machine, so both saw the same load. That comparison was made by hand during the build, on October 5, 2026 (UTC), after an earlier run of `tools/measure.sh` with shorter fuzzing, on a machine shared with two other builds. It built 0.1.0 from the project's own history, from the commit of October 1 that the log names, which isn't part of this repository. It wasn't made again with the final run. `engine/results/agent-0.2.0/side-by-side.txt` holds the script and its output:

| Measure, on one machine | 0.1.0 | 0.2.0 |
|---|---|---|
| Start-up and exit of /bin/true, sealed, median of 60 | 7.37 ms | 7.30 ms |
| The same with the env backend | 3.48 ms | 3.66 ms |
| Memory of vpnw while a sealed program runs, resident | 4.2 MB | 5.4 MB |
| of which anonymous memory: the heap, stacks and the like | 1.0 MB | 1.0 MB |
| of which pages of the program file | 3.2 MB | 4.4 MB |

Start-up times are within 0.2 ms of each other. The extra memory is pages of the larger program file, which the kernel keeps in its page cache and can share between processes running the same file; vpnw and its helper are the same file. The memory vpnw allocates for its own work didn't change.

## Reproducing the figures

From the engine folder, on Linux with unprivileged user namespaces, Go 1.24, python3, and TinyGo for the browser build:

```
tools/measure.sh                  # a minute of fuzzing per target, as in the final run; writes results/agent-0.2.0/
FUZZTIME=10s tools/measure.sh     # the same with shorter fuzzing
```

With a minute of fuzzing per target, the final run took 580 seconds. `python3 tools/planted_bugs.py` alone plants the 39 bugs one at a time and restores each file afterwards.

## License

VPN Works is open source under the Apache License 2.0. Copyright VPNW.com 2026. The code is at https://github.com/VPNWorks/vpnw.

Contact: info@vpnw.com
