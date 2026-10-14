# Reference

## Commands

| Command | What it does |
|---|---|
| `vpnw run [options] -- CMD [ARGS]` | runs a program through a chosen path |
| `vpnw trace [options] -- CMD [ARGS]` | the same, printing every connection |
| `vpnw guard [options] -- CMD [ARGS]` | the same, under a policy, enforced |
| `vpnw learn [--from last\|FILE]... [--name NAME] [--ports] [--wildcards] [-o FILE]` | turns traces into a draft policy, with the built-in Learn plugin |
| `vpnw advise PLUGIN [--from last\|FILE]... [--set KEY=VALUE]... [-o FILE]` | runs an advisor plugin on traces |
| `vpnw verify LEDGER [TRACE]... [--head HASH]` | checks a ledger the Ledger plugin wrote, with the built-in ledger-verify plugin. With no trace given it also reads `last`. Exit 0: intact. Exit 1: changed, or cut short |
| `vpnw exit serve\|check\|token\|cert` | runs an exit, the server end of a path, and makes what it needs; see [Exit](#exit) |
| `vpnw plugin list\|info\|add\|remove\|keygen\|sign\|trust\|keys` | manages plugins; `vpnw plugin help` lists them |
| `vpnw doctor` | checks what this machine supports |
| `vpnw version` | |

`run` prints nothing of its own unless asked (`-v`). `trace` prints every event, `guard` the decisions. The console is the built-in Trace plugin; `--set trace.level=all|decisions|quiet` and `--set trace.show_allows=true` change it, in any run that prints a console (not `run` without `-v`, and not with `-q` or `--json`). If the console can't start, vpnw prints the events as JSON instead and carries on.

### Options for run, trace and guard

| Option | Meaning |
|---|---|
| `--policy FILE` | a file with a `[policy]` table, and optionally paths |
| `--config FILE` | a file with `[network]` and `[paths.NAME]` tables |
| `--via NAME` | use a named path from `--config` or `--policy` |
| `--direct` | connect from this machine (the default) |
| `--wireguard FILE` | go through a WireGuard tunnel, from a wg-quick config file. vpnw runs the tunnel itself: no root, no network interface |
| `--proxy URL` | `socks5://`, `socks5h://`, `http://`, `https://` or `socks5+tls://`. Given more than once, a list of exits used in order, moving to the next when one stops answering |
| `--ca FILE` | certificates to trust for a proxy over TLS |
| `--token-file FILE` | the token for a proxy over TLS |
| `--dns MODE` | where names are resolved: `local` or `remote` for `--proxy`, `tunnel` or `local` for `--wireguard` |
| `--allow RULE`, `--deny RULE` | rules on the command line, repeatable |
| `--deny-private` | deny loopback, private and link-local addresses |
| `--default allow\|deny` | what happens when no rule matches |
| `--plugin NAME` | run an observer or guard plugin alongside, repeatable |
| `--set NAME.KEY=VALUE` | a setting for plugin NAME, repeatable |
| `--plugin-file NAME=PATH` | the file vpnw opens for plugin NAME, if it asks for one (`file.write`). It must not exist yet; the default is `~/.local/state/vpnw/NAME/RUN.NAME` |
| `--out FILE` | also write the events to FILE as JSON lines |
| `--json` | print events as JSON lines instead of text |
| `-v`, `--verbose` | print more, plugin log lines included |
| `-q`, `--quiet` | print only errors |
| `--no-save` | don't keep this trace as `last` |
| `--backend sealed\|env` | sealed (Linux, enforced) or env (proxy settings only) |
| `--allow-unix-sockets` | let a sealed program use Unix sockets |
| `--no-deny-exit` | keep the program's exit code when a connection was denied |

A policy, or a guard plugin, needs the sealed backend: the env backend only sets proxy variables, so it can't stop a program that ignores them.

### Exit codes

| Code | Meaning |
|---|---|
| the program's own | it ran and nothing was denied, or `--no-deny-exit` |
| 120 | a connection was denied and the program exited with 0 |
| 121 | usage or configuration error |
| 122 | enforcement not available here (no sealed backend) |
| 123 | the chosen path can't be used; the program never started |
| 124 | vpnw itself failed |
| 126 | the program can't be run |
| 127 | the program wasn't found |

## Files

A strict subset of TOML: tables, `key = value`, and strings, integers, booleans or arrays of them. Anything else is an error with its line number, never skipped.

```toml
version = 1
name = "agent"

[network]                 # the path used unless --via names another
type = "proxy"
urls = ["https://exit-de.example:8443", "https://exit-nl.example:8443"]
ca_file = "ca.pem"
token_file = "agent.token"

[paths.home]
type = "proxy"
url = "socks5h://127.0.0.1:1080"

[paths.office]
type = "wireguard"
config = "office.conf"    # a wg-quick file, relative to this one

[policy]
default = "deny"
deny_private = true
allow = ["api.github.com", "*.githubusercontent.com", "pypi.org:443"]
deny = ["telemetry.example"]

[trace]
enabled = true
format = "jsonl"          # or "text"
out = "trace.jsonl"
```

| Path key | Value |
|---|---|
| `type` | `direct`, `proxy` or `wireguard` |
| `url` or `urls` | a proxy path: one proxy, or a list of exits with failover |
| `config` | a WireGuard path: its wg-quick file, relative to this file's folder |
| `dns` | proxy paths: `local` or `remote`, remote unless told otherwise. WireGuard paths: `tunnel` (the config's DNS servers, through the tunnel, the default) or `local`. A WireGuard config with no DNS server needs `local`, said out loud, and one whose DNS server is outside every peer's AllowedIPs is refused |
| `ca_file`, `token_file` | for proxies over TLS; relative to the file's folder |

### WireGuard config files

The usual wg-quick format, as VPN providers and `wg` hand it out. In `[Interface]`: `PrivateKey`, `Address`, and optionally `DNS`, `MTU` and `ListenPort`; `Table`, `SaveConfig` and `FwMark` are accepted and have no effect, since the tunnel has no routing table or interface. IPv6 endpoints are written `[address]:port`. In each `[Peer]`: `PublicKey`, `Endpoint`, `AllowedIPs`, and optionally `PresharedKey` and `PersistentKeepalive`. Unknown keys are errors, and so are wg-quick's shell hooks (`PreUp`, `PostUp`, `PreDown`, `PostDown`): vpnw runs no commands from a config file.

Before the program starts, vpnw waits up to 12 seconds for a handshake with every peer (WireGuard retries after 5) and stops with exit code 123 if one doesn't answer. A connection to an address outside every peer's `AllowedIPs` is refused with that reason. So is one to a loopback, link-local (169.254.0.0/16, fe80::/10) or multicast address, always, even with `AllowedIPs = 0.0.0.0/0` and with no setting to allow it: through a tunnel those could only reach the peer's own machine or its network segment, where cloud metadata lives, so a lying DNS answer from the tunnel can't send a program there. The peers' endpoints are looked up on this machine, the one lookup that can't go through the tunnel.

### When connections end

On every path, a connection ends when both sides are done. When the program has stopped sending (it closed its side, say after giving up on a timeout) and the destination then sends nothing for 2 minutes, vpnw closes the connection and records it, so a path that went silent doesn't hold it open until the run ends. A destination that keeps sending, however slowly, keeps it open. When the run ends, connections still open are closed and recorded, and lookups or dials still waiting are recorded as cut off by the end of the run.

## Policy

Rules are a host (`api.github.com`), every subdomain of one (`*.github.com`, not `github.com` itself), an address (`10.0.0.7`) or a range (`10.0.0.0/8`), each with an optional port (`pypi.org:443`). Rules never match more than they say: host rules never match an address typed as a number.

Every connection is decided in the same order:

1. deny rules on the name
2. deny rules on every address the name resolved to
3. `deny_private` on every address: loopback, private ranges, link-local (cloud metadata), and IPv6 forms that embed them
4. allow rules
5. the default; with an allow list and no default, the default is deny

A name is looked up only when an address could change the answer. A name that's denied, or simply not allowed, is never looked up, because a DNS query can carry data out too. If a name resolves to several addresses, all must pass.

Guard plugins come after the policy: they see only connections the policy allowed, and can only refuse them.

## Events

One JSON object per line, schema version 1. Every event has `v`, `ts`, `type` and `run`; most have `pid`, `path` and `conn`.

| Type | Fields |
|---|---|
| `run.start` | `mode`, `backend`, `enforced`, `version`, `path_kind`, `path`, `remote_dns`, `policy`, `plugins`, `unix_sockets` |
| `process.start` | `cmd`, `args` |
| `connection.attempt` | `host` or `ip`, `port`, `proto`; at an exit also `client`, `source`, `peer`, `client_run`, `client_conn` |
| `dns.query` | `host` |
| `dns.result` | `host`, `ips` and `ms`, or `error` |
| `policy.allow` | `rule`, `text`, `reason` |
| `policy.deny` | `rule`, `reason`, `text`; a guard plugin's rule is `plugin:NAME` |
| `path.switch` | `from`, `to`, `error`, `ms` |
| `connection.open` | `ip` or `host`, `exit`, `ms`; at an exit, `source` |
| `connection.close` | `bytes_up`, `bytes_down`, `ms` |
| `connection.error` | `error`, `exit` |
| `plugin.error` | `plugin`, `type`, `error` |
| `auth.deny` | at an exit: `peer`, `proto`, `reason`, and `host` or `ip` and `port` when the request named them |
| `process.exit` | `code`, `signal`, `ms` |
| `run.end` | `connections`, `opened`, `allowed`, `denied`, `failed`, `bytes_up`, `bytes_down`, `code` |
| `plugin.NAME.TYPE` | whatever plugin NAME emitted |

Events describe decisions, never payloads: no application data, URL paths, headers, environment variables or proxy passwords.

## Ledger

The built-in Ledger plugin seals a run's events into a ledger file as the run goes:

```
vpnw guard --plugin ledger --policy agent.toml -- ./my-agent
vpnw verify ~/.local/state/vpnw/ledger/r-3f9a1c.ledger
```

The ledger is JSON Lines. Each event is written as it arrives, exactly as vpnw sent it, with a SHA-256 hash that covers the line before it, its number and the event. Every 100 entries (`--set ledger.every=N`) and at the end, Ledger writes a checkpoint; at the end it writes an end line, then prints the ledger's path and its last hash. Each checkpoint is also copied into the run's trace as a `plugin.ledger.checkpoint` event (fields `cp`, `n`, `h`, and `end` on the last).

```
{"vpnw-ledger":1,"run":"r-3f9a1c"}
{"n":1,"ev":{"v":1,"ts":"…","type":"run.start",…},"h":"7e3b…"}
{"n":7,"lost":12,"h":"…"}
{"cp":1,"n":100,"h":"…"}
{"end":143,"cp":2,"h":"…"}
```

```
h0 = SHA-256("vpnw-ledger v1\n" || the header line)
h = SHA-256(h' || 0x00 || N as 8 bytes || the event)          event N
h = SHA-256(h' || 0x01 || N as 8 bytes || count as 8 bytes)    lost-events entry N
h = SHA-256(h' || 0x02 || K as 8 bytes || N as 8 bytes)        checkpoint K, after entry N
h = SHA-256(h' || 0x03 || N as 8 bytes || K as 8 bytes)        the end: N entries, K checkpoints
```

`h'` is the hash of the line before; numbers are big-endian. Every line after the header is a link in the chain, checkpoints and the end line included.

`vpnw verify` reports the first problem with its file and line:

| Found | Verdict |
|---|---|
| every line matches its hash, the end line is there, and the checkpoint copies and `--head` (if given) match | `intact`, exit 0 |
| an event, a hash, a checkpoint or the end line changed; a line removed, copied, added or moved; two lines swapped; the header changed; a line not in the exact form Ledger writes | `CHANGED`, exit 1, naming the line |
| the ledger stops without an end line, or in the middle of a line | `cut short`, exit 1: the run was killed there, or the end was removed. What is there is checked |
| the hashes were written again from some line on | `CHANGED` only against something kept elsewhere: the checkpoint copies in the trace (then the trace's events name the line) or the last hash given with `--head` |

`lost` entries mark events that never reached Ledger because it fell behind the run. They are part of the chain and reported, and don't make a ledger changed.

What a ledger can't show alone: anyone who can write the file and knows the format can write a new one from scratch. That includes the program being watched, while it runs: vpnw limits the network, not files, and the program runs as your user. Keep the last hash Ledger prints, or the trace with its checkpoint copies, somewhere neither the program nor the person holding the ledger can change.

## Exit

An exit is the server end of a path: `vpnw exit serve`, on a machine with fixed addresses. Clients reach it over TLS through vpnw's proxy paths (`https://` or `socks5+tls://`), each with a token of its own. The exit decides every request again with that client's own policy, by the same code that decides a run's connections, before it connects anywhere. Then the connection leaves from the client's fixed address. So a partner can let a client in by its address, and a client that skipped its own policy, or someone with its token, gets nothing that policy refuses.

```
vpnw exit cert --host 198.51.100.2 --name exit-de      # a private CA, and the exit's certificate
vpnw exit token --out agent-1.token                     # a client's token, and its hash
vpnw exit check --config exit-de.toml                   # what each client may do
vpnw exit serve --config exit-de.toml --out exit.jsonl
```

On the client's machine, with `ca.pem` and the token file copied over:

```
vpnw guard --proxy https://198.51.100.2:8443 --ca ca.pem --token-file agent-1.token --policy agent-1.toml -- ./my-agent
```

Give `--proxy` twice, or `urls` in the file, for a list of exits: when the one in use stops answering, connections move to the next.

| Command | What it does |
|---|---|
| `vpnw exit serve --config FILE` | takes clients' requests over TLS until SIGINT, SIGTERM or SIGHUP. Takes `--out`, `--json`, `-v`, `-q`, `--plugin`, `--set` and `--plugin-file` as a run does; `--out` adds to the file, so a restart keeps the earlier record. The console prints refusals and errors; `-v` every step |
| `vpnw exit check --config FILE` | reads the file, its policy files, certificate and key, and says what each client may do and whether its addresses are on this machine |
| `vpnw exit token [--out FILE]` | makes a token, 32 random bytes as 43 characters, and prints the `token_sha256` line for the exit's file. With `--out` the token goes to FILE, created new and readable by you alone, instead of the screen |
| `vpnw exit token --from FILE` | prints the `token_sha256` of a token kept in FILE |
| `vpnw exit cert --host HOST... [--name NAME] [--dir DIR]` | makes NAME.crt and NAME.key (default `exit`), valid for 2 years, for each address or name given with `--host`, signed by the private CA in DIR (`ca.pem` and `ca.key`). With no CA there, it makes one, valid for 10 years. Clients trust `ca.pem` with `--ca`; one CA can sign several exits. Never overwrites a file |

Exit codes: 0, or 121 for a usage or configuration error, with the file and line; 122 when it's not possible on this machine (the listening address, or a source address the machine doesn't have); 124 for any other failure.

### The exit's file

The same strict TOML subset as vpnw's other files.

```toml
version = 1
name    = "exit-de"              # on its record; the default is the file's name
listen  = "198.51.100.2:8443"
cert    = "exit-de.crt"          # relative to this file
key     = "exit-de.key"

[clients.agent-1]
token_sha256 = "1045911b…"       # vpnw exit token prints it
source       = "198.51.100.10"   # an address of its own
policy       = "agent-1.toml"    # the client's own policy file: its [policy] table
allow_exit_host = false          # the default; true lets it reach this machine

[clients.ci]
token_sha256 = "576873c3…"
pool         = "shared"          # addresses it shares with other clients
default      = "deny"            # or the policy written here, as in [policy]
deny_private = true
allow        = ["registry.partner.example"]

[pools.shared]
addresses = ["198.51.100.20", "198.51.100.21"]
```

- Every client needs `token_sha256`, a `source` or a `pool`, and a policy: a policy file, or the keys `default`, `deny_private`, `allow` and `deny` in its table, not both.
- An address belongs to one client, or to one pool. A client of a pool always leaves from the same address of it, picked from the client's name.
- A source is one address of the machine: not a wildcard such as `0.0.0.0`, and not a broadcast, multicast or link-local address. Every source has to be on the exit's machine, or `serve` refuses to start (exit code 122). The exit checks that each connection really left from the client's address.
- Whatever a client's policy says, the exit never connects to its own machine, unless the client's table has `allow_exit_host = true`: its loopback addresses, the addresses it had when it started, and any address it routes to itself now. For every client it refuses link-local, multicast and unspecified addresses, and the cloud metadata addresses outside link-local that it knows (`fd00:ec2::254`, `100.100.100.200`), so a cloud's metadata service at 169.254.169.254 is out of reach from an exit. Such a refusal is recorded as `policy.deny` with the rule `exit`, after the client's own policy allowed the connection.
- Names are looked up at the exit, so `deny_private` sees where a name really points. Give clients of an exit the default, names resolved at the exit (`dns = "remote"`): the exit needs the names to check name rules.
- `check` and `serve` warn about a client with default allow and no `deny_private`, an allow rule that takes in private addresses, and `allow_exit_host`.

### On the wire

| | HTTP CONNECT, inside TLS | SOCKS5, inside TLS |
|---|---|---|
| token | `Proxy-Authorization: Basic`, the token as the password | the password of the user-and-password login |
| the client's run and connection IDs | `VPNW-Run: r-3f9a1c` and `VPNW-Conn: 17` | the user name, `r-3f9a1c/17` |
| refused by the policy | 403, with `VPNW-Rule` and `VPNW-Reason` | reply 2 |
| wrong token | 407 | login refused |
| health check | `GET /health` with the token: 200 and the exit's name, or 407 | a login, then nothing |

vpnw sends the IDs with every request. A request that gives the token or an ID header twice is refused, so the exit never chooses between two. When a client asks for a name, a refusal that comes from an address the exit looked up is told to the client by its rule only, so a token can't be used to read the exit's DNS answers; the exit's record has the whole reason.

Before a client shows its token, it holds little. A connection gets 10 seconds for TLS and its request together. One address can have at most 32 such connections waiting (an IPv6 address counts with its /64), and all addresses together 1,024; when all 1,024 are taken, the oldest waiting connection of the address holding the most is closed to make room. A wrong token is answered after a second. Behind a TCP load balancer every client comes from the balancer's address, so they share its 32. Once logged in, a client can have 1,024 connections open at the exit; one more is answered 429, or with SOCKS5 reply 1. A client without vpnw can send no IDs at all; its connections are decided and recorded like any other. The exit takes nothing but CONNECT, the health check and SOCKS5 CONNECT; SOCKS5 BIND and UDP are refused with a record of it.

### The exit's record

Events of schema version 1, the same types as a run's. Each connection's first event, `connection.attempt`, also has `client`, `source` (the address it leaves from), `peer` (where the request came from), and `client_run` and `client_conn`, the client's own run and connection IDs. So the exit's record lines up with the client's, whose `connection.open` names the exit that carried it. `connection.open` has `source`, the address the connection really left from. `auth.deny` records a request without a valid token, never the token itself: at most 20 in 10 seconds, and the next one recorded after more says how many were left out (`unrecorded`). Under a flood of wrong tokens, the record keeps those 20 and a count, not every address that tried. `run.start` has `mode` = `exit`, `exit`, `listen`, `clients`, `cert_for` and `cert_until`. `run.end` has a run's totals except `code`, with `auth_denied`, `health_checks`, `tls_failed`, `over_limit`, `accept_errors`, and `why` the exit stopped. When the machine runs out of file descriptors, the exit keeps trying, and says so on the console once a minute.

Plugins run at an exit as they do in a run. Observers see its record (`--plugin ledger` seals it), and Guard plugins are asked about every connection a client's policy allowed, with the client's name in the request. A ledger file grows to at most 1 GiB, about half a million connections at an exit; each start of the exit begins a new one.

### What an exit doesn't do yet

- It reads its file when it starts. To change its clients, restart it.
- A client's policy file at the exit is the exit's own copy. When the client's policy changes, copy it to the exit too.
- A client can't ask for a particular address of its pool.
- Over SOCKS5 a refusal carries no reason. Over HTTP CONNECT it does, and vpnw shows it.

## Where things are kept

| What | Where |
|---|---|
| the last trace (for `learn`) | `~/.local/state/vpnw/last.jsonl`, or under `$XDG_STATE_HOME` |
| a plugin's file (`file.write`), unless `--plugin-file` says otherwise | `~/.local/state/vpnw/NAME/RUN.NAME`, as `ledger/r-3f9a1c.ledger`; created new, readable by you alone |
| installed plugins | `~/.local/share/vpnw/plugins/NAME/`, or under `$XDG_DATA_HOME` |
| trusted signing keys | `~/.config/vpnw/trusted-keys`, or under `$XDG_CONFIG_HOME` |
| compiled plugins | `~/.cache/vpnw/wasm/`, or under `$XDG_CACHE_HOME`; safe to delete |

## What it doesn't do yet

- Sealed runs and `guard` need Linux.
- TCP only, through HTTP CONNECT, plain HTTP and SOCKS5, on every path WireGuard included. UDP and QUIC are refused.
- Network only. A sealed program can read whatever your user can read, and send it only where the policy allows. Run vpnw as an ordinary user.
- Per program only. Gateway mode, for every device behind a machine, is planned.
