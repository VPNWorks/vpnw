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
| `connection.attempt` | `host` or `ip`, `port`, `proto` |
| `dns.query` | `host` |
| `dns.result` | `host`, `ips` and `ms`, or `error` |
| `policy.allow` | `rule`, `text`, `reason` |
| `policy.deny` | `rule`, `reason`, `text`; a guard plugin's rule is `plugin:NAME` |
| `path.switch` | `from`, `to`, `error`, `ms` |
| `connection.open` | `ip` or `host`, `exit`, `ms` |
| `connection.close` | `bytes_up`, `bytes_down`, `ms` |
| `connection.error` | `error`, `exit` |
| `plugin.error` | `plugin`, `type`, `error` |
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
