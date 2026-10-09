# Reference

## Commands

| Command | What it does |
|---|---|
| `vpnw run [options] -- CMD [ARGS]` | runs a program through a chosen path |
| `vpnw trace [options] -- CMD [ARGS]` | the same, printing every connection |
| `vpnw guard [options] -- CMD [ARGS]` | the same, under a policy, enforced |
| `vpnw learn [--from last\|FILE]... [--name NAME] [--ports] [--wildcards] [-o FILE]` | turns traces into a draft policy, with the built-in Learn plugin |
| `vpnw advise PLUGIN [--from last\|FILE]... [--set KEY=VALUE]... [-o FILE]` | runs an advisor plugin on traces |
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
| `dns` | proxy paths: `local` or `remote`, remote unless told otherwise. WireGuard paths: `tunnel` (the config's DNS servers, through the tunnel) or `local`; tunnel whenever the config names DNS servers |
| `ca_file`, `token_file` | for proxies over TLS; relative to the file's folder |

### WireGuard config files

The usual wg-quick format, as VPN providers and `wg` hand it out. In `[Interface]`: `PrivateKey`, `Address`, and optionally `DNS`, `MTU` and `ListenPort`. In each `[Peer]`: `PublicKey`, `Endpoint`, `AllowedIPs`, and optionally `PresharedKey` and `PersistentKeepalive`. Unknown keys are errors, and so are wg-quick's shell hooks (`PreUp`, `PostUp`, `PreDown`, `PostDown`): vpnw runs no commands from a config file.

Before the program starts, vpnw waits up to 5 seconds for a handshake with every peer and stops with exit code 123 if one doesn't answer. A connection to an address outside every peer's `AllowedIPs` is refused with that reason. The peers' endpoints are looked up on this machine, the one lookup that can't go through the tunnel.

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

## Where things are kept

| What | Where |
|---|---|
| the last trace (for `learn`) | `~/.local/state/vpnw/last.jsonl`, or under `$XDG_STATE_HOME` |
| installed plugins | `~/.local/share/vpnw/plugins/NAME/`, or under `$XDG_DATA_HOME` |
| trusted signing keys | `~/.config/vpnw/trusted-keys`, or under `$XDG_CONFIG_HOME` |
| compiled plugins | `~/.cache/vpnw/wasm/`, or under `$XDG_CACHE_HOME`; safe to delete |

## What it doesn't do yet

- Sealed runs and `guard` need Linux.
- TCP only, through HTTP CONNECT, plain HTTP and SOCKS5, on every path WireGuard included. UDP and QUIC are refused.
- Network only. A sealed program can read whatever your user can read, and send it only where the policy allows. Run vpnw as an ordinary user.
- Per program only. Gateway mode, for every device behind a machine, is planned.
