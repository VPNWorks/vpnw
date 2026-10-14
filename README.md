# VPN Works

VPN Works is the VPN, rebuilt as an operating system. Its kernel, `vpnw`, gives each program its own network path, its own policy and its own record. Paths are its drivers, and everything else is a plugin: WebAssembly apps that reach the kernel only through the calls they're allowed.

```
vpnw guard --policy agent.toml -- ./my-agent
```

That runs `my-agent` sealed off from the network. Its only way out is vpnw, which checks every connection against `agent.toml`, sends the allowed ones down the path you chose, refuses the rest, and writes down what happened.

Open source under the Apache License 2.0. Linux first; macOS for the parts that don't need Linux. Site: [vpnw.com](https://vpnw.com).

## What it's for

An ordinary VPN gives your whole machine one way out. VPN Works works one level down: per program. An AI coding agent, a build script, a scraper or a container each get their own path (direct, a WireGuard tunnel, a SOCKS or HTTP proxy, a proxy over TLS, a list of exits with failover) and their own rules (which hosts, which ports, nothing on the private network). A program that ignores proxy settings doesn't leak around vpnw; on Linux it has no route anywhere else.

It's built like an OS, and it isn't one you boot: vpnw is one program that runs on Linux or macOS without root.

| In an OS | In VPN Works |
|---|---|
| Kernel | the core, `vpnw`: seals, decides, carries, records |
| Drivers | paths: direct, proxy, proxy over TLS, WireGuard |
| System calls | the plugin interface |
| Apps | plugins |

The core does four things and nothing else:

- **Decide**: the broker takes every connection and asks the policy.
- **Enforce**: on Linux the program runs in a network namespace with nothing but loopback, and a seccomp filter keeps it off Unix sockets and io_uring, so the broker is the only way out.
- **Carry**: allowed connections go down the chosen path.
- **Record**: every decision becomes an event. Events record hosts, addresses, ports, byte counts and decisions, never payloads, URL paths, headers or passwords.

Plugins do the rest. They're WebAssembly modules that run in a sandbox inside vpnw with no files, no network and no environment, and they reach vpnw only through the calls their manifest asks for. Three kinds run today:

| Type | What it does | Built in |
|---|---|---|
| **Observer** | Watches a run's events as they happen | `trace`: the console output of run, trace and guard. `ledger`: seals the run's record |
| **Advisor** | Reads recorded traces or files and writes advice | `learn`: turns a trace into a draft policy. `ledger-verify`: checks a sealed record |
| **Guard** | Can refuse a connection the policy allowed | none yet |

Tunnel and Identity plugins come in later versions.

## A record nobody can quietly edit

The Ledger plugin writes every event of a run to its own file as it happens, each linked to the ones before it by a SHA-256 hash chain, with checkpoints along the way and an end line when the run finishes:

```
vpnw guard --plugin ledger --policy agent.toml -- ./my-agent
vpnw verify ~/.local/state/vpnw/ledger/r-3f9a1c.ledger
```

`vpnw verify` names the line where something was changed, removed, added or moved. A run that was killed leaves a ledger that checks out up to where it stops, and verify says it was cut short. Ledger copies each checkpoint into the run's trace and prints the last hash at the end; kept somewhere else, either one also catches a ledger written again from scratch. The format is in [the reference](docs/reference.md#ledger).

Ledger is a plugin like any other. It writes its file through the `file.write` permission, which vpnw offers every plugin: one new file, opened by vpnw, that the plugin can only add to.

## WireGuard, without root

Give vpnw the WireGuard config your VPN provider (or your own server) hands out, and one program goes through the tunnel while the rest of your machine doesn't:

```
vpnw guard --wireguard mullvad-de.conf --policy agent.toml -- ./my-agent
```

vpnw runs the tunnel itself, inside its own process: the WireGuard protocol from the official wireguard-go and a TCP/IP stack from gVisor. No root, no kernel module, no network interface on the machine, and nothing changes for any other program. Names are looked up through the tunnel at the DNS servers in the config, so lookups don't leak, and the policy still checks every address before anything is sent. A config without a DNS server is refused unless you ask for lookups on your own machine with `--dns local`. If the tunnel doesn't come up (a wrong key, a blocked port) the program never starts.

A lying DNS answer from the tunnel can't send a program to loopback or link-local addresses, cloud metadata among them: those are refused through any tunnel, a full tunnel included.

WireGuard is a built-in path, like the proxy paths, not a plugin: it carries every byte, and plugins never carry traffic. It's a registered trademark of Jason A. Donenfeld; VPN Works isn't affiliated with the WireGuard project.

## Exits with fixed addresses

Partners and internal systems often let traffic in by address. `vpnw exit` is the server end of a path: run it on a machine with fixed addresses, and each client leaves from an address of its own, or from a pool it shares.

```
vpnw exit cert --host 198.51.100.2 --name exit-de     # a private CA and the exit's certificate
vpnw exit token --out agent-1.token                   # a token for one client
vpnw exit serve --config exit-de.toml
```

```
vpnw guard --proxy https://198.51.100.2:8443 --ca ca.pem --token-file agent-1.token --policy agent-1.toml -- ./my-agent
```

Clients reach the exit over TLS, each with a token of its own. The exit decides every request again with the client's own policy file, by the same code the client used, before it connects anywhere. A client that skips its own check, or someone holding its token, gets nothing that policy refuses. Names are looked up at the exit, where `deny_private` sees where they really point, and whatever a client's policy allows, it can't reach the cloud metadata addresses vpnw knows from the exit, or the exit's own machine unless the exit's file says so. The exit's record names the client and its run and connection IDs, so it lines up with the client's own record. Plugins run at the exit as they do in a run, so Ledger can seal its record and a Guard plugin gets a say. The file format and the wire conventions are in [the reference](docs/reference.md#exit).

## Install

Download the archive for your system from the [latest release](https://github.com/VPNWorks/vpnw/releases/latest), unpack it, and put `vpnw` on your PATH:

| System | Archive |
|---|---|
| Linux, x86-64 | [vpnw_linux_amd64.tar.gz](https://github.com/VPNWorks/vpnw/releases/latest/download/vpnw_linux_amd64.tar.gz) |
| Linux, ARM64 | [vpnw_linux_arm64.tar.gz](https://github.com/VPNWorks/vpnw/releases/latest/download/vpnw_linux_arm64.tar.gz) |
| macOS, Apple silicon | [vpnw_darwin_arm64.tar.gz](https://github.com/VPNWorks/vpnw/releases/latest/download/vpnw_darwin_arm64.tar.gz) |
| macOS, Intel | [vpnw_darwin_amd64.tar.gz](https://github.com/VPNWorks/vpnw/releases/latest/download/vpnw_darwin_amd64.tar.gz) |

Then check what this machine supports:

```
vpnw doctor
```

Sealed runs need Linux with unprivileged user namespaces, the default on Debian, Fedora, Arch and most others. On Ubuntu 23.10 and later AppArmor restricts them; `vpnw doctor` says so, and you can run vpnw with sudo or allow user namespaces. On macOS, `run` and `trace` work for programs that honor proxy settings, and `learn`, `advise` and the plugin commands work as on Linux.

## Quick start

See what a program connects to:

```
vpnw trace -- ./my-agent
```

Turn that trace into a draft policy, read it, then enforce it:

```
vpnw learn --name my-agent -o my-agent.toml
vpnw guard --policy my-agent.toml -- ./my-agent
```

Learn allows whatever the program did, including anything it shouldn't have, so read the draft first. It flags raw IP addresses, uploads much larger than the downloads, and destinations on the private network (which `deny_private` will refuse).

Send a program through a WireGuard tunnel, or a proxy:

```
vpnw run --wireguard wg0.conf -- ./scraper
vpnw run --proxy socks5h://127.0.0.1:1080 -- ./scraper
```

Rules can also go on the command line:

```
vpnw guard --allow api.github.com --allow '*.pythonhosted.org' --deny-private -- pip install requests
```

A policy file:

```toml
version = 1
name = "agent"

[policy]
default = "deny"
deny_private = true
allow = ["api.github.com", "*.githubusercontent.com", "pypi.org:443"]
```

The full reference for commands, files, rules and events is in [docs/reference.md](docs/reference.md).

## Plugins

```
vpnw plugin list                 # built-in and installed plugins
vpnw plugin info learn           # what a plugin is and may do
vpnw plugin add ./geo-fence      # install from a folder
vpnw guard --policy p.toml --plugin geo-fence -- ./my-agent
vpnw advise learn --from trace.jsonl --set name=agent
```

A plugin folder holds `plugin.toml`, `plugin.wasm` and `plugin.sig`. vpnw installs signed plugins from keys you trust (`vpnw plugin trust KEY`), and unsigned ones only with `--allow-unsigned`. Before installing, it checks that the module imports nothing its manifest doesn't permit.

The rules plugins live by:

- A plugin decides and observes. It never carries traffic, so it can't slow a connection once it's open. A Guard is asked before each connection opens and gets 250 ms to decide, sleeping included; Observers and Advisors are never in the way at all.
- A plugin that crashes or runs past its time budget is stopped for the rest of the run. The run carries on and the failure goes into the record.
- A Guard that fails refuses the connection it was asked about and every one after it. Guards fail closed.
- An Observer that falls behind loses events (counted and reported) rather than slowing the program.

Writing a plugin in Go takes the SDK and one build command; [docs/plugins.md](docs/plugins.md) walks through it and documents the plugin interface for other languages.

## How it was tested

Every number here comes from `tools/record-results.sh`, which writes [test/results](test/results). The main promise is that a sealed program can't get out except through vpnw, so the integration tests try every way out they know from inside the sandbox ([bypass matrix](test/results/bypass-matrix.md)), and the plugin tests aim at the plugin promises: a plugin that panics, spins forever, writes without permission, falls behind, or fails while guarding. Costs per plugin call are in [plugins.txt](test/results/plugins.txt). WireGuard paths are tested against a real WireGuard peer running in the tests, with a web and a DNS server inside its tunnel; their speed is in [wireguard.txt](test/results/wireguard.txt). Lab, the fault kit in the tests, breaks that tunnel on purpose (a silent peer, lost handshakes, an impostor peer, a slow path, a DNS server that lies) and checks that the program hears about it, nothing goes around the tunnel, every connection has an outcome in the record, and vpnw never hangs: [lab.md](test/results/lab.md). Exit's tests run the real `vpnw exit serve` with the real vpnw as its client: fixed addresses, a client that skips its own policy, one policy file at both ends, an exit killed partway through, and clients with the wrong token or CA ([exit.md](test/results/exit.md)).

## Build from source

Go 1.24 or later:

```
sh tools/build-plugins.sh        # the built-in plugins, to WebAssembly
go build -o vpnw ./cmd/vpnw
go test ./...
```

`tools/build-plugins.sh` rebuilds the built-in plugins, `plugins/builtin/*.wasm`, from `plugins/trace`, `plugins/learn`, `plugins/ledger` and `plugins/ledgerverify`. CI runs it before every build, so released binaries always embed plugins built from the same commit.

| Folder | What's in it |
|---|---|
| `cmd/vpnw` | the command |
| `internal/broker`, `policy`, `path`, `process`, `events`, `config` | the core; `path` holds the direct, proxy and WireGuard paths |
| `internal/pluginhost` | loads and runs plugins (wazero, a pure-Go WebAssembly runtime) |
| `plugins/sdk` | the Go SDK for plugins |
| `plugins/trace`, `plugins/learn` | the built-in plugins |
| `test/integration` | end-to-end tests of the real binary |
| `test/results` | recorded results |

## License

Apache License 2.0. Copyright VPNW.com 2026. See [LICENSE](LICENSE), [NOTICE](NOTICE) and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

info@vpnw.com
