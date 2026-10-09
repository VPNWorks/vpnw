# VPN Works

VPN Works decides where every connection goes. It gives each program its own network path, its own policy and its own record, and everything beyond that small core is a plugin.

```
vpnw guard --policy agent.toml -- ./my-agent
```

That runs `my-agent` sealed off from the network. Its only way out is vpnw, which checks every connection against `agent.toml`, sends the allowed ones down the path you chose, refuses the rest, and writes down what happened.

Open source under the Apache License 2.0. Linux first; macOS for the parts that don't need Linux. Site: [vpnw.com](https://vpnw.com).

## What it's for

An ordinary VPN gives your whole machine one way out. VPN Works works one level down: per program. An AI coding agent, a build script, a scraper or a container each get their own path (direct, a WireGuard tunnel, a SOCKS or HTTP proxy, a proxy over TLS, a list of exits with failover) and their own rules (which hosts, which ports, nothing on the private network). A program that ignores proxy settings doesn't leak around vpnw; on Linux it has no route anywhere else.

The core does four things and nothing else:

- **Decide**: the broker takes every connection and asks the policy.
- **Enforce**: on Linux the program runs in a network namespace with nothing but loopback, and a seccomp filter keeps it off Unix sockets and io_uring, so the broker is the only way out.
- **Carry**: allowed connections go down the chosen path.
- **Record**: every decision becomes an event. Events record hosts, addresses, ports, byte counts and decisions, never payloads, URL paths, headers or passwords.

Plugins do the rest. They're WebAssembly modules that run in a sandbox inside vpnw with no files, no network and no environment, and they reach vpnw only through the calls their manifest asks for. Three kinds run today:

| Type | What it does | Built in |
|---|---|---|
| **Observer** | Watches a run's events as they happen | `trace`: the console output of run, trace and guard |
| **Advisor** | Reads recorded traces and writes advice | `learn`: turns a trace into a draft policy |
| **Guard** | Can refuse a connection the policy allowed | none yet |

Tunnel, Exit and Identity plugins come in later versions.

## WireGuard, without root

Give vpnw the WireGuard config your VPN provider (or your own server) hands out, and one program goes through the tunnel while the rest of your machine doesn't:

```
vpnw guard --wireguard mullvad-de.conf --policy agent.toml -- ./my-agent
```

vpnw runs the tunnel itself, inside its own process: the WireGuard protocol from the official wireguard-go and a TCP/IP stack from gVisor. No root, no kernel module, no network interface on the machine, and nothing changes for any other program. Names are looked up through the tunnel at the DNS servers in the config, so lookups don't leak, and the policy still checks every address before anything is sent. If the tunnel doesn't come up (a wrong key, a blocked port) the program never starts.

WireGuard is a built-in path, like the proxy paths, not a plugin: it carries every byte, and plugins never carry traffic. It's a registered trademark of Jason A. Donenfeld; VPN Works isn't affiliated with the WireGuard project.

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

Every number here comes from `tools/record-results.sh`, which writes [test/results](test/results). The main promise is that a sealed program can't get out except through vpnw, so the integration tests try every way out they know from inside the sandbox ([bypass matrix](test/results/bypass-matrix.md)), and the plugin tests aim at the plugin promises: a plugin that panics, spins forever, writes without permission, falls behind, or fails while guarding. Costs per plugin call are in [plugins.txt](test/results/plugins.txt). WireGuard paths are tested against a real WireGuard peer running in the tests, with a web and a DNS server inside its tunnel; their speed is in [wireguard.txt](test/results/wireguard.txt).

## Build from source

Go 1.24 or later:

```
sh tools/build-plugins.sh        # the built-in plugins, to WebAssembly
go build -o vpnw ./cmd/vpnw
go test ./...
```

`tools/build-plugins.sh` rebuilds `plugins/builtin/*.wasm` from `plugins/trace` and `plugins/learn`. CI runs it before every build, so released binaries always embed plugins built from the same commit.

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
