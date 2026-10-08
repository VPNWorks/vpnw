# VPN Works

**VPN Works keeps network access narrow and on the record.** It is a family of five small networking engines on one shared core, written in Go with the standard library only, Linux first.

| Engine | Command | What it does | Version |
|---|---|---|---|
| Agent | `vpnw` | Gives one program, usually an AI agent, its own network on Linux: a sealed sandbox whose only way out is vpnw, a path you choose, a policy the program can't get around and a record of every connection | 0.2.0 |
| Scope | `vpnw-scope` | Learns least-privilege access for a company VPN from its traffic, replays a draft before anything is enforced, and writes the rules for the gateway's firewall | 0.1.0 |
| Lab | `vpnw-lab` | A test bench for VPN apps: it runs an app in a private test network, breaks things on a timetable and catches anything that leaves outside the tunnel | 0.1.0 |
| Ledger | `vpnw-ledger` | Seals a log of connections so that any change shows, checks it offline and proves single records | 0.1.0 |
| Exit | `vpnw-exit` | Fixed exit addresses for agents and CI jobs, with the client's policy checked again at the exit and one record joined from both ends | 0.1.0 |

All five are Alphas. Each works and has been tested on one Linux machine with two CPUs, in private test networks, with stand-ins for the agents, servers, offices and VPN apps. None has had real users yet. Each engine has a page and a live demo at [vpnw.com](https://vpnw.com/), and each report below says what was measured, what wasn't, and how far the engine is from a first release.

## Reports

| Engine | Report | Measured results |
|---|---|---|
| Agent 0.1.0 | [vpnw.com/alpha](https://vpnw.com/alpha/) | `engine/results/alpha` (September 29, 2026) |
| Agent 0.2.0 | [docs/agent-0.2.0.md](docs/agent-0.2.0.md) | `engine/results/agent-0.2.0` |
| Scope | [vpnw.com/scope](https://vpnw.com/scope/) | `engine/results/scope-alpha` |
| Lab | [docs/lab-alpha.md](docs/lab-alpha.md) | `engine/results/lab-alpha` |
| Ledger | [docs/ledger-alpha.md](docs/ledger-alpha.md) | `engine/results/ledger-alpha` |
| Exit | [docs/exit-alpha.md](docs/exit-alpha.md) | `engine/results/exit-alpha` |

## What is where

```
engine/                 the Go module vpnw.com/vpnw, standard library only
  cmd/                  vpnw, vpnw-scope, vpnw-lab, vpnw-ledger, vpnw-exit, and scope-office (Scope's demo data)
  internal/             the shared core: config, events, policy, plan, path, broker, process, learn, version
                        and one package per engine: scope/, lab/, ledger/, exit/; testnet/ builds the test networks
  wasm/                 the browser builds, compiled with TinyGo: the Agent at the top, the others in their own folders
  test/                 tests of the real binaries: integration/ (the Agent), and scope/, lab/, ledger/, exit/ against the Linux kernel
  tools/                the measurement scripts, planted bugs and performance scripts behind every published figure
  results/              every results log, as measured
web/                    the five browser demos: app/ (the Agent), scope/, lab/, ledger/, exit/; tools/ builds and checks them
recordings/             the Agent demo's six recorded runs
kit/                    the Agent's Linux demo: README, licenses and the demo world
docs/                   the reports of Lab, Ledger, Exit and Agent 0.2.0
```

## Download

Ready-built binaries for Linux (x86-64 and ARM64, static) and macOS are on the [releases page](https://github.com/VPNWorks/vpnw/releases/latest). Each archive holds all five commands and `scope-office`, with the license files; SHA256SUMS lists the checksums. The newest archive for each system is always at the same address, such as https://github.com/VPNWorks/vpnw/releases/latest/download/vpnw_linux_amd64.tar.gz.

Releases go out on their own. When the tests pass on main and the version in `engine/internal/version/version.go` has no tag yet, the release workflow builds and checks the binaries, then tags the commit and publishes them.

## What you need

- Linux on x86-64 with unprivileged user and network namespaces, for sealed runs and the kernel tests. On Ubuntu 23.10 and later AppArmor restricts them, and `vpnw doctor` says so.
- Go 1.24. Everything here was built and tested with 1.24.7. There are no third-party modules.
- nftables (`nft`) for the kernel tests of Scope, Lab, Ledger and Exit, and the TUN driver for Lab's.
- python3 for the measurement scripts and the Agent's demo world, and openssl for Exit's measurements.
- Optional: TinyGo 0.39 for the browser engines, and Node 22 with Playwright for the headless demo checks.

When the machine lacks one of these, the kernel tests skip, with the reason.

## Build and test

```
cd engine
go vet ./...
go test ./...
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/ ./cmd/...
bin/vpnw doctor
```

The kernel tests of Scope, Lab, Ledger and Exit start themselves again under `unshare`, as root in a user namespace of their own, so they need no root on the machine. The Agent's sealed runs need none either.

## Reproduce the figures

Each engine has one script that measures every figure in its report and writes its results folder. Run them from `engine/`, one at a time, on an idle machine:

| Engine | Script | Time on a machine with two CPUs, with the default 60 seconds of fuzzing per target |
|---|---|---|
| Agent | `tools/measure.sh` | about 10 minutes |
| Scope | `tools/measure-scope.sh` | about 12 minutes |
| Lab | `tools/measure-lab.sh` | about 36 minutes |
| Ledger | `tools/measure-ledger.sh` | about 13 minutes |
| Exit | `tools/measure-exit.sh` | about 9 minutes |

`FUZZTIME=10s` shortens the fuzzing. Put TinyGo on PATH to get the browser engines' sizes too; the scripts of Scope, Lab, Ledger and Exit then also rebuild their demo's engine script and, with Node and Playwright, check the page in headless Chromium.

## The browser demos

Each folder in `web/` opens from disk, with no network requests: open its `index.html`. The engine scripts (`engine*.js`) are built from `engine/wasm` with TinyGo by `web/tools/build_*_js.py`, and `web/tools/check_*_demo.js` plays each page through at computer and phone widths. The live versions are at [vpnw.com/demo](https://vpnw.com/demo/).

`web/app/engine.v1.js` and `web/scope/engine.scope.v1.js` are the builds the Agent and Scope demos have run since October 1, 2026. Agent 0.2.0 changed the shared configuration reader since, so a build from this tree differs from them in its bytes.

## The Agent's Linux demo

```
cp engine/bin/vpnw kit/vpnw
kit/demo/run-demo.sh              # --no-pause plays it straight through
```

It builds its own private network with stand-in servers, needs no root and changes nothing on the machine. `kit/README.txt` says what each step shows.

## License

VPN Works is open source under the Apache License 2.0. Copyright VPNW.com 2026. The code is at https://github.com/VPNWorks/vpnw. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

The browser engines include code under the Go, TinyGo and musl licenses, listed in `web/THIRD-PARTY-LICENSES.txt`. The Linux binaries include the Go standard library, whose license is in `kit/THIRD-PARTY-LICENSES.txt`.

Contact: info@vpnw.com
