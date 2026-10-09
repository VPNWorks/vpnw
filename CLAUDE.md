# Notes for Claude

VPN Works is a core with plugins: `vpnw` (cmd/vpnw and internal/) decides,
enforces, carries and records; everything else is a WebAssembly plugin run
by internal/pluginhost. Keep features out of the core when a plugin can hold
them, and give first-party plugins no back door the plugin interface doesn't
offer everyone.

- After changing plugins/trace, plugins/learn or plugins/sdk, run
  `sh tools/build-plugins.sh` and commit plugins/builtin/*.wasm. CI rebuilds
  them anyway, but `go build` from a clean checkout embeds the committed ones.
- Built-in plugin manifests carry the release version; raise them with
  internal/version/version.go (a test checks).
- Figures quoted on vpnw.com or in the README come from
  `tools/record-results.sh`, which writes test/results.

Releases are automated. To release, raise the version and push to `main`;
never ask the owner to publish one. [RELEASING.md](RELEASING.md) has the
whole procedure and the checks to run afterwards.

## Where things stand

Read this first in a new session, and update it at the end of every release.

- **Released:** 0.4.1 (October 9, 2026): the bypass matrix's IPv6 rows run
  in CI (17 of 17 ways out blocked on the Linux runner), and a data race in
  closing plugins is fixed. 0.4.0 added WireGuard paths; 0.3.0 rebuilt VPN
  Works as a core with plugins.
- **Next:** 0.5.0, Ledger. Waiting for the owner's go-ahead.
- **How the IPv6 rows are recorded:** the machine used so far has no IPv6 in
  its kernel. CI runs the matrix on its Linux runner with
  `VPNW_REQUIRE_SEAL=1` and `VPNW_REQUIRE_IPV6=1` and leaves the table as a
  `bypass-matrix` annotation; `tools/record-results.sh` reads it back with
  `gh api` into test/results/bypass-matrix-ci.md, from the green push run of
  the same commit. Push, wait for CI, then record. The runner has no
  outbound IPv6, so the public IPv6 row shows no route outside the sandbox
  too; only the loopback row has a working control.
- **Getting Go modules here:** proxy.golang.org may be unreachable; use
  `GOTOOLCHAIN=local GOPROXY=off GONOSUMDB='*' GOFLAGS=-mod=mod` with the
  module cache already in place. CI checks the sums.

## The program

Approved by the owner on October 9, 2026. Work through it in this order.

**After each release, stop and ask the owner for the go-ahead before the
next one starts.** This keeps usage under control. Don't start the next
release on your own, even when the last one went well.

| Release | What | Status |
|---|---|---|
| 0.4.1 | Fixes: the two IPv6 escape tests run inside the test sandbox, so they no longer depend on the machine having IPv6 (16 of 16 ways out tested); small cleanups left from the reviews | released |
| 0.5.0 | Ledger | waiting |
| 0.6.0 | Lab | waiting |
| 0.7.0 | Exit | waiting |
| 0.8.0 | Tunnel plugins | waiting |

**0.5.0, Ledger.**
- Plugin interface: a new permission that lets a plugin write to one file
  vpnw opens for it. Every plugin can ask for it, not only Ledger.
- Ledger, an Observer plugin: seals each run's record as a hash chain while
  the run goes, with a checkpoint at the end.
- Verify, an Advisor plugin: checks a sealed record and names the exact line
  that was changed.
- Tests: every kind of edit to a record is caught; a run killed halfway
  leaves a record that shows the gap.
- The old engine is in the `v0.2.0` tag (engine/internal/ledger,
  engine/cmd/vpnw-ledger). Take what fits, rebuilt as plugins.

**0.6.0, Lab.**
- A fault kit the WireGuard path must pass, and any later tunnel too: a peer
  that goes silent, a lost handshake, a hostile route or DNS answer. It lives
  in the tests and doesn't ship as a feature.
- Fix whatever it finds in the same release.
- Old code: `v0.2.0` tag, engine/internal/lab.

**0.7.0, Exit.**
- The server end of a path, `vpnw exit`: fixed exit addresses, and the
  client's policy checked again at the far end.
- Old code: `v0.2.0` tag, engine/internal/exit.

**0.8.0, Tunnel plugins.**
- Open the reserved `tunnel` plugin type: a plugin hands WireGuard configs to
  the core and rotates them. The tunnel itself stays in the core, because
  plugins never carry traffic.
- First plugin: rotate through a folder of configs.

**Later, not in this program:** gateway mode (packet level, UDP), Scope as an
Advisor for gateway mode, sealing on macOS, a file-system layer. Don't start
these without the owner.

## Decisions already made

- VPN Works is one small core plus WebAssembly plugins (wazero). The core
  seals, decides, carries and records; plugins decide and observe and never
  carry traffic. Plugin types today: Observer, Advisor, Guard; `tunnel`,
  `exit` and `identity` are reserved.
- WireGuard is a built-in path in the core, run in user space without root,
  because a tunnel carries traffic. Tunnel plugins will only manage configs.
- Binaries for Linux and macOS only, no Windows.
- The repo was rebuilt from scratch in 0.3.0. Old code comes back only when
  a new piece needs it; it stays in the `v0.2.0` tag. The old browser demos
  and the Word and PDF documents are retired.
- This file is the one place that says what comes next, the same in every
  project of the owner's. There is no separate roadmap file in the repo; the
  site's roadmap page is the public version of the program below.
- The order of the program and the pause after each release were set by the
  owner. Don't reorder it without asking.
- How the project is presented (October 9, 2026, chosen by the owner): "The
  VPN, rebuilt as an operating system". The OS is named VPN Works; its
  kernel is vpnw. OS is a metaphor, used openly: the core is the kernel,
  paths are drivers, the plugin interface is system calls, plugins are apps.
  Keep the site, README and posts in those terms, and don't claim more than
  the code does (it isn't an OS you boot, a router or a VPN service).

## Every release

1. Code and tests: fuzzing for anything that parses input, and failure tests
   aimed at the release's promise.
2. An independent review agent, then fixes.
3. `tools/record-results.sh` for a fresh test/results.
4. Raise the version and push to `main`; watch the release run; download the
   binary, check SHA256SUMS and run it (RELEASING.md).
5. Site, github.com/photozeitgeist/vpnw.com (take the latest from GitHub):
   a post for the release, the roadmap page and any figures that changed.
   Content and config values only; the template and the site structure stay
   as they are, and every existing URL keeps working.
6. Update "Where things stand" and the table above, then stop and ask the
   owner for the go-ahead.
