# Notes for Claude

VPN Works is a core with plugins: `vpnw` (cmd/vpnw and internal/) decides,
enforces, carries and records; everything else is a WebAssembly plugin run
by internal/pluginhost. Keep features out of the core when a plugin can hold
them, and give first-party plugins no back door the plugin interface doesn't
offer everyone.

- After changing anything under plugins/ (trace, learn, ledger, ledgerverify,
  rotate, sdk), run `sh tools/build-plugins.sh` and commit
  plugins/builtin/*.wasm. CI rebuilds them anyway, but `go build` from a
  clean checkout embeds the committed ones. They stay uncompressed on
  purpose: unpacking one cost every run about 40 ms.
- Built-in plugin manifests carry the release version; raise them with
  internal/version/version.go (a test checks).
- Figures quoted on vpnw.com or in the README come from
  `tools/record-results.sh`, which writes test/results.

Releases are automated. To release, raise the version and push to `main`;
never ask the owner to publish one. [RELEASING.md](RELEASING.md) has the
whole procedure and the checks to run afterwards.

## Where things stand

Read this first in a new session, and update it at the end of every release.

- **Released:** 0.8.0 (October 14, 2026): Tunnel plugins. The `tunnel`
  plugin type is open (internal/path/tunnels.go for the path,
  internal/pluginhost/tunnel.go and folder.go for the plugin side,
  plugins/rotate for the built-in), with the new `folder.read` permission.
  Results in test/results/tunnel.md (9 of 9), and Lab runs every case
  through `--wireguard` and `--tunnel rotate` (36 of 36). 0.7.0 added Exit
  (`vpnw exit`, in the core), 0.6.0 Lab, 0.5.0 Ledger and `file.write`,
  0.4.1 the IPv6 escape tests in CI, 0.4.0 WireGuard paths, 0.3.0 the core
  with plugins.
- **Next:** the approved program is complete. Waiting for the owner to say
  what comes next; nothing from "Later" starts without the owner.
- **Tunnel plugins, what to keep in mind:**
  - Liveness counts only what WireGuard accepted: rx_bytes from IpcGet,
    polled each second (`Silent`), with the socket's arrival time as the
    timestamp; `begin` resets it when Health completes. Rotated-out tunnels
    are watched too, and one that went silent is never moved back to.
  - One key and peer, one tunnel: a config handed over again while its
    tunnel winds down gets that tunnel back (same name and text, not failed
    or silent); one sharing key and peer with the tunnel in use is refused;
    a new tunnel cuts rotated-out ones that share them (`why` "replaced").
    ListenPort clashes are refused; at most 16 peers per plugin config; at
    most 4 tunnels wind down.
  - What the plugin is told of a failed tunnel (`toPlugin`) leaves out
    resolved addresses and resolver errors; config errors never quote a
    line beyond a key's name or an address-like value. Trust model, in the
    docs: a Tunnel plugin chooses where traffic goes.
  - Known and documented: `--tunnel` only on the command line (not in
    `[paths]`, not at an exit); an idle rotated-out tunnel whose peer died
    is moved back to and fails over after 20 s.
- **The netstack copy:** internal/path/netstack is wireguard-go's
  tun/netstack at the pinned version, with one change: Close never closes
  the channel packets are sent on (the original panicked vpnw when a tunnel
  closed under traffic). When raising wireguard-go, copy the new file and
  apply the change again; TestCloseWhileSending panics on the original.
  record-results counts it apart from the core and leaves it out of
  coverage.
- **Exit, what to keep in mind:** tokens are kept as SHA-256 hashes; the
  exit's own machine is refused unless the client has `allow_exit_host`,
  and link-local, multicast and cloud metadata always are (`path.Refusal`,
  rule `exit`); a refusal of a name doesn't tell the client what the name
  resolved to. Limits before login and per client are variables at the top
  of internal/broker/exit.go. Known and documented: the file is read at
  start, so a new client means a restart; over SOCKS5 a refusal carries no
  reason. The `exit` plugin type stays reserved: Observers and Guards run
  at an exit, and a Guard's request carries `Client`. The integration tests
  use sources 127.0.0.2 and up, which only Linux has; off Linux the
  in-process test uses a pool.
- **Speed figures vary with this machine:** 0.8.0 recorded 54 MB/s through
  WireGuard; side by side the same evening, HEAD and v0.7.0 both measured
  55 to 64 MB/s (0.7.0 recorded 60, 0.6.0 99 on a faster day). Compare
  speeds only within one recording; the site's Platform page says so.
  record-results.sh takes about fifty minutes.
- **Lab, for later tunnels:** a new path or tunnel plugin gets the same
  cases through `labPeer` and `labVias` (each case runs once per way to
  the tunnel, `--wireguard` and `--tunnel rotate` today). Every case
  records a row with `labRecord(t, v, …)` built from measured values;
  `labGuard` gives a test that stops early a FAILED row. The hostile-route fault is covered as a reroute (impostor);
  a pushed route can't move a sealed program, since the tunnel doesn't use
  the host's routing table.
- **Ledger's limits, known and documented:** no signed checkpoints (a
  plugin can't hold a key it can't read; noted as an open question on the
  roadmap). A ledger written again from scratch is caught only by the
  checkpoint copies in the trace or the printed last hash, kept elsewhere.
  The watched program runs as the user and could rewrite both files.
- **Binary size:** the five built-in plugins are embedded uncompressed
  (about 19 MB of WebAssembly; the binary is 31 MB). Shipping them gzipped
  saved 11 MB but cost every run about 40 ms to unpack Trace, so it was
  reverted.
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
| 0.5.0 | Ledger | released |
| 0.6.0 | Lab | released |
| 0.7.0 | Exit | released |
| 0.8.0 | Tunnel plugins | released |

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
