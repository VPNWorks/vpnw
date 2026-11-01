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

- **Released:** 0.9.0 (November 1, 2026): egress budgets. Guards can put
  byte budgets on connections (the `meter` host call; internal/broker/meter.go
  counts and cuts, `connection.cut`), the built-in `budget` Guard
  (plugins/budget), and `vpnw exit serve` reloads its file
  (internal/exit/reload.go, `exit.reload`). Results in test/results/budget.md
  (7 of 7) and exit.md (23 of 23). Two independent review rounds:
  6 defects, all fixed with tests (review_090*_test.go). Guards are asked a
  refuse-only `stage: lookup` question before a policy lookup, so a refused
  name never reaches DNS. 0.8.0 (October 14, 2026): Tunnel plugins. The `tunnel`
  plugin type is open (internal/path/tunnels.go for the path,
  internal/pluginhost/tunnel.go and folder.go for the plugin side,
  plugins/rotate for the built-in), with the new `folder.read` permission.
  Results in test/results/tunnel.md (9 of 9), and Lab runs every case
  through `--wireguard` and `--tunnel rotate` (36 of 36). 0.7.0 added Exit
  (`vpnw exit`, in the core), 0.6.0 Lab, 0.5.0 Ledger and `file.write`,
  0.4.1 the IPv6 escape tests in CI, 0.4.0 WireGuard paths, 0.3.0 the core
  with plugins.
- **Next:** 0.10.0, signed ledger checkpoints (Phase B of softdev-plan.md
  item 4), approved by the owner on November 1, 2026 ("Go"). Plan below,
  under "0.10.0".
- **Budgets, what to keep in mind:** meters are per (guard, key), bounded by
  MaxMeters per guard and exit client; only metered connections leave the
  kernel copy path. Budget's request counts are per key and counted when it
  lets a connection through at the decision stage, never at `lookup`. A
  Guard built with the 0.9 SDK imports `meter`, which 0.8 refuses. Exit
  reload: every broker.Client generation of a name is kept in `gens` and
  revoked together; the files are hashed from the same bytes they're parsed
  from; a refused reload also watches the files it tried to read.
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

## 0.10.0: signed ledger checkpoints (Phase B)

What and why: a ledger written again from scratch, chain and all, is caught
today only by copies kept elsewhere. Signatures from a key the core holds,
which no plugin can read, make each checkpoint evidence a third party can
check with the public key alone: a ledger rewritten after a checkpoint
fails `vpnw verify`.

Design decisions:
- The key: Ed25519, one per machine and user, `~/.config/vpnw/signing.key`
  (`vpnw-ed25519-private:` format, 0600), made on first use; `--sign-key
  FILE` in run, trace, guard and exit serve. `vpnw key` prints its path and
  public key (making it if missing). The plugin never sees it.
- Plugin interface: permission `sign`, host call `sign(msg, len, out) ->
  i32`: the core signs `"vpnw-signed v1\n" + plugin + "\n" + run + "\n" +
  msg` (msg printable ASCII, at most 1 KiB) and writes 64 bytes to out. The
  plugin's name and the run are the core's, so a plugin can only sign as
  itself, for this run. Config gains `sign_key` (the public key) when
  signing is available; none in advise.
- Ledger: header `{"vpnw-ledger":1,"run":"…","key":"vpnw-ed25519:…"}` when
  signed (the key is in h0, so it's in the chain); after each checkpoint
  line `{"sig":K,"s":"<base64>"}` over `cp K N <h>`, after the end line
  `{"sig":"end","s":"…"}` over `end N K <h>`. Signature lines aren't chain
  links. The trace copies carry `sig` too. `ledger.sign=false` writes an
  unsigned ledger, as 0.9 did.
- Verify (`vpnw verify LEDGER [TRACE]... [--head H] [--key KEY|FILE]`): a
  signed ledger is checked against `--key`, or else this machine's key; a
  ledger signed by another key fails against either. Each checkpoint and the
  end must carry a valid signature; a missing or wrong one is CHANGED with
  its line. `--key` on an unsigned ledger fails. With no key to check
  against, the report says who signed it and that it wasn't checked.
- Limit, documented: the watched program runs as the same user and could
  read the key file (sealing is network only); keep the key where it can't
  (`--sign-key` on a path the program's user can't read, or vpnw run as
  another user). Entries after the last signed checkpoint of a killed run
  are covered by the chain only.
- Done when: a ledger rewritten after a checkpoint (chain recomputed,
  signature lines kept) fails verify, naming the checkpoint; so do stripped
  signatures and a ledger signed by another key.

Steps:
1. [ ] core: key file, `vpnw key`, `--sign-key`, permission `sign`, host call, SDK; tests
2. [ ] chain + seal: signed header, signature lines, trace copies; verifier; tests
3. [ ] ledger-verify and `vpnw verify --key`; integration test of the rewrite
4. [ ] README, docs, independent review, fixes, record-results.sh
5. [ ] release 0.10.0; vpnw.com post; softdevstudio note; softdev-plan.md

## 0.9.0: egress budgets (Phase A)

What and why: an AI agent or a build script given network access can send
anything anywhere. A domain allowlist with byte and request budgets per
host, enforced by vpnw and recorded in the ledger, bounds what it can send
out and to whom. Exits served to several clients need clients added without
a restart.

Design decisions:
- Budgets are a Guard interface addition any Guard can use, not a back
  door for the built-in: a new host call `meter(ptr, len)` (no permission,
  Guards only), called before `vpnw_on_decide` returns 0, with
  `{"key":"...","up":N,"down":N,"reason":"..."}`. The core keeps one meter
  per (plugin, key) for the run (at an exit, for the exit's run); every
  connection given that key adds its bytes to it. A connection that would
  pass `up` or `down` is sent only up to the limit, then closed: a
  `connection.cut` event (rule `plugin:NAME`, the reason, key, which limit,
  bytes = the budget), then its `connection.close`. A connection asked for once a
  meter is spent is refused (`policy.deny`, same rule). Only metered
  connections leave the kernel copy path. Plugins still never carry traffic.
- Built-in Guard `budget` (plugins/budget), settings only (no file, so no
  folder that must exist):
  `allow` = entries separated by `;`, each a host (`api.github.com`), a
  subdomain pattern (`*.npmjs.org`), an IP, or `*` (any host), optionally
  followed by `up=SIZE down=SIZE requests=N`; `up`, `down`, `requests`
  settings are defaults for entries that set none. Sizes: B, KB, MB, GB
  (1000s), KiB, MiB, GiB. A host on no entry is refused ("not on the
  allowlist"). A pattern's hosts share one budget (so a wildcard can't be
  used to mint budgets); `*` gives each host its own. Requests are
  connections, counted by the plugin; at an exit every key carries the
  client, so each client has its own budgets.
- Trace prints `connection.cut`; Ledger seals it like every event.
- Exit hot reload: `vpnw exit serve` checks its config file and the policy
  files it names every 2 s (contents, not times). A changed file is read
  again whole; if it's invalid, the old clients stay and the error is
  printed and recorded (`exit.reload`, with `error`). If valid: clients
  added, removed and changed are swapped in (`exit.reload` names them); a
  removed client, or one whose token changed, has its open connections
  closed; others keep theirs, and new requests use the new policy. Changes
  to name, listen, cert or key need a restart and are reported as such; a
  new source address must be on the machine, or the reload is refused.
  SIGHUP keeps stopping the exit (unchanged).
- Upkeep: release and test workflows build with `go-version: stable`;
  go.mod stays `go 1.24` (this sandbox has only Go 1.24.7). README build
  section lists all six built-in plugins and `rotate`.
- Done when: a recorded agent session (test/results) hits its byte budget
  and is cut off, with the ledger entry; a client added to a running exit
  can use it without a restart.

Steps:
1. [x] core meters + `meter` host call + SDK `Budget`; tests
2. [x] plugins/budget; tests; Trace line for connection.cut
3. [x] exit hot reload; tests
4. [x] agent-session recording (test/results/budget.md), README, docs,
       workflows on stable Go
5. [x] independent review, fixes, record-results.sh
6. [ ] release 0.9.0; vpnw.com post; softdevstudio note; softdev-plan.md

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
| 0.9.0 | Egress budgets (softdev-plan.md item 4, Phase A) | released |

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
