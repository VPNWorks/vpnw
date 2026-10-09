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

- **Released:** 0.4.0 (October 9, 2026), WireGuard paths. 0.3.0 before it
  rebuilt VPN Works as a core with plugins.
- **Now:** 0.4.1 under way.
- **Waiting for the owner:** nothing yet.

## The program

Approved by the owner on October 9, 2026. Work through it in this order.

**After each release, stop and ask the owner for the go-ahead before the
next one starts.** This keeps usage under control. Don't start the next
release on your own, even when the last one went well.

| Release | What | Status |
|---|---|---|
| 0.4.1 | Fixes: the two IPv6 escape tests run inside the test sandbox, so they no longer depend on the machine having IPv6 (16 of 16 ways out tested); small cleanups left from the reviews | under way |
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
