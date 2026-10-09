# Writing a plugin

A VPN Works plugin is a WebAssembly module plus a manifest. vpnw runs it in a sandbox inside its own process, with the [wazero](https://wazero.io) runtime. The plugin gets no files, no network, no environment variables and no arguments. It talks to vpnw only through the hooks it exports and the host calls it imports, and vpnw refuses, before running a single instruction, any module that imports a host call its manifest doesn't ask for.

This page shows how to write one in Go with the SDK, then documents the interface itself (ABI 1) for any language that compiles to WASI.

## Types

| Type | vpnw calls | Runs with |
|---|---|---|
| `observer` | `OnEvent` for every event of a run, as it happens, then `Finish` | `vpnw run/trace/guard --plugin NAME` |
| `advisor` | `OnEvent` for every event of the traces it's given, then `Finish`, where it writes its advice | `vpnw advise NAME --from FILE` |
| `guard` | `OnDecide` for every connection the policy allowed | `vpnw run/trace/guard --plugin NAME` |

`Init` comes first for every type. `tunnel`, `exit` and `identity` are reserved for later versions of vpnw; a manifest with one of them is refused with that message.

## A Guard in Go

A Guard that refuses one domain and everything under it, with the domain as a setting:

```go
package main

import (
	"strings"

	"github.com/VPNWorks/vpnw/plugins/sdk"
)

var blocked string

func init() {
	sdk.Register(sdk.Plugin{
		Init: func(c *sdk.Config) error {
			blocked = c.Settings["domain"]
			return nil
		},
		OnDecide: func(r *sdk.Request) (bool, string) {
			if blocked != "" && (r.Host == blocked || strings.HasSuffix(r.Host, "."+blocked)) {
				return true, r.Host + " is under " + blocked
			}
			return false, ""
		},
	})
}

func main() {}
```

Register from `init`, not `main`: vpnw starts a plugin as a library (a WASI reactor), so `main` never runs.

`plugin.toml` next to it:

```toml
name = "no-domain"
version = "0.1.0"
type = "guard"
abi = 1
description = "Refuses one domain and its subdomains"
permissions = []
```

Build, sign, install and use it:

```
GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o plugin.wasm .
vpnw plugin keygen -o mykey              # once: mykey.key (private) and mykey.pub
vpnw plugin sign --key mykey.key .
vpnw plugin trust mykey.pub              # on each machine that should accept your plugins
vpnw plugin add .
vpnw guard --policy p.toml --plugin no-domain --set no-domain.domain=tracker.example -- ./my-agent
```

A refusal shows up like any other denial, with the rule `plugin:no-domain` and your reason.

The SDK's hooks run as ordinary Go: test them with `go test` on your machine. Outside WebAssembly, `sdk.CallInit`, `CallEvent`, `CallDecide` and `CallFinish` run your hooks with the JSON vpnw would send, and `sdk.TestStdout`, `TestStderr`, `TestEmit` and `TestLog` catch what the plugin sends back.

## Manifest

| Key | Required | Value |
|---|---|---|
| `name` | yes | lower-case letters, digits and dashes, starting with a letter, at most 40. `trace` and `learn` are taken |
| `version` | yes | `X.Y.Z`, optionally with a `-pre` or `+build` part |
| `type` | yes | `observer`, `advisor` or `guard` |
| `abi` | yes | `1` |
| `description` | no | one line of at most 200 characters, shown by `vpnw plugin list` |
| `permissions` | no | a list from the table below |

Unknown keys and tables are errors, never silently skipped.

| Permission | Lets the plugin |
|---|---|
| `console` | write to vpnw's standard output and error (`sdk.Stdout`, `sdk.Stderr`) |
| `events.emit` | add its own events to the run's record (`sdk.Emit`) |

Logging (`sdk.Log`, shown with `--verbose`), reporting an error, and giving the reason for a refusal need no permission.

## Settings

Settings are strings, given on the command line:

- `--set NAME.KEY=VALUE` for plugins in `run`, `trace` and `guard`, as in `--set trace.level=all`
- `--set KEY=VALUE` for `vpnw advise NAME`

A plugin reads them from `Config.Settings` in `Init` and returns an error for one it doesn't accept; vpnw stops with that message. The one exception is the console: if the built-in Trace plugin refuses its settings, vpnw prints the run's events as JSON instead and carries on. A `--set` for a plugin that isn't part of the run is an error.

`Config` also says which command is running, whether the console shows colour, and the local time zone (a plugin has no time zone database).

## Events

An event is one JSON object:

```json
{"v":1,"ts":"2026-10-09T09:47:25.496Z","type":"connection.attempt","run":"r-ee6c61","pid":7826,"path":"direct","conn":1,
 "fields":{"host":"api.github.com","port":443,"proto":"http-connect"}}
```

The types and their fields are listed in [reference.md](reference.md#events). Events a plugin emits are named `plugin.<name>.<type>`, so a plugin can never pass one off as vpnw's own; `<type>` is one to three dot-separated words of lower-case letters, digits and underscores. A plugin's own events go into the record but are not handed back to it.

Text a plugin sends that may reach the console (a refusal reason, an error message, a log line, the strings in an emitted event) has control characters and the Unicode marks that reorder text replaced with `?`, and is cut to length: 300 characters for a reason, 500 for an error. Only the `console` permission writes to the terminal as is.

Decoding JSON is a large share of a plugin's time. A plugin that decodes events into its own types can set `RawEvents: true` and read `Event.Raw` only, so it doesn't pay twice.

## Time budgets and failures

| Call | Budget |
|---|---|
| starting the module and `Init` | 10 s |
| one event | 5 s |
| `Finish` | 60 s |
| one Guard decision | 250 ms |
| waiting for a Guard's turn, when many connections ask at once | 5 s |

Every plugin is held to its budgets: the runtime checks for the end of the budget at every function call and loop, and stops the plugin there. A sleep never lasts past the end of the budget either; the plugin's clock and sleep come from vpnw, and vpnw cuts the sleep short. That makes plugin code roughly four to five times slower than it would otherwise be, and it's the only safe choice: code that can't be interrupted can't be paused by Go's garbage collector either, so one endless loop would freeze vpnw.

A request that waits longer than 5 seconds for a busy Guard is refused, with a reason that says so, and the Guard carries on. A plugin that panics, traps, exits, reports an error or runs out of budget is stopped for the rest of the command. vpnw reports it on the console and records a `plugin.error` event; the program keeps running. A Guard that has stopped refuses every connection it's asked about from then on: Guards fail closed. Calls into one plugin are taken one at a time, so a Guard asked about many connections at once answers them in turn.

An Observer gets events through a queue of 8,192. If it falls further behind, events are dropped for it, counted, and reported at the end of the run; the program is never slowed down. After the run it has 5 seconds to work through what's queued.

Each plugin gets up to 128 MiB of memory.

## The interface (ABI 1)

For plugins in other languages: the module must be a WASI (`wasi_snapshot_preview1`) reactor, which means it exports `_initialize` and `memory`, and it may import only from `wasi_snapshot_preview1` and `vpnw`. WASI gives it a clock, random numbers, and a standard error that vpnw reads only to quote a crash message; there are no files, sockets, environment or arguments behind it.

### Exports

| Export | Signature | Meaning |
|---|---|---|
| `vpnw_abi` | `() -> i32` | returns 1 |
| `vpnw_alloc` | `(len i32) -> ptr i32` | a buffer of `len` bytes that vpnw fills before calling a hook; the plugin keeps it alive until that hook returns |
| `vpnw_init` | `(ptr, len) -> i32` | the config, as JSON; 0 for success |
| `vpnw_on_event` | `(ptr, len) -> i32` | one event, as JSON; 0 for success. Observers and Advisors |
| `vpnw_finish` | `() -> i32` | the events are over; 0 for success. Advisors (and Observers, if exported) |
| `vpnw_on_decide` | `(ptr, len) -> i32` | one request, as JSON; 0 lets it through, 1 refuses it. Guards |

All of them take and return `i32`; vpnw refuses a module whose exports have other signatures. Any other result means failure: the plugin should have called `error` first with the message.

### Host calls (module `vpnw`)

| Import | Signature | Needs |
|---|---|---|
| `log` | `(ptr, len)` | nothing |
| `error` | `(ptr, len)` | nothing: the message for a failing hook |
| `reason` | `(ptr, len)` | nothing: the reason for a refusal, called before `vpnw_on_decide` returns 1 |
| `write` | `(stream i32, ptr, len)` | `console`; stream 1 is standard output, 2 standard error |
| `emit` | `(ptr, len)` | `events.emit`; JSON `{"type": "...", "fields": {...}}` |

### Config (`vpnw_init`)

```json
{"plugin":"no-domain","command":"guard","settings":{"domain":"tracker.example"},"color":false,"tz_offset":10800,"tz_name":"IDT"}
```

### Request (`vpnw_on_decide`)

```json
{"run":"r-3f9a1c","conn":17,"pid":4242,"path":"office","host":"api.github.com","port":443,"proto":"http-connect"}
```

`host` is empty when the program asked for an address, which is then in `ip`. `proto` is `http-connect`, `http` or `socks5`. The policy has already allowed the connection; a Guard can only refuse it.

## Signatures

`plugin.sig` holds two lines: the signer's public key (`vpnw-ed25519:` and base64) and an Ed25519 signature, in base64, over

```
sha256("vpnw-plugin-signature-v1\n" || sha256(plugin.toml) || sha256(plugin.wasm))
```

Trusted keys are one per line in `~/.config/vpnw/trusted-keys`. vpnw checks an installed plugin's signature again every time it loads it, so taking a key out of that file stops the plugins it signed.
