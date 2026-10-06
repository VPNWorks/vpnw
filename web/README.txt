VPN Works: the browser demos
============================

VPN Works keeps network access narrow and on the record.

One folder per engine. Open its index.html in a web browser. There is
nothing to install, and nothing leaves the page: it makes no network
requests at all. The same demos are online at https://vpnw.com/demo/

app/      The Agent. A coding agent runs a task whose task file hides an
          instruction to send a deploy token to an attacker. Six steps show
          vpnw tracing the agent, learning a policy from the trace, blocking
          the token, routing the agent through an office exit, sealing off a
          script that ignores proxy settings, and refusing the cloud metadata
          address. Under the replay, two panels let you run the agent under
          your own policy and ask the engine about any destination.
scope/    Scope. A made-up office of 30 people learns least-privilege VPN
          rules from two weeks of traffic, replays the week after and meets a
          stolen login.
lab/      Lab. Two stand-in VPN clients go through a five-second server
          outage, and one of them sends its DNS outside the tunnel while it
          reconnects.
ledger/   Ledger. The Agent's recorded run, sealed in the page with a key made
          in your browser. Change a record or delete one, and the check names
          the line.
exit/     Exit. Two agents and two exits in two "countries", a stolen token
          refused at the exit, and an exit that fails partway.

Each page says what is real and what is a stand-in. In short: the engines
are real, and each page runs its engine's own Go code, compiled to
WebAssembly with TinyGo, in its engine script (engine*.js). The runs they
replay were recorded in private test networks on Linux, with stand-ins for
the agents, servers, offices, VPN apps and attackers. Scope's office is
generated from a fixed seed.

tools/ builds the engine scripts from engine/wasm (build_*_js.py) and plays
each page through in headless Chromium (check_*_demo.js). The two loaders in
tools/ are unchanged copies: wasm_exec_tinygo.js from TinyGo's targets/
folder and wasm_exec_go.js from Go's lib/wasm/ folder.

The demos have been tested in Chromium, at computer and phone screen sizes.
They use only standard JavaScript and WebAssembly, so current Chrome, Edge,
Firefox and Safari should run them.

VPN Works is open source under the Apache License 2.0. Copyright VPNW.com
2026. The code is at https://github.com/VPNWorks/vpnw. The engine scripts
include code under the Go, TinyGo and musl licenses; see
THIRD-PARTY-LICENSES.txt.
