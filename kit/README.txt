VPN Works Agent: the Linux demo kit
===================================

VPN Works keeps network access narrow and on the record. Its Agent, vpnw,
gives one program its own network: you choose where its traffic exits and
where it is allowed to go, and every connection is logged. One binary, no
dependencies, on networks you already have.

This folder holds an offline demo of the Agent and this guide. Put a vpnw
binary next to this file first, built from the code in this repository:

    (cd ../engine && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/vpnw ./cmd/vpnw)
    cp ../engine/bin/vpnw .


THE DEMO (about a minute, offline)
----------------------------------

    cd demo
    ./run-demo.sh

A stand-in coding agent runs a task whose task file hides an instruction to
send a deploy token to evil.example. The demo shows vpnw tracing it, learning
a policy from the trace, blocking the token, routing the agent through an
office exit, sealing off an agent that ignores proxy settings, and refusing a
cloud metadata address.

The demo builds its own private network with stand-in servers, inside a
namespace of its own. It leaves your network and your settings alone, and it
needs no root.

It needs Linux with unprivileged user namespaces (the default on Debian,
Fedora, Arch and most others), python3, unshare (from util-linux) and curl.

On Ubuntu 23.10 and later, AppArmor restricts user namespaces and
./vpnw doctor says so. For a quick look, run the demo with sudo; it still
stays inside its own private network. The Beta ships an AppArmor profile.

Options: ./run-demo.sh --no-pause plays it straight through, and
--record=DIR saves each step's output and trace.


ON YOUR OWN PROGRAMS
--------------------

    ./vpnw doctor                        # what this machine supports
    ./vpnw trace -- ./my-agent           # every connection, printed
    ./vpnw learn --name my-agent > my-agent.toml   # a draft from that trace
    ./vpnw guard --policy my-agent.toml -- ./my-agent
    ./vpnw run --proxy socks5h://127.0.0.1:1080 -- ./my-agent
                                         # through a SOCKS5 proxy you run
    ./vpnw help

A policy file:

    version = 1
    name = "agent"

    [policy]
    default = "deny"
    deny_private = true
    allow = ["api.github.com", "*.pythonhosted.org"]

Exit codes: the program's own, or 120 when guard denied a connection and the
program would have exited with 0, 121 for a usage or configuration error, 122
when enforcement is not available here, 123 when the chosen path cannot be
used, 124 when vpnw itself failed, 126 when the program cannot be run and 127
when it is not found.


WHAT THE ALPHA COVERS
---------------------

- Linux only for sealed runs. The program gets a network namespace of its
  own with nothing but loopback; its one way out is vpnw. So far the Alpha
  has run on one x86-64 machine; the arm64 build compiles but hasn't been
  run. Other systems are meant to get run and trace with --backend env, for
  programs that honor proxy settings, and guard refuses to run there.
- TCP through HTTP CONNECT, plain HTTP and SOCKS5. UDP and QUIC are refused.
- Paths: direct, or through a SOCKS5 or HTTP proxy. Agent 0.2.0 adds
  proxies reached over TLS and a list of exits with failover, for VPN Works
  Exit. WireGuard comes in the Beta.
- Unix sockets are blocked in sealed runs as well. A seccomp filter makes
  the program's socket(AF_UNIX) calls fail, so it cannot ask a local service
  such as Docker to connect for it. The filter also blocks io_uring and
  system calls made through a second system call table. socketpair still
  works. A program that needs a local socket (ssh-agent, D-Bus) can run with
  --allow-unix-sockets, which lifts the filter for that run.
- Not covered yet: files. vpnw limits the network only. A sealed program can
  read whatever your user can read, and send it only where the policy allows.
  It can also write files that other programs run later, outside the
  sandbox. The Beta adds a file-system layer. Run vpnw as an ordinary user,
  not as root.
- Events record hosts, addresses, ports, byte counts and decisions. They never
  record payloads, URL paths, headers, environment variables or passwords.


LICENSE AND AVAILABILITY
------------------------

VPN Works is open source under the Apache License 2.0. Copyright VPNW.com
2026. The code is at https://github.com/VPNWorks/vpnw. The binary includes
the Go standard library; its license is in THIRD-PARTY-LICENSES.txt.

https://vpnw.com    info@vpnw.com
