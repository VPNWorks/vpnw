# VPN Works Lab Alpha

**vpnw-lab 0.1.0 runs a VPN app in a private test network, breaks things on a timetable, and watches from the network side for anything that leaves outside the tunnel.**

Version 0.1, October 6, 2026.

Lab is the third engine of VPN Works. It builds a small test network out of Linux network namespaces: a laptop, a home router, the internet and a VPN server. It starts the VPN app under test on the laptop with a probe that sends a DNS query, a TCP connection and a UDP datagram every 50 ms, and then it breaks things on a timetable: the VPN server falls silent or goes away, the app is killed, the link drops, the home network pushes a route or a new DNS server. Observers on the far side write down every arrival and the address it came from. From that record Lab decides whether anything left outside the tunnel, which probes, and when.

Everything here ran on one Linux machine, a virtual machine with two CPUs, against stand-ins. The four VPN clients and the VPN server were built for the bench: they behave like VPN software in their routing, firewall, DNS and timing, and they encrypt nothing. No third-party VPN app took part, and this report names none: results about named vendors need legal review before anyone publishes them. The VPN Works Agent took part as itself.

> **VPN Works keeps network access narrow and on the record.** The Agent gives one program, usually an AI agent, its own network on Linux. Scope narrows what each person on a company VPN can reach. Lab checks that VPN apps keep traffic inside the tunnel when things go wrong. Ledger makes every record tamper-evident. Exit checks the policy again at the far end. The Agent and Scope exist today; Lab, Ledger and Exit are new in this release.

| Figure | What it means |
|---|---|
| 210 of 210 | Runs that gave the verdict the design expects: six apps through seven scenarios, five times each with the same seed. Each faulty client leaked in every run of the scenarios that expose its fault and passed the others, the correct client and the Agent's sealed mode passed every run, and the Agent's proxy-settings mode leaked in every run from the probes that ignore proxy settings |
| 22 ms | The median time from the change that opened a leak to the first leaked probe Lab saw, over 50 leak windows; at most 52 ms. The probe sends every 50 ms |
| 29 of 29 | Deliberately planted bugs caught by the tests |
| 3.92 s to 8.10 s | One scenario run of the correct client, from the command to the verdict, building the test world and tearing it down included |

## Contents

1. Lab in brief
2. How it works
3. Using it
4. Scenarios and apps
5. Tests
6. Speed and size
7. Features and limits
8. The demo
9. Where it stands
10. Reproducing the figures
11. License

## 1. Lab in brief

| Area | Status | Key figures |
|---|---|---|
| Engine | Complete for the Alpha scope | One Go program, `vpnw-lab`, standard library only. 5,359 lines of Go in 24 files, the browser build included, and four recorded runs for the demo |
| Test world | Working on Linux | Four network namespaces per run, with NAT, a resolver at the home router and one inside the tunnel, a name server and TCP and UDP observers on the internet side, a SOCKS5 proxy at the VPN server |
| Apps under test | Working | Four stand-in clients on TUN devices: one correct, three with a planted fault each. The VPN Works Agent, sealed and with proxy settings only |
| Scenarios | Seven working | Steady traffic, the server silent, the server gone, the app killed, the link dropped, a route pushed, the DNS server changed. Each is a seeded timetable |
| Verdict | Working | Pass, leak or no traffic; counts by kind; each leak's window with the change that opened and closed it. The same code runs in the browser |
| Tests | Extensive, on one machine | 59 test functions, 124 with subtests. 210 of 210 matrix runs as designed. 29 of 29 planted bugs caught. 25.7 million fuzzed inputs. 93.7% of statements covered |
| Speed | Measured on one machine | A scenario run takes 3.92 s to 8.10 s; the verdict reads 213,333 recording events a second |
| Platforms | Linux x86-64, run and tested | arm64 Linux compiles, not run yet. macOS and Windows compile for `verdict`, `list` and `probe`; running scenarios needs Linux |
| Demo | In the browser | Six steps on recorded runs; Lab's verdict code runs in the page and gives the command line's numbers |
| Readiness | TRL 4 | "Technology validated in lab", on the European Commission's scale |

## 2. How it works

### 2.1 The test world

Each run gets a world of its own, built in about a tenth of a second and thrown away after the run. It is four network namespaces joined by virtual Ethernet pairs, with addresses from the ranges set aside for documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and private ranges.

| Namespace | Plays | What runs there |
|---|---|---|
| device | The laptop, at 192.168.1.10 | The app under test and the probe. Its DNS setting is a file in resolv.conf form that the probe reads before every query |
| home | The home router, at 192.168.1.1 | NAT to its public address 203.0.113.2, and a DNS resolver at 192.168.1.1 and 192.168.1.53 that writes down every query |
| internet | The far side | TCP and UDP observers at 198.51.100.10 and the name server for the probe's names at 198.51.100.53, each writing down every arrival and its source address |
| vpn | The VPN server, at 192.0.2.10 | The tunnel's end on a TUN device, NAT out from one exit address, 192.0.2.20, a resolver inside the tunnel at 10.66.0.1, and a SOCKS5 proxy for the Agent |

The observers, resolvers, server and proxy run inside the bench's own process, with their sockets in the namespaces. The app under test and the probe are separate processes, started in the device namespace.

### 2.2 How an arrival is judged

Lab tells the paths apart by address alone. It needs nothing from the app, the device or the tunnel.

- **Through the tunnel:** an arrival from the VPN's exit address, or a query at the VPN's own resolver.
- **Outside the tunnel:** an arrival from the home network's public address, a query at the home router's resolver, or an arrival from any address the recording doesn't name. The last is counted separately as unexplained, and in this release's runs it never happened.

A probe that arrived outside the tunnel at least once leaked. One that arrived only through the tunnel came through. One that arrived nowhere was held back: blocked by a kill switch, dropped by a silent server, or lost with a tunnel that was down.

### 2.3 The probe

Every 50 ms the probe sends three probes, each tagged with the run's id and a sequence number:

- a DNS query for a name nobody asked for before, such as `d57.r-9fb898.lab.test`, to the resolver in the device's DNS setting;
- a TCP connection to the observer, carrying a one-line tag;
- a UDP datagram to the observer, carrying the same kind of tag.

It can send them two ways. Direct, as a program that ignores proxy settings does. Or through the proxy settings (SOCKS5), as a program that honors them does: TCP to the observer by address, and DNS by asking the proxy to connect to the probe's name, so the name is resolved at the far end. The stand-in clients are tested with direct probes, since they work at the IP level; the Agent is tested with both. The tick numbers count from the run's start, so a probe restarted with a crashed app goes on counting where it left off.

### 2.4 The stand-in VPN clients

Each stand-in is `vpnw-lab client` in one of four modes. It opens a TUN device, carries IP packets in plain UDP frames to the stand-in server, installs its routes and its DNS setting, sends a keepalive every 100 ms, gives up on the server after a second without an answer (at once if the server refuses its packets), and tries to reconnect every 300 ms. When its link comes back after a drop, it waits a second for the network to settle before it tries again. Its own log of every change goes into the run's recording.

| Mode | Routing | Kill switch | DNS | Planted fault |
|---|---|---|---|---|
| correct | Its own table: a rule sends every packet without its mark into the tunnel, so routes added to the main table never apply | nftables on the physical link: only its own tunnel packets leave, connected or not, and the rules stay if it crashes | Points at the VPN's resolver, puts it back if anything changes it, and drops DNS to any other server | None |
| dns-leak | Its own table, plus a rule that lets the local network through | As correct, but local traffic may leave | Points DNS at the home router "so names keep working" while it reconnects, and leaves alone a setting the network changes | DNS leaks during reconnects and after a DNS change |
| no-kill-switch | Its own table | None | As correct | When the tunnel is down its routes fall away and traffic goes out the home network |
| follows-routes | The main table: 0.0.0.0/1 and 128.0.0.0/1 through the tunnel, kept on a persistent TUN device so they survive a crash | None in the firewall; its routes are its kill switch | As correct | A more specific route pushed by the local network wins over the tunnel: the flaw published as TunnelVision (CVE-2024-3661) |

Each faulty client is the correct one with its fault and the few settings that come with it, so a failure points at the fault. The tunnel is a stand-in too: a four-byte header in front of each packet, and no encryption.

### 2.5 The timetable and the record

A scenario is a list of steps: start, fault on, fault off and stop. The seed moves the fault by up to 400 ms, so a run can be repeated exactly. A step's time is when the bench began its action, and its note says how long the action took; the change itself comes at that time or just after. The run's recording is one JSON Lines file: the header, the bench's steps, the app's own log, the probe's line for every probe it sent, and the observers' line for every arrival.

```
{"t":"2026-10-05T21:31:43.410483588Z","ev":"run","lab":"0.1.0","run":"r-9fb898","app":"dns-leak","scenario":"server-silent","seed":7,"interval_ms":50,"exit":"192.0.2.20","home":"203.0.113.2"}
{"t":"2026-10-05T21:31:44.998227336Z","ev":"step","step":"fault-on","fault":"server-silent","note":"took 20 ms"}
{"t":"2026-10-05T21:31:46.011453689Z","ev":"arrival","kind":"dns","via":"direct","seq":52,"at":"home-dns","src":"192.168.1.10"}
```

### 2.6 The verdict

The verdict reads a recording and makes no system calls, so the same code runs on the command line and in the browser.

- **Pass:** probes came through the tunnel before the fault and none leaked.
- **Leak:** at least one probe leaked. The verdict counts leaks by kind, merges leaked probes into windows while the gaps stay under four probe intervals, and names, for each window, the last change the bench or the app recorded before it opened and the first one after it closed, with the time between.
- **No traffic:** nothing came through the tunnel before the fault, so the app never carried the probe's traffic and there is nothing to judge.

The verdict of a run is its status and the kinds that leaked, such as "leak (dns)". A kind sent through the proxy settings is named with its path, such as "tcp via proxy". Counts of leaked probes vary by up to four from one run of an app and scenario to the next; the verdict didn't vary in any run (section 5.1).

## 3. Using it

### 3.1 Commands

| Command | What it does |
|---|---|
| `vpnw-lab run --app NAME --scenario NAME` | Builds a test world, runs one scenario for one app, prints the verdict and, with `-o FILE`, writes the recording. Linux; it runs itself again in a user namespace of its own, so it needs no root |
| `vpnw-lab verdict FILE...` | Decides recordings again. Works anywhere |
| `vpnw-lab list` | Lists the scenarios and the apps |
| `vpnw-lab client --mode MODE` | A stand-in VPN client. `run` starts it |
| `vpnw-lab probe --run ID` | The probe. `run` starts it, and the Agent runs it as its workload |
| `vpnw-lab version` | Prints the version |

`run` takes `--seed N`, `--fault-for D` to lengthen a fault (the demo's server is silent for `5s`), `--interval D`, `--vpnw FILE` for the Agent's executable, `--keep DIR` to keep the run's logs, `--json` and `-v`. `verdict` takes `--json`; the browser demo shows the same fields.

```
$ vpnw-lab verdict dns-leak-server-silent.jsonl
dns-leak, server-silent (seed 7): LEAK
  546 probes sent: 243 through the tunnel, 81 leaked, 222 seen nowhere
    dns              182 sent,    81 tunnel,    81 leaked,    20 nowhere
    tcp              182 sent,    81 tunnel,     0 leaked,   101 nowhere
    udp              182 sent,    81 tunnel,     0 leaked,   101 nowhere
  fault server-silent: on at 1.59 s, off at 6.59 s; stop at 9.09 s
  the tunnel carried probes again 60 ms after the fault ended
  leak 1: 81 probes from 2.60 s to 6.60 s (dns)
    first seen 27 ms after: client dns 192.168.1.1 (while reconnecting)
    last seen 47 ms before: client up
```

### 3.2 Exit codes

| Code | Meaning |
|---|---|
| 0 | Pass |
| 120 | A leak was found, so a script or CI job can stop on it |
| 121 | A usage error, or an error in an input file, with the file and line |
| 122 | Not possible on this machine: no user namespaces, nftables or TUN driver, or not Linux |
| 124 | Any other failure, a run that carried no traffic included |

## 4. Scenarios and apps

| Scenario | Fault on | Fault off |
|---|---|---|
| steady | No fault: 3 s of traffic | |
| server-silent | Every packet to and from the VPN server's address is dropped (3 s; 5 s in the demo) | The server answers again |
| server-gone | The server's address refuses everything: ICMP port unreachable for UDP, a reset for TCP | Never: the fault lasts to the end |
| app-killed | The app is killed with SIGKILL, as in a crash | The app is started again (2 s later), as a service manager would |
| link-drop | The device's link goes down, and Linux drops every route through it | The link comes back and the bench gives the device its default route again (2 s later), as DHCP would |
| route-push | The bench adds a route for the observers' range, 198.51.100.0/24, through the home router, as a DHCP option 121 route would arrive | The route is withdrawn (2 s later) |
| dns-change | The home network hands out a new DNS server, 192.168.1.53, and the bench writes it into the device's DNS setting, as a network manager would | The network hands out its first server again (2 s later) |

All seven are simulated at the network level: no DHCP server or client runs, and the bench makes each change itself.

The apps are the four stand-ins and the Agent in two modes. For the Agent, the probe runs as the Agent's workload, with the SOCKS5 proxy at the VPN server as the Agent's path, and sends probes both ways: through the proxy settings and directly.

- **agent-sealed:** `vpnw guard`, with its own network namespace where the only way out is the Agent's proxy path.
- **agent-env:** `vpnw run --backend env`, proxy settings only. Programs that ignore the settings go direct, as the Agent's documents say, and Lab reports that as a leak.

### 4.1 The matrix

The verdicts of the final run, five runs of each app and scenario with seed 1. After a leak comes the number of probes that leaked in each run, as the lowest and the highest of the five where they differed.

| App | steady | server-silent | server-gone | app-killed | link-drop | route-push | dns-change |
|---|---|---|---|---|---|---|---|
| correct | pass | pass | pass | pass | pass | pass | pass |
| dns-leak | pass | leak (dns), 44 to 45 | leak (dns), 59 to 60 | pass | leak (dns), 20 to 21 | pass | leak (dns), 72 |
| no-kill-switch | pass | leak (tcp, udp), 84 to 88 | leak (tcp, udp), 118 to 120 | leak (tcp, udp), 86 | leak (tcp, udp), 42 | pass | pass |
| follows-routes | pass | pass | pass | pass | pass | leak (tcp, udp), 84 | pass |
| agent-sealed | pass | pass | pass | pass | pass | pass | pass |
| agent-env | leak (dns, tcp, udp), 183 | leak (dns, tcp, udp), 432 | leak (dns, tcp, udp), 276 | leak (dns, tcp, udp), 246 | leak (dns, tcp, udp), 276 | leak (dns, tcp, udp), 312 | leak (dns, tcp, udp), 312 |

Every cell gave the same verdict in all five runs, and the number of leaked probes varied by at most four between runs of the same cell. The dns-leak client passes when it is killed: it crashes with DNS pointed into the tunnel, and its kill switch stays. The no-kill-switch client passes a pushed route and a DNS change: its own routing table ignores the route, and it puts its resolver back. The follows-routes client passes every fault except the pushed route: its routes stay while the tunnel is down, even after a crash, so traffic goes into the dead tunnel and is lost there. The Agent's sealed mode passes everything. In its proxy-settings mode only the direct probes leaked: no kind sent through the proxy, such as "tcp via proxy", showed up in any run's verdict.

## 5. Tests

Every test runs on Linux against the real code. The kernel tests build test worlds in network namespaces, run the stand-in clients, the probe and the Agent as real processes on real TUN devices, with real routing tables and nftables rules, and check every verdict.

| Suite | What it checks | Result |
|---|---|---|
| Unit tests | Recordings and their reader, timetables and seeds, the verdict and its windows, the DNS, tag and frame formats, the netlink helpers and the routing decisions the clients rely on, the test world's observers, faults and proxy, the clients' firewall rules, the probe, the command line, the demo's recordings | 53 test functions in eight packages; all passed |
| The matrix | Six apps through seven scenarios, five runs each, every verdict against the design; that each designed leak opens and closes within 250 ms of the change that causes and ends it; that a silent or gone server passes nothing; that every kind of probe comes through the tunnel again after a fault ends | 210 of 210 as designed |
| Command line | `vpnw-lab run` and `vpnw-lab verdict` end to end, for a stand-in and for the Agent in both modes | Passed |
| Seeds | The same seed plans the same timetable; each step lands close to its plan; another seed moves the fault | Passed |
| Clean exit | The correct client removes its table, rule, routes and TUN device on exit and puts the home DNS server back | Passed |
| Crash | The follows-routes client's routes outlive it on its persistent TUN device | Passed |
| Bench errors | Clients that exit early, never come up, or write a bad log line; missing inputs | Passed |
| Race detector | The whole suite under Go's race detector, the matrix once through, two test worlds at a time | Clean |
| Fuzzing | Nine readers, one minute each | 25,721,614 inputs (the sum of fuzz.txt), no crash, no failed check |
| Planted bugs | 29 deliberate bugs, one at a time | 29 of 29 caught |
| Coverage | All tests together | 93.7% of statements |

Coverage by part: the demo's recordings 100%, the verdict and recordings (internal/lab) 98.9%, the wire formats 98.9%, the command line 95.2%, the probe 94.3%, the netlink helpers 93.0%, the bench 90.8%, the stand-in clients 89.7%, the test world 88.0%.

### 5.1 Same seed, same verdict

In the final run every app went through every scenario five times with seed 1, 210 runs in all, four test worlds at a time. All 210 verdicts matched the design, and no cell's verdict changed between runs. The counts did move a little, by up to four probes, two ticks' worth of TCP and UDP probes (computed): the fault and the clients' own timers fell at slightly different points between ticks from run to run. The seed test checks the plan itself: seed 4 placed the fault at 1.88 s in both of its runs, seed 9 at 1.73 s, and every step of the three runs came at most 1 ms after its plan. All three gave the same verdict, leak (dns).

### 5.2 How closely a leak is timed

For every leak window that opened after a change the bench or the app recorded, Lab gives the time from that change to the first leaked probe, and from the last leaked probe to the change that closed the window. Windows that open as the run or the app starts are left out. Over the final run's leaks:

| Measure | Median | Largest | Windows |
|---|---|---|---|
| From the change that opened a leak to the first leaked probe seen | 22 ms | 52 ms | 50 |
| From the last leaked probe to the change that closed the leak | 23 ms | 48 ms | 40 |

The 50 are the faulty clients' 45 designed leaks and five of the Agent's, its direct probes going out again when the link came back. The 40 are the 30 designed leaks that end before the run does and ten of the Agent's, which ended as the link dropped or the Agent was killed (both counted from the design of the matrix).

With probes every 50 ms, the first leaked probe is the one sent at the first tick after the change takes hold, up to one interval later, and it then needs a moment to reach the observer. The largest lag, 52 ms, is one interval and 2 ms more (computed). On the closing side, the last leaked probe went out at most 48 ms before the change. A leak shorter than one interval can pass unseen.

### 5.3 Planted bugs

To check the tests themselves, 29 bugs were put into the code on purpose, one at a time. For each one the unit tests ran first, and the kernel tests ran only if all of them passed. A bug counts as caught only if a test fails. All 29 were caught in the final run. During the build, in a first validation run, bug 29 got past every test. An earlier run of the planted bugs had counted it caught, though no test then checked what it breaks: a test failed for another reason while it was planted. Defect 9 in section 5.5 is the check that now catches it.

| | Planted bug | Part |
|---|---|---|
| 1 | A query that reached the home router's resolver counts as through the tunnel | Verdict |
| 2 | An arrival from the home network's address counts as through the tunnel | Verdict |
| 3 | A probe seen outside the tunnel and then through it counts as through | Verdict |
| 4 | A leak window breaks apart at every probe | Verdict |
| 5 | A leak still going when the run stops is reported as over | Verdict |
| 6 | An app that carried nothing through the tunnel before the fault is judged anyway | Verdict |
| 7 | Negative sequence numbers and seeds are accepted | Recordings |
| 8 | A note with a quote mark writes a broken line | Recordings |
| 9 | The seed is ignored, so the fault moves from run to run | Timetables |
| 10 | A name asked through the proxy is read as a direct probe | Probe names |
| 11 | DNS answers go out marked as queries | DNS messages |
| 12 | The tunnel refuses every IPv4 packet | Tunnel frames |
| 13 | Routes for the client's own table land in the main table | Netlink helpers |
| 14 | A "not fwmark" rule loses its "not" | Netlink helpers |
| 15 | The VPN's NAT uses the server's address in place of the exit address | Test world |
| 16 | The home router stops translating addresses | Test world |
| 17 | A silent server still takes the client's packets in and passes them on | Test world |
| 18 | The device gets no default route when its link comes back | Test world |
| 19 | The pushed route misses the observers' range | Test world |
| 20 | Arrivals of other runs end up in the recording, and this run's are lost | Test world |
| 21 | Strict routing sends only the client's own packets to the tunnel's table | Stand-in clients |
| 22 | The kill switch blocks the client's own tunnel | Stand-in clients |
| 23 | The client waits ten seconds before it notices a silent server | Stand-in clients |
| 24 | The correct client stops putting its resolver back after the network changes it | Stand-in clients |
| 25 | Every client but dns-leak points DNS at the home router while it reconnects | Stand-in clients |
| 26 | Direct DNS probes ask for the proxy's names | Probe |
| 27 | TCP probes are tagged as UDP | Probe |
| 28 | Killing the Agent leaves its workload running | Bench |
| 29 | The DNS change hands out the VPN's own resolver | Bench |

### 5.4 Fuzzing

Each reader got one minute of Go's fuzzer in the final run, with no crash and no failed check.

| Reader | Inputs | Package |
|---|---|---|
| One line of a recording | 3,782,146 | internal/lab |
| A whole recording, read, decided, written out and read again | 47,965 | internal/lab |
| DNS queries | 3,712,118 | internal/lab/wire |
| DNS answers | 2,691,512 | internal/lab/wire |
| Probe names | 2,880,360 | internal/lab/wire |
| Probe tags | 3,769,850 | internal/lab/wire |
| Tunnel frames | 4,025,791 | internal/lab/wire |
| DNS settings in resolv.conf form | 2,449,059 | internal/lab/world |
| Proxy addresses | 2,362,813 | internal/lab/probe |

Apart from crashes, every target except the one for DNS answers checks that what its reader accepts writes out and reads back the same. The whole-recording target also checks that the verdict's counts add up and stay the same after the recording is written out, which is why it gets through fewer inputs.

### 5.5 Defects found and fixed

Building and testing Lab turned up these defects. All are fixed, and each is covered by a test.

| | Defect | Found by | Effect before the fix |
|---|---|---|---|
| 1 | A route added without its device took its gateway's path through the client's policy rules, and landed on the tunnel | The netlink routing test | A pushed route, or the default route given back after a link drop, could go into the tunnel instead of the home network. The bench now names the device for every route it adds |
| 2 | The bench stopped the Agent before its probe had finished | The first Agent runs | The last proxied probe of a run was cut and counted as held back |
| 3 | Steps were stamped when the bench's action had finished | The demo's recording of the killed client | A leak that began during a slow action was seen before its own step, and the verdict named an older change as its cause. Steps are now stamped when the action begins, with its length in the step's note |
| 4 | Nothing checked that a silent server passes nothing | Planted bug 17, missed in the first planted-bug run | A "silent" server that dropped only its replies would have gone on passing the client's packets |
| 5 | The new check counted probes sent before the fault that a slow machine delivered late | The race detector run | A false alarm in one run. It now counts probes sent after the fault took effect |
| 6 | Each DNS query a resolver forwarded, and each connection the proxy opened, entered its namespace on a new thread | Runs under the race detector | The thread churn starved the bench's own server, and a client gave up on a server that was still there, in about one run in four under the race detector. Each resolver now keeps one socket and the proxy a small pool of threads in its namespace |
| 7 | Go's test runner capped the parallel runs at the number of CPUs | Timing the matrix | 84 runs took 277 s; the kernel tests now set the limit from VPNW_LAB_PARALLEL |
| 8 | The planted-bug script didn't restore a file when stopped with SIGTERM | Stopping a run by hand | A planted bug stayed in the code until it was restored from git |
| 9 | The matrix checked each run's verdict, and nothing about when its leak opened and closed | Planted bug 29, missed in the first validation run | With the bug, the DNS change handed out the VPN's own resolver, and the dns-leak client leaked only once the network handed out its first server again, 2 s late; the matrix still passed. Each designed leak must now open within 250 ms of the change that causes it, and close within 250 ms of the change that ends it |

### 5.6 What the tests don't cover yet

- **Real VPN apps.** None ran. The clients and the server are stand-ins that send plain UDP frames, without keys or a real handshake. A real app's reconnect logic and timers will differ.
- **IPv6.** The machine has no IPv6, and the IPv6 scenarios weren't written; they were cut for time. A dual-stack network, where an app that tunnels IPv4 only leaks IPv6, is the obvious next scenario.
- **The real network stack around the app.** No DHCP server or client runs; the bench makes each change itself. The device's DNS setting is a file the probe reads; systemd-resolved, nsswitch and DNS over HTTPS aren't involved.
- **Other events.** Sleep and resume, roaming between networks, captive portals and a slow or lossy link aren't simulated.
- **Short leaks.** A leak shorter than the probe's 50 ms can pass unseen.
- **Other machines.** One kernel (Linux 6.18) on x86-64. The arm64 build compiles but hasn't run.
- **Long runs.** The longest scenario runs about 8 s. The verdict was timed on a generated one-hour recording, and no hour-long run has been made on the bench.
- **Time.** Fuzzing ran one minute per reader.
- **Independent review.** Every test was written by the people who wrote the code.

## 6. Speed and size

All figures from the final run, on a virtual machine with two CPUs, Linux 6.18 on x86-64, Go 1.24.7, with no other measurement running. Each time is the median of three runs, each memory figure the highest of three; memory is the peak resident size of the largest process of a run.

| Scenario, correct client | Planned | Run, command to verdict | World built in | Peak memory | Recording |
|---|---|---|---|---|---|
| steady | 3.00 s | 3.92 s | 88 ms | 10 MB | 47 kB |
| server-silent | 7.18 s | 8.10 s | 109 ms | 10 MB | 79 kB |
| server-gone | 4.56 s | 6.40 s | 123 ms | 10 MB | 41 kB |
| app-killed | 6.18 s | 7.12 s | 124 ms | 10 MB | 74 kB |
| link-drop | 6.68 s | 7.59 s | 93 ms | 10 MB | 72 kB |
| route-push | 5.18 s | 6.11 s | 115 ms | 10 MB | 80 kB |
| dns-change | 5.18 s | 6.12 s | 114 ms | 10 MB | 79 kB |

A run takes about 0.9 s longer than its plan (computed from the table): the world is built, the client starts and comes up, the last probes get half a second to arrive, and everything is torn down. server-gone takes about 0.9 s more again (computed): its fault lasts to the end, so the last TCP probes go nowhere, and the probe waits 0.9 s for them before it stops. With the dns-leak client, server-silent took 8.10 s and 10 MB; with the Agent's sealed mode, 8.52 s and 13 MB. In the matrix, four test worlds at a time, the median run took from 3.96 s (steady) to 8.12 s (server-silent).

Deciding a long recording: `vpnw-lab verdict` on a generated recording of one hour of probes, 504,003 events in 55 MB of JSON Lines, took 2.36 s, 213,333 events a second, with a peak of 671 MB. The verdict holds the whole recording and every probe in memory (section 7).

| Build | Size | Compressed (gzip -9) |
|---|---|---|
| Linux x86-64 | 3,330,232 bytes | 1,389,195 bytes |
| Linux arm64 | 3,276,984 bytes | 1,280,493 bytes |
| macOS, Intel and Apple silicon; Windows x86-64 | Compile, for verdict, list and probe | |
| Browser engine (TinyGo, WebAssembly), the four demo recordings inside | 879,988 bytes | 230,321 bytes |

No third-party modules.

## 7. Features and limits

| Feature | What 0.1.0 supports | Limits |
|---|---|---|
| Test world | Four network namespaces per run on one Linux machine, with NAT, resolvers, observers and a stand-in VPN server | Linux only; IPv4 only; one machine |
| Apps | Four stand-in clients; the VPN Works Agent, sealed and with proxy settings only | No third-party apps yet |
| Faults | Seven scenarios, seeded | No sleep, roaming, captive portals, lossy links or IPv6 |
| Probes | DNS, TCP and UDP every 50 ms, direct and through SOCKS5 | UDP through a proxy isn't sent: the Agent refuses SOCKS5 UDP |
| Verdict | Pass, leak or no traffic; counts by kind and path; windows with their causes; JSON for scripts | Its resolution is the probe's interval. It holds a whole recording in memory: 671 MB for a generated hour of probes |
| Recordings | JSON Lines, one event to a line; read and decided anywhere, the browser included | Lines up to 4,096 bytes |
| Platforms | `run` and the stand-ins on Linux; `verdict`, `list` and `probe` anywhere Go builds | Running scenarios needs user namespaces, nftables and the TUN driver |

## 8. The demo

The demo replays real runs. The page loads Lab's verdict code, compiled to WebAssembly with TinyGo, with four recordings inside it. The recordings were made in the test network with `vpnw-lab run` by `engine/tools/record-lab-demo.sh` (seed 7) and are kept in the repository as they came out. The page decides them as it opens and draws every number from that.

| Step | On the page | What it shows |
|---|---|---|
| 1 | The test bench | The four namespaces, the probe, and how an arrival is judged |
| 2 | The fault | The timetable as the bench carried it out: the server silent from 1.59 s to 6.59 s, and both clients' own logs |
| 3 | The correct client | By its own log the tunnel was down from 2.58 s to 6.66 s. 246 probes went nowhere in that time, held by its kill switch, and 60 more were lost before it noticed the silence: they went into the tunnel, and the silent server dropped them. None left outside, and probes came through the tunnel again 105 ms after the server answered |
| 4 | The leaky client | 81 DNS queries reached the home router's resolver between 2.60 s and 6.60 s, the first 27 ms after the client pointed DNS at 192.168.1.1. Its TCP and UDP probes were held back |
| 5 | One probe at a time | Both runs around the reconnect; any probe can be picked to see where it arrived and how Lab judged it |
| 6 | Other faults | The no-kill-switch client killed for 2 s, and the follows-routes client with a route pushed for 2 s, decided in the page; and the verdicts of the matrix in section 4.1, copied into the page |

A headless Chromium check plays the page through at computer and phone widths. It compares the counts on the page, and the leaky client's leak window and times in step 4, with `vpnw-lab verdict --json` on the same recordings, and checks that nothing overflows a 390 px screen, that the page makes no network request, and that the console stays free of errors. In the final run every check passed, and the page decided the four recordings, 1,764 probes, in 188 ms. The page rounds times from the JSON's tenths of a millisecond, so a time can read 1 ms off the command line's: step 6 shows the no-kill-switch leak first seen 13 ms after the fault, where the command line says 12 ms.

## 9. Where it stands

### 9.1 Maturity by part

| Part | Maturity | Evidence | Gap to close |
|---|---|---|---|
| Verdict and recordings | Working, tested | Unit tests; two fuzzed readers; 9 planted bugs caught (verdict 6, recordings 2, timetables 1) | A verdict that reads long recordings as a stream |
| Test world | Working on Linux | Every matrix run; one fuzzed reader; 6 planted bugs caught | IPv6; a real DHCP server and client |
| Stand-in clients | Working | Every matrix run; 7 planted bugs caught, 5 in the clients and 2 in the netlink helpers they use | Real apps' behavior |
| Wire formats | Working | Five fuzzed readers; 3 planted bugs caught | None found so far |
| Probe | Working | Unit tests; one fuzzed reader; 2 planted bugs caught | More kinds, such as QUIC |
| Bench | Working | Every matrix run; 2 planted bugs caught | None found so far |
| The Agent as an app | Working | 70 runs in the matrix | Agents on other platforms |
| Scenarios | Seven working | 210 runs as designed | IPv6, sleep, roaming, captive portals |
| Command line | Working | Unit and end-to-end tests | Reports for many runs at once |
| Browser demo | Working | Same verdicts as the command line; headless checks | None found so far |
| Testing real VPN apps | None | None | A harness per platform |

### 9.2 Readiness level

On the European Commission's technology readiness scale, which runs from TRL 1 to TRL 9, Lab 0.1.0 sits at TRL 4, "technology validated in lab". The bench works against the real Linux kernel, with real processes, routing tables and firewalls, and it catches the faults it was built to catch. Its subjects so far are stand-ins and the Agent. Running real VPN apps on the bench, and the bench in a setting closer to theirs, would take it to TRL 5.

### 9.3 How far from a first release

An estimate, and only an estimate: Lab is about a quarter of the way to a first release. The core works: the world, the faults, the probe and the verdict. What's left is the larger part: a harness that installs and drives real VPN apps (Linux command-line clients first, then desktop and mobile apps in virtual machines), IPv6, a real DHCP server and client, sleep and roaming, a verdict that streams long recordings, reports across many runs, packages, and an outside review.

### 9.4 Technical risks Lab revealed

- **Real apps don't fit a namespace.** Linux command-line clients such as WireGuard and OpenVPN can run on the bench's device. Desktop and mobile apps use their platform's VPN interfaces, need a whole operating system, and give the bench coarser control of faults.
- **The stand-ins encode our idea of how VPNs fail.** Real apps will fail in ways the stand-ins don't model; the observers will still see the result, but the scenarios may not provoke it.
- **Resolution.** Timing is bound to the probe's interval. Sending more often catches shorter leaks and adds load.
- **What the observers see.** A leak to a destination the probe never uses, such as a DNS server hardcoded in another app, isn't seen.
- **A busy machine.** The bench's servers share one process. Under the race detector, before fix 6 in section 5.5, a starved server made a client give up on it. Nothing like that showed in the normal runs, and fix 6 makes it rarer; a far busier machine could bring it back.
- **Long recordings.** The verdict holds a whole recording in memory, 671 MB for a generated hour of probes. Runs of many hours need a verdict that decides probes as it reads them.
- **Publishing.** Results about named vendors' apps need legal review before they are published.

## 10. Reproducing the figures

Every figure in this report comes from the final run of `FUZZTIME=60s tools/measure-lab.sh`, from the engine folder, on October 6, 2026 (UTC), on an idle machine with one engine measured at a time. It took about 36 minutes and wrote `engine/results/lab-alpha`. It put each app through each scenario five times, four test worlds at a time, and gave each fuzz target one minute. The exceptions: the demo's four recordings were made on October 5 by `tools/record-lab-demo.sh`, and their numbers come from `vpnw-lab verdict` on them, in demo.txt; the defects in section 5.5, and the first validation run in section 5.3, belong to the build.

| File | What it holds |
|---|---|
| environment.txt | Date, kernel, CPUs, Go, TinyGo, Python, nftables and Node versions |
| size.txt | Sizes for each build, compressed and not, and the platforms that compile |
| source.txt | Lines of Go per part, and lines of tests |
| tests.txt, tests.json | Every test and subtest with its result |
| race.txt | The suite under the race detector |
| coverage.txt | Coverage per package and in total |
| fuzz.txt | Inputs per fuzz target |
| kernel.txt | The matrix, timing, durations, seeds, command line and clean-exit results |
| planted-bugs.txt | Each planted bug and whether a test caught it |
| perf.txt | Scenario runs and the verdict on a long recording |
| demo.txt, demo-verdicts.json | The demo's recordings decided by the command line |
| demo-browser.txt, demo-check.txt | The browser engine's answers and the headless check of the page |

## 11. License

VPN Works is open source under the Apache License 2.0. Copyright VPNW.com 2026. The code is at https://github.com/VPNWorks/vpnw.

Contact: info@vpnw.com
