| Check | What must happen | What happened | Result |
|---|---|---|---|
| agent-1, with an address of its own, fetches 3 times through vpnw | every connection leaves from 127.0.0.2 | 3 of 3 from 127.0.0.2, exit 0 | passed |
| agent-2, with an address of its own, fetches 3 times through vpnw | every connection leaves from 127.0.0.3 | 3 of 3 from 127.0.0.3, exit 0 | passed |
| ci, with a pool it shares, connects 10 times without vpnw | one address of its pool, every time | 10 of 10 from 127.0.0.5 | passed |
| what the server saw | only the clients' own addresses | 16 connections, 0 from any other address | passed |
| a client sends 11 forbidden requests straight to the exit, with its valid token | every one refused by the client's own policy at the exit; none reaches a server | 11 of 11 refused (1 BIND refused over SOCKS5, 2 refused by default, 2 refused over SOCKS5, 6 refused by deny_private), 0 reached a server | passed |
| one policy file at both ends; the program asks for 5 destinations | the client's 3 refusals never reach the exit; the exit allows the other 2 by the same rules; the records line up | 3 refused by the client, 2 seen at the exit, 2 allowed there by the same rule, 2 of 2 lined up on run and connection IDs | passed |
| the exit in use is killed after 3 of 10 fetches | the rest go through the next exit, from its address; none fails | 3 through exit-a from 127.0.0.2, 7 through exit-b from 127.0.0.3, 0 failed; the switch took 0 ms | passed |
| the client's record and the exits' records | every connection the client opened is in the record of the exit that carried it, by run and connection ID | 10 of 10 found | passed |
| a client with the wrong token | the program never starts (exit 123), and vpnw says why | exit 123, program started: false, "the exit refused the token" | passed |
| a client that trusts another CA | the program never starts (exit 123), and vpnw says why | exit 123, program started: false, "certificate not accepted" | passed |
| a client asking for the exit by a name its certificate doesn't have | the program never starts (exit 123), and vpnw says why | exit 123, program started: false, "certificate not accepted" | passed |
| the exit's record of these | the wrong token is recorded as refused; no token is ever written down | auth.deny events: 1; a token in the record: false | passed |
| a client's source address the machine doesn't have | serve refuses to start (exit 122) | exit 122 | passed |
| vpnw exit check on that file | says what the client may do, and that its address isn't here | said so: true | passed |
| a wildcard source address, 0.0.0.0 | refused (exit 121): the machine could pick any of its addresses, another client's included | exit 121 | passed |
| a listening address that's taken | serve refuses to start (exit 122) | exit 122 | passed |
| a mistake in the exit's file | refused with the file and line (exit 121) | exit 121 | passed |
| a token or a certificate made over one that exists | refused (exit 121); nothing is overwritten | token: exit 121, cert: exit 121 | passed |
| a Guard plugin and Ledger at the exit | the Guard refuses what the client's policy allowed; Ledger seals the exit's record; SIGTERM ends it cleanly | localhost: 403 by plugin:blocker; 127.0.0.1: 200, from 127.0.0.2; exit code 0; ledger: intact, 9 entries | passed |
| a client whose policy allows everything asks for the exit's own machine and for cloud metadata | every one refused at the exit, whatever the policy says; nothing reached | 5 of 5 refused, 0 reached | passed |
| the same with allow_exit_host = true for that client | the exit's own machine is reached, from the client's address; cloud metadata stays refused | loopback: 200, from 127.0.0.3; metadata: 403 | passed |
21 of 21 checks passed
513 of 513 requests decided the same way at both ends, by a run's broker and by an exit, given the same policy and the same DNS answers (TestSameDecisionAtBothEnds)
