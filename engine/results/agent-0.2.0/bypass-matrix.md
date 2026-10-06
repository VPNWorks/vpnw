| Way out | Inside the sandbox | Outside (control) | Result |
|---|---|---|---|
| IPv4 TCP to this machine's loopback (127.0.0.1) | nothing listening in the sandbox (ECONNREFUSED) | reached | blocked |
| IPv4 TCP to this machine's own address (192.0.2.2) | no route (ENETUNREACH) | reached | blocked |
| IPv4 TCP to a public address (1.1.1.1:443) | no route (ENETUNREACH) | reached | blocked |
| IPv4 TCP to a private address (10.0.0.1:80) | no route (ENETUNREACH) | not needed | blocked |
| IPv4 TCP to cloud metadata (169.254.169.254:80) | no route (ENETUNREACH) | not needed | blocked |
| UDP to this machine's own address | no route (ENETUNREACH) | reached | blocked |
| UDP to a public DNS resolver (8.8.8.8:53) | no route (ENETUNREACH) | not needed | blocked |
| DNS lookup through the system resolver | name lookup failed | not needed | blocked |
| Raw IP socket (ICMP echo to 1.1.1.1) | no route (ENETUNREACH) | not needed | blocked |
| A child process connecting on its own | no route (ENETUNREACH) | not needed | blocked |
| Abstract Unix socket (@vpnw-bypass) | not permitted (EPERM) | reached | blocked |
| Unix socket in the file system (like the Docker socket) | not permitted (EPERM) | reached | blocked |
| io_uring, which can create sockets without socket() | not permitted (EPERM) | reached | blocked |
| IPv6 TCP to loopback (::1) | not run | not run | skipped: this machine's kernel has no IPv6 |
| IPv6 TCP to a public address (2606:4700:4700::1111) | not run | not run | skipped: this machine's kernel has no IPv6 |
| An x32 system call (a second system call table) | not permitted (EPERM) | not needed | blocked |
