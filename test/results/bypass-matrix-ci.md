date: 2026-10-09
commit: 7513f65
kernel: Linux 6.17.0-1022-azure, x86_64, 4 CPUs
runner: GitHub Actions ubuntu-latest, run 37931925523

| Way out | Inside the sandbox | Outside (control) | Result |
|---|---|---|---|
| IPv4 TCP to this machine's loopback (127.0.0.1) | nothing listening in the sandbox (ECONNREFUSED) | reached | blocked |
| IPv4 TCP to this machine's own address (10.1.0.201) | no route (ENETUNREACH) | reached | blocked |
| IPv4 TCP to a public address (1.1.1.1:443) | no route (ENETUNREACH) | reached | blocked |
| IPv4 TCP to a private address (10.0.0.1:80) | no route (ENETUNREACH) | not needed | blocked |
| IPv4 TCP to cloud metadata (169.254.169.254:80) | no route (ENETUNREACH) | not needed | blocked |
| UDP to this machine's own address | no route (ENETUNREACH) | reached | blocked |
| UDP to a public DNS resolver (8.8.8.8:53) | no route (ENETUNREACH) | not needed | blocked |
| DNS lookup through the system resolver | name lookup failed | not needed | blocked |
| Raw IP socket (ICMP echo to 1.1.1.1) | not permitted (EPERM) | not needed | blocked |
| A child process connecting on its own | no route (ENETUNREACH) | not needed | blocked |
| Abstract Unix socket (@vpnw-bypass) | not permitted (EPERM) | reached | blocked |
| Unix socket in the file system (like the Docker socket) | not permitted (EPERM) | reached | blocked |
| io_uring, which can create sockets without socket() | not permitted (EPERM) | reached | blocked |
| IPv6 TCP to this machine's loopback (::1) | nothing listening in the sandbox (ECONNREFUSED) | reached | blocked |
| IPv6 TCP to a public address (2606:4700:4700::1111) | no route (ENETUNREACH) | failed (101 OSError) | blocked |
| An x32 system call (a second system call table) | not permitted (EPERM) | not needed | blocked |
| ping (ICMP) to 1.1.1.1 | no route (ENETUNREACH) | not needed | blocked |

