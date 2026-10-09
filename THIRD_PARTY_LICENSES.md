# Third-party licenses

The `vpnw` binary contains the Go standard library and runtime and the
modules below. The built-in plugins, compiled into it as WebAssembly,
contain the Go standard library and runtime as well.

| Module | Version | License | Used for |
|---|---|---|---|
| github.com/tetratelabs/wazero | v1.10.1 | Apache 2.0 | running plugins |
| golang.zx2c4.com/wireguard | v0.0.0-20261006164505-2631ce99a06f | MIT | WireGuard paths |
| gvisor.dev/gvisor | v0.0.0-20250503011706-39ed1f5ac29c | Apache 2.0 | the TCP/IP stack inside WireGuard paths |
| github.com/google/btree | v1.1.2 | Apache 2.0 | used by gVisor |
| golang.org/x/crypto, net, sys, time | v0.37.0, v0.39.0, v0.32.0, v0.7.0 | BSD 3-clause (the Go license, below) | used by WireGuard and gVisor |

The Apache License 2.0 is the same text as this project's LICENSE file.

## wazero

github.com/tetratelabs/wazero v1.10.1, under the Apache License 2.0 (the same
text as this project's LICENSE file). Its NOTICE file:

```
wazero
Copyright 2020-2023 wazero authors
```

## WireGuard (golang.zx2c4.com/wireguard)

```
Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## gVisor (gvisor.dev/gvisor)

Apache License 2.0. Copyright The gVisor Authors.

## google/btree (github.com/google/btree)

Apache License 2.0. Copyright Google Inc.

## golang.org/x/crypto, x/net, x/sys, x/time

Under the same license as Go, below.

## Go (the standard library and runtime)

```
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
