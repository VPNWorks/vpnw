// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package process

import (
	"strings"
	"testing"
)

// The workload must be told to use the broker and must not be told to go
// around it: NO_PROXY and friends are removed, whatever their case.
func TestProxyEnv(t *testing.T) {
	in := []string{"PATH=/usr/bin", "NO_PROXY=github.com", "no_proxy=*", "HTTPS_PROXY=http://elsewhere:8080",
		"Http_Proxy=http://mixed:1", "SOCKS_PROXY=socks5://x:1", "VPNW_SANDBOX_SOCK=/tmp/s", "HOME=/home/a"}
	out := proxyEnv(in, "http://127.0.0.1:3128", "socks5h://127.0.0.1:1080", "r-1", "office")
	got := map[string][]string{}
	for _, kv := range out {
		k, v, _ := strings.Cut(kv, "=")
		got[k] = append(got[k], v)
	}
	for _, k := range []string{"NO_PROXY", "no_proxy", "Http_Proxy", "SOCKS_PROXY", "VPNW_SANDBOX_SOCK"} {
		if _, ok := got[k]; ok {
			t.Errorf("%s survived into the workload's environment", k)
		}
	}
	want := map[string]string{
		"HTTP_PROXY": "http://127.0.0.1:3128", "https_proxy": "http://127.0.0.1:3128",
		"ALL_PROXY": "socks5h://127.0.0.1:1080", "VPNW_PATH": "office", "PATH": "/usr/bin", "HOME": "/home/a",
	}
	for k, v := range want {
		if len(got[k]) != 1 || got[k][0] != v {
			t.Errorf("%s = %v, want exactly %q", k, got[k], v)
		}
	}
}
