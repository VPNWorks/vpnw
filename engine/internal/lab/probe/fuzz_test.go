// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package probe

import (
	"net/url"
	"testing"
)

func FuzzParseProxy(f *testing.F) {
	f.Add("socks5h://vpnw:token@127.0.0.1:1080")
	f.Add("socks5://[::1]:9")
	f.Add("http://127.0.0.1:3128")
	f.Fuzz(func(t *testing.T, raw string) {
		p, err := ParseProxy(raw)
		if err != nil {
			return
		}
		u := url.URL{Scheme: "socks5h", Host: p.Addr}
		if p.User != "" || p.Pass != "" {
			u.User = url.UserPassword(p.User, p.Pass)
		}
		again, err := ParseProxy(u.String())
		if err != nil || again != p {
			t.Fatalf("%q -> %+v -> %q -> %v %+v", raw, p, u.String(), err, again)
		}
	})
}
