// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Review of 0.9.0: reproductions of defects found by the independent review.

package integration

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A client's connection opened before an unrelated reload (another client
// added) stays open after the client is taken out of the file: the reload
// made new broker.Client objects for every client, and Revoke only closes
// connections tracked under the newest one.
func TestReview090RevokeAfterUnrelatedReload(t *testing.T) {
	k := newExitKit(t)
	srv := newSourceServer(t)
	tok1, h1 := k.token("agent-1")
	_, h2 := k.token("agent-2")
	_, h3 := k.token("agent-3")
	one := fmt.Sprintf("[clients.agent-1]\ntoken_sha256 = %q\nsource = \"127.0.0.2\"\nallow_exit_host = true\ndefault = \"deny\"\nallow = [\"127.0.0.1\"]\n", h1)
	two := fmt.Sprintf("[clients.agent-2]\ntoken_sha256 = %q\nsource = \"127.0.0.3\"\nallow_exit_host = true\ndefault = \"deny\"\nallow = [\"127.0.0.1\"]\n", h2)
	three := fmt.Sprintf("[clients.agent-3]\ntoken_sha256 = %q\nsource = \"127.0.0.4\"\nallow_exit_host = true\ndefault = \"deny\"\nallow = [\"127.0.0.1\"]\n", h3)
	x := k.serve("exit-a", one+two)
	conf := filepath.Join(k.e.dir, "exit-a.toml")
	head, _ := os.ReadFile(conf)
	base := strings.SplitN(string(head), "[clients.", 2)[0]
	d1 := k.direct(x.addr, tok1)
	target := fmt.Sprintf("127.0.0.1:%d", srv.port)

	held := d1.dial()
	fmt.Fprintf(held, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", target, target, base64.StdEncoding.EncodeToString([]byte("vpnw:"+d1.token)))
	hb := bufio.NewReader(held)
	status, _ := hb.ReadString('\n')
	for {
		l, err := hb.ReadString('\n')
		if err != nil || l == "\r\n" {
			break
		}
	}
	if !strings.HasPrefix(status, "HTTP/1.1 200") {
		t.Fatalf("status %q", status)
	}
	wait := func(n int) {
		t0 := time.Now()
		for time.Since(t0) < 15*time.Second {
			if len(x.events(t, "exit.reload")) >= n {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("no exit.reload %d:\n%s", n, x.output())
	}
	// Reload 1: agent-3 added, agent-1 untouched.
	writeFile(t, k.e.dir, "exit-a.toml", base+one+two+three)
	wait(1)
	// Reload 2: agent-1 taken out.
	writeFile(t, k.e.dir, "exit-a.toml", base+two+three)
	wait(2)
	ev := fields(x.events(t, "exit.reload")[1])
	time.Sleep(300 * time.Millisecond)
	io.WriteString(held, "GET / HTTP/1.0\r\n\r\n")
	held.SetReadDeadline(time.Now().Add(5 * time.Second))
	rest, _ := io.ReadAll(hb)
	if strings.Contains(string(rest), "from 127.0.0.2") {
		t.Errorf("agent-1 was taken out (exit.reload %v), but its connection opened before an unrelated reload still carries traffic: %q", ev, rest)
	}
}
