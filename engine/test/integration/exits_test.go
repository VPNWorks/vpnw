// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// Agent 0.2.0 end to end: the real vpnw, sealed, with a list of two exits
// reached over TLS. The exits here are stand-ins written in this test; Exit's
// own tests run the real vpnw-exit in a private network.

type pki struct {
	caPEM []byte
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &pki{caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert: c, key: key}
}

func (p *pki) leaf(t *testing.T, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "exit"},
		NotBefore: notAfter.Add(-48 * time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.cert, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// tlsExit is a stand-in exit over TLS: it answers GET /health, and a
// CONNECT by playing the destination itself, saying which exit it is.
type tlsExit struct {
	name     string
	ln       net.Listener
	addr     string
	mu       sync.Mutex
	requests []map[string]string
	conns    []net.Conn
	// dieAfter, if above 0, stops the exit once it has served that many
	// requests, as if its process were killed.
	dieAfter int
	health   string
}

func startTLSExit(t *testing.T, name string, cert tls.Certificate, setup func(*tlsExit)) *tlsExit {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	x := &tlsExit{name: name, ln: ln, addr: ln.Addr().String(), health: "200 OK"}
	if setup != nil {
		setup(x)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			x.mu.Lock()
			x.conns = append(x.conns, c)
			x.mu.Unlock()
			go x.serve(tls.Server(c, cfg))
		}
	}()
	t.Cleanup(x.stop)
	return x
}

func (x *tlsExit) stop() {
	x.ln.Close()
	x.mu.Lock()
	for _, c := range x.conns {
		c.Close()
	}
	x.mu.Unlock()
}

func (x *tlsExit) seen() []map[string]string {
	x.mu.Lock()
	defer x.mu.Unlock()
	return append([]map[string]string(nil), x.requests...)
}

func (x *tlsExit) serve(c *tls.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	h := map[string]string{"line": strings.TrimSpace(line)}
	for {
		l, err := br.ReadString('\n')
		if err != nil || l == "\r\n" {
			break
		}
		k, v, _ := strings.Cut(strings.TrimSpace(l), ":")
		h[strings.ToLower(k)] = strings.TrimSpace(v)
	}
	if strings.HasPrefix(h["line"], "GET /health ") {
		io.WriteString(c, "HTTP/1.1 "+x.health+"\r\nContent-Length: 0\r\n\r\n")
		return
	}
	x.mu.Lock()
	x.requests = append(x.requests, h)
	n := len(x.requests)
	x.mu.Unlock()
	io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	// Now the destination: read one request and answer it.
	for {
		l, err := br.ReadString('\n')
		if err != nil || l == "\r\n" {
			break
		}
	}
	body := "via " + x.name + "\n"
	fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	if x.dieAfter > 0 && n >= x.dieAfter {
		x.ln.Close() // new connections are refused from now on
	}
}

func writeTemp(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExitListFailoverEndToEnd(t *testing.T) {
	skipIfNoSeal(t)
	ca := newPKI(t)
	good := ca.leaf(t, time.Now().Add(24*time.Hour))
	a := startTLSExit(t, "A", good, func(x *tlsExit) { x.dieAfter = 1 })
	b := startTLSExit(t, "B", good, nil)
	caFile := writeTemp(t, "ca.pem", ca.caPEM)
	tok := writeTemp(t, "token", []byte("agent-token-1\n"))
	probe := "import urllib.request\n" +
		"for i in range(3):\n" +
		"    print(urllib.request.urlopen('http://api.partner.test/', timeout=10).read().decode().strip())\n"
	out, evs := runProbe(t, []string{"trace", "--backend", "sealed", "--proxy", "https://" + a.addr, "--proxy", "https://" + b.addr,
		"--ca", caFile, "--token-file", tok}, probe)
	// The program's lines and vpnw's own share one output and can interleave.
	via := regexp.MustCompile(`via [AB]`).FindAllString(out, -1)
	if strings.Join(via, ",") != "via A,via B,via B" {
		t.Fatalf("the program did not go through A, then B:\n%s", out)
	}
	if strings.Contains(out, "agent-token-1") {
		t.Errorf("the token was printed:\n%s", out)
	}
	run := ""
	exits := map[float64]string{}
	switched := 0
	for _, e := range evs {
		f, _ := e["fields"].(map[string]any)
		switch e["type"] {
		case "run.start":
			run, _ = e["run"].(string)
			if f["path_kind"] != "exits" || !strings.Contains(fmt.Sprint(f["path"]), "https://"+a.addr+" (in use), https://"+b.addr) {
				t.Errorf("run.start %v", f)
			}
		case "connection.open":
			exits[e["conn"].(float64)], _ = f["exit"].(string)
		case "path.switch":
			switched++
			if e["conn"].(float64) != 2 || f["from"] != a.addr || f["to"] != b.addr {
				t.Errorf("switch %v", e)
			}
		}
	}
	if exits[1] != a.addr || exits[2] != b.addr || exits[3] != b.addr || switched != 1 {
		t.Errorf("exits per connection %v, %d switches\n%s", exits, switched, out)
	}
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("vpnw:agent-token-1"))
	ra, rb := a.seen(), b.seen()
	if len(ra) != 1 || len(rb) != 2 {
		t.Fatalf("A saw %d requests, B %d", len(ra), len(rb))
	}
	for i, r := range append(ra, rb...) {
		want := fmt.Sprint(i + 1)
		if r["vpnw-run"] != run || r["vpnw-conn"] != want || r["proxy-authorization"] != auth || r["line"] != "CONNECT api.partner.test:80 HTTP/1.1" {
			t.Errorf("request %d: %v (run %s)", i+1, r, run)
		}
	}
}

// The health check before the start refuses an exit whose certificate fails
// or that refuses the token, and the program never runs.
func TestExitRefusedBeforeStart(t *testing.T) {
	ca := newPKI(t)
	expired := startTLSExit(t, "old", ca.leaf(t, time.Now().Add(-time.Hour)), nil)
	strict := startTLSExit(t, "strict", ca.leaf(t, time.Now().Add(time.Hour)), func(x *tlsExit) { x.health = "407 Proxy Authentication Required" })
	caFile := writeTemp(t, "ca.pem", ca.caPEM)
	for _, c := range []struct {
		url, want string
	}{
		{"https://vpnw:tok@" + expired.addr, "certificate has expired"},
		{"https://vpnw:tok@" + strict.addr, "the exit refused the token"},
	} {
		marker := filepath.Join(t.TempDir(), "ran")
		cmd := exec.Command(vpnw, "run", "--backend", "env", "--no-save", "--proxy", c.url, "--ca", caFile, "--", "touch", marker)
		out, _ := cmd.CombinedOutput()
		if code := cmd.ProcessState.ExitCode(); code != 123 || !strings.Contains(string(out), c.want) || strings.Contains(string(out), ":tok@") {
			t.Errorf("%s: exit %d, want 123 and %q\n%s", c.url, code, c.want, out)
		}
		if _, err := os.Stat(marker); err == nil {
			t.Error("the program ran although its exit was refused")
		}
	}
	cmd := exec.Command(vpnw, "run", "--backend", "env", "--no-save", "--ca", caFile, "--", "true")
	if out, _ := cmd.CombinedOutput(); cmd.ProcessState.ExitCode() != 121 || !strings.Contains(string(out), "--ca and --token-file apply to --proxy") {
		t.Errorf("--ca without --proxy: %s", out)
	}
}
