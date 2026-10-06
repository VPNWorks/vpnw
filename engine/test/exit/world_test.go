// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package exittest

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"vpnw.com/vpnw/internal/events"
	"vpnw.com/vpnw/internal/exit"
	"vpnw.com/vpnw/internal/testnet"
)

// The test network. Every address here exists only inside its namespaces:
//
//	agents 192.0.2.2 ---.                            .--- internet: partner
//	                     \                          /     servers, a stand-in
//	exit-de 198.51.100.x --- router (this process) ---    DNS server at the
//	                     /                                address resolv.conf
//	exit-nl 203.0.113.x -'                                names
//
// exit-de stands for an exit in Germany and exit-nl for one in the
// Netherlands: each has a listening address and source addresses of its own.
const (
	agentsAddr = "192.0.2.2"
	deListen   = "198.51.100.2"
	nlListen   = "203.0.113.2"
	exitPort   = 8443
)

var exitSources = map[string][]string{
	"exit-de": {"198.51.100.10", "198.51.100.11", "198.51.100.20", "198.51.100.21"},
	"exit-nl": {"203.0.113.10", "203.0.113.11", "203.0.113.20", "203.0.113.21"},
}

// names is what the stand-in DNS server answers.
var names = map[string]string{
	"api.partner.test":      "51.15.0.10",
	"files.partner.test":    "51.15.0.11",
	"www.partner.test":      "51.15.0.12",
	"deep.a.partner.test":   "51.15.0.13",
	"partner.test":          "51.15.0.14",
	"intranet.partner.test": "10.50.0.5",
	"meta.partner.test":     "169.254.169.254",
	"attacker.test":         "66.66.0.66",
	"evilpartner.test":      "66.66.0.67",
	"public.test":           "93.184.215.14",
}

// Destination servers listen on every address in names on these ports.
var serverPorts = []int{80, 443, 8080}

// hit is one connection a destination server saw.
type hit struct {
	Src, Dst string
	Port     int
	At       time.Time
}

type world struct {
	t                        testing.TB
	agents, de, nl, internet *testnet.NS
	dir                      string
	ca                       *testCA
	dns                      *dnsServer
	mu                       sync.Mutex
	hits                     []hit
	closers                  []func()
}

func (w *world) ns(exitName string) *testnet.NS {
	if exitName == "exit-nl" {
		return w.nl
	}
	return w.de
}

// build makes the test network.
func build(t testing.TB) *world {
	t.Helper()
	w := &world{t: t, dir: t.TempDir(), dns: &dnsServer{names: map[string][]net.IP{}}}
	os.Chmod(w.dir, 0o755)
	for n, a := range names {
		w.dns.names[n] = []net.IP{net.ParseIP(a)}
	}
	w.dns.names["exit-de.test"] = []net.IP{net.ParseIP(deListen)}
	w.dns.names["exit-nl.test"] = []net.IP{net.ParseIP(nlListen)}
	var err error
	for _, p := range []struct {
		ns   **testnet.NS
		name string
	}{{&w.agents, "agents"}, {&w.de, "exit-de"}, {&w.nl, "exit-nl"}, {&w.internet, "internet"}} {
		if *p.ns, err = testnet.NewNS(p.name); err != nil {
			w.close()
			t.Fatal(err)
		}
	}
	t.Cleanup(w.close)
	links := []struct {
		router, inside string
		ns             *testnet.NS
		routerAddr     string
		addrs          []string
		gw             string
	}{
		{"r-a", "a0", w.agents, "192.0.2.1/24", []string{agentsAddr + "/24"}, "192.0.2.1"},
		{"r-d", "d0", w.de, "198.51.100.1/24", prefixed(append([]string{deListen}, exitSources["exit-de"]...), "/24"), "198.51.100.1"},
		{"r-n", "n0", w.nl, "203.0.113.1/24", prefixed(append([]string{nlListen}, exitSources["exit-nl"]...), "/24"), "203.0.113.1"},
		{"r-i", "i0", w.internet, "172.31.9.1/30", []string{"172.31.9.2/30"}, "172.31.9.1"},
	}
	for _, l := range links {
		must(t, testnet.AddVeth(l.router, l.inside))
		must(t, testnet.MoveLink(l.inside, l.ns))
		must(t, testnet.AddAddr(l.router, l.routerAddr))
		must(t, testnet.LinkUp(l.router))
		l := l
		must(t, l.ns.Do(func() error {
			for _, a := range l.addrs {
				if err := testnet.AddAddr(l.inside, a); err != nil {
					return err
				}
			}
			if err := testnet.LinkUp(l.inside); err != nil {
				return err
			}
			return testnet.AddRoute("default", l.gw)
		}))
	}
	must(t, testnet.Here.Sysctl("net/ipv4/ip_forward", "1"))
	for _, ns := range []*testnet.NS{testnet.Here, w.agents, w.de, w.nl, w.internet} {
		must(t, ns.Sysctl("net/ipv4/icmp_ratelimit", "0"))
	}
	// Destinations, and the DNS server, live on the internet side.
	dests := map[string]bool{}
	for _, a := range names {
		dests[a] = true
	}
	servers := resolvers()
	var loopbackDNS []string
	for _, s := range servers {
		if net.ParseIP(s).IsLoopback() {
			loopbackDNS = append(loopbackDNS, s)
		} else {
			dests[s] = true
		}
	}
	must(t, w.internet.Do(func() error {
		for a := range dests {
			if err := testnet.AddAddr("lo", a+"/32"); err != nil {
				return err
			}
		}
		return nil
	}))
	for a := range dests {
		must(t, testnet.AddRoute(a+"/32", "172.31.9.2"))
	}
	for a := range dests {
		isDNS := false
		for _, s := range servers {
			isDNS = isDNS || s == a
		}
		if isDNS {
			w.serveDNS(w.internet, a)
			continue
		}
		for _, port := range serverPorts {
			w.serveDest(a, port)
		}
	}
	// A resolver on loopback (127.0.0.53, say) has to answer in every
	// namespace that looks names up.
	for _, s := range loopbackDNS {
		for _, ns := range []*testnet.NS{w.agents, w.de, w.nl} {
			w.serveDNS(ns, s)
		}
	}
	w.ca = newCA(t, "VPN Works test CA")
	w.writeCert("exit-de", w.ca.leaf(t, []string{"exit-de.test"}, []string{deListen}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)))
	w.writeCert("exit-nl", w.ca.leaf(t, []string{"exit-nl.test"}, []string{nlListen}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)))
	w.write("ca.pem", string(w.ca.pem))
	return w
}

func prefixed(addrs []string, suffix string) []string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a + suffix
	}
	return out
}

func (w *world) close() {
	for i := len(w.closers) - 1; i >= 0; i-- {
		w.closers[i]()
	}
	for _, ns := range []*testnet.NS{w.agents, w.de, w.nl, w.internet} {
		if ns != nil {
			ns.Close()
		}
	}
	for _, l := range []string{"r-a", "r-d", "r-n", "r-i"} {
		testnet.DelLink(l)
	}
}

// resolvers returns the IPv4 name servers in /etc/resolv.conf, the ones the
// binaries' resolver will ask.
func resolvers() []string {
	b, _ := os.ReadFile("/etc/resolv.conf")
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			if ip := net.ParseIP(f[1]); ip != nil && ip.To4() != nil {
				out = append(out, f[1])
			}
		}
	}
	return out
}

func (w *world) write(name, content string) string {
	p := filepath.Join(w.dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		w.t.Fatal(err)
	}
	return p
}

// serveDest runs a stand-in partner server: it answers an HTTP request with
// the source address it saw, and records every connection.
func (w *world) serveDest(addr string, port int) {
	var ln net.Listener
	must(w.t, w.internet.Do(func() error {
		var err error
		ln, err = net.Listen("tcp", net.JoinHostPort(addr, fmt.Sprint(port)))
		return err
	}))
	w.closers = append(w.closers, func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			src, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			w.mu.Lock()
			w.hits = append(w.hits, hit{Src: src, Dst: addr, Port: port, At: time.Now().UTC()})
			w.mu.Unlock()
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				br := bufio.NewReader(c)
				for {
					l, err := br.ReadString('\n')
					if err != nil || l == "\r\n" || l == "\n" {
						break
					}
				}
				body := fmt.Sprintf("seen-from %s at %s:%d\n", src, addr, port)
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			}(c)
		}
	}()
}

// hitsSince returns the connections destination servers saw after t.
func (w *world) hitsSince(t time.Time) []hit {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []hit
	for _, h := range w.hits {
		if !h.At.Before(t) {
			out = append(out, h)
		}
	}
	return out
}

// ---- the stand-in DNS server ----

type dnsServer struct {
	mu      sync.Mutex
	names   map[string][]net.IP
	queries []string
}

func (w *world) serveDNS(ns *testnet.NS, addr string) {
	var pc net.PacketConn
	var ln net.Listener
	must(w.t, ns.Do(func() error {
		var err error
		if pc, err = net.ListenPacket("udp", addr+":53"); err != nil {
			return err
		}
		ln, err = net.Listen("tcp", addr+":53")
		return err
	}))
	w.closers = append(w.closers, func() { pc.Close(); ln.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if resp := w.dns.answer(buf[:n]); resp != nil {
				pc.WriteTo(resp, from)
			}
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				for {
					var l [2]byte
					if _, err := io.ReadFull(c, l[:]); err != nil {
						return
					}
					q := make([]byte, binary.BigEndian.Uint16(l[:]))
					if _, err := io.ReadFull(c, q); err != nil {
						return
					}
					resp := w.dns.answer(q)
					if resp == nil {
						return
					}
					c.Write(append([]byte{byte(len(resp) >> 8), byte(len(resp))}, resp...))
				}
			}(c)
		}
	}()
}

// answer builds the reply to one query: A and AAAA records from the table,
// NXDOMAIN for names it does not know.
func (d *dnsServer) answer(q []byte) []byte {
	if len(q) < 12 || binary.BigEndian.Uint16(q[4:6]) != 1 {
		return nil
	}
	off := 12
	var labels []string
	for {
		if off >= len(q) {
			return nil
		}
		l := int(q[off])
		off++
		if l == 0 {
			break
		}
		if l&0xc0 != 0 || off+l > len(q) {
			return nil
		}
		labels = append(labels, string(q[off:off+l]))
		off += l
	}
	if off+4 > len(q) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(q[off:])
	off += 4
	name := strings.ToLower(strings.Join(labels, "."))
	d.mu.Lock()
	d.queries = append(d.queries, name)
	ips, known := d.names[name]
	d.mu.Unlock()
	var ans []byte
	count := 0
	for _, ip := range ips {
		var rdata []byte
		var typ uint16
		switch {
		case qtype == 1 && ip.To4() != nil:
			rdata, typ = ip.To4(), 1
		case qtype == 28 && ip.To4() == nil:
			rdata, typ = ip.To16(), 28
		default:
			continue
		}
		rr := []byte{0xc0, 0x0c, byte(typ >> 8), byte(typ), 0, 1, 0, 0, 0, 60, 0, byte(len(rdata))}
		ans = append(append(ans, rr...), rdata...)
		count++
	}
	rcode := byte(0)
	if !known {
		rcode = 3
	}
	h := []byte{q[0], q[1], 0x81 | (q[2] & 0x01), 0x80 | rcode, 0, 1, 0, byte(count), 0, 0, 0, 0}
	return append(append(h, q[12:off]...), ans...)
}

// ---- certificates ----

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t testing.TB, name string) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

type certPEM struct{ cert, key string }

func (ca *testCA) leaf(t testing.TB, dnsNames, ips []string, notBefore, notAfter time.Time) certPEM {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "exit"},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: dnsNames}
	for _, a := range ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(a))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	return certPEM{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}))}
}

func (w *world) writeCert(name string, c certPEM) {
	w.write(name+".crt", c.cert)
	w.write(name+".key", c.key)
}

// ---- clients, policies and exits ----

// client is one client of the exits, with a token and a policy file that
// the Agent and the exits both read.
type client struct {
	name, token string
	policy      string // the [policy] table's body
	// sources maps an exit's name to the client's address there; empty
	// means the exit's pool.
	sources map[string]string
}

func (w *world) policyFile(c client) string {
	return w.write(c.name+".toml", fmt.Sprintf("version = 1\nname = %q\n\n[paths.exits]\ntype = \"proxy\"\nurls = [\"https://%s:%d\", \"https://%s:%d\"]\nca_file = \"ca.pem\"\ntoken_file = %q\n\n[policy]\n%s",
		c.name, deListen, exitPort, nlListen, exitPort, c.name+".token", c.policy))
}

func (w *world) tokenFile(c client) string { return w.write(c.name+".token", c.token+"\n") }

// exitConfig writes an exit's configuration for the clients given.
func (w *world) exitConfig(exitName, listen string, port int, cert string, clients []client) string {
	var b strings.Builder
	fmt.Fprintf(&b, "version = 1\nname = %q\nlisten = \"%s:%d\"\ncert = %q\nkey = %q\n", exitName, listen, port, cert+".crt", cert+".key")
	pool := exitSources[exitName][2:]
	for _, c := range clients {
		w.policyFile(c)
		fmt.Fprintf(&b, "\n[clients.%s]\ntoken_sha256 = %q\n", c.name, exit.HashHex(c.token))
		if a := c.sources[exitName]; a != "" {
			fmt.Fprintf(&b, "source = %q\n", a)
		} else {
			fmt.Fprintf(&b, "pool = \"shared\"\n")
		}
		fmt.Fprintf(&b, "policy = %q\n", c.name+".toml")
	}
	fmt.Fprintf(&b, "\n[pools.shared]\naddresses = [%q, %q]\n", pool[0], pool[1])
	return w.write(exitName+"-"+fmt.Sprint(port)+".toml", b.String())
}

// exitProc is a running vpnw-exit.
type exitProc struct {
	name   string
	cmd    *exec.Cmd
	stderr *syncBuf
	record string
	done   chan struct{}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// startExit runs vpnw-exit serve in the exit's namespace and waits until it
// listens.
func (w *world) startExit(exitName, config string) *exitProc {
	w.t.Helper()
	p := &exitProc{name: exitName, stderr: &syncBuf{}, record: config + ".jsonl", done: make(chan struct{})}
	p.cmd = exec.Command(exitBin, "serve", "--config", config, "--out", p.record, "-v")
	p.cmd.Stderr = p.stderr
	p.cmd.Env = exitEnv()
	if err := w.ns(exitName).Start(p.cmd); err != nil {
		w.t.Fatal(err)
	}
	go func() { p.cmd.Wait(); close(p.done) }()
	w.closers = append(w.closers, p.stop)
	re := regexp.MustCompile(`listening on`)
	deadline := time.Now().Add(20 * time.Second)
	for !re.MatchString(p.stderr.String()) {
		select {
		case <-p.done:
			w.t.Fatalf("%s did not start:\n%s", exitName, p.stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			w.t.Fatalf("%s did not start in time:\n%s", exitName, p.stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	return p
}

// kill ends the exit at once, as a crash would: no goodbye, no summary.
func (p *exitProc) kill() {
	p.cmd.Process.Signal(syscall.SIGKILL)
	<-p.done
}

// stop ends the exit cleanly.
func (p *exitProc) stop() {
	select {
	case <-p.done:
		return
	default:
	}
	p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(10 * time.Second):
		p.cmd.Process.Kill()
		<-p.done
	}
}

func readRecord(t testing.TB, name string) []events.Event {
	t.Helper()
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	evs, err := events.Read(f)
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

// agentProc is a vpnw run in the agents' namespace.
type agentProc struct {
	cmd    *exec.Cmd
	out    *syncBuf
	trace  string
	done   chan struct{}
	code   int
	stdout io.ReadCloser
}

// startAgent runs vpnw (guard, sealed) with a Python workload. The
// workload's standard output can be read as it runs from p.stdout.
func (w *world) startAgent(name string, args []string, script string) *agentProc {
	w.t.Helper()
	p := &agentProc{out: &syncBuf{}, trace: filepath.Join(w.dir, fmt.Sprintf("%s-%d.jsonl", name, time.Now().UnixNano())), done: make(chan struct{})}
	full := append(append([]string{}, args...), "--no-save", "--out", p.trace, "--", "python3", "-u", "-c", script)
	p.cmd = exec.Command(vpnwBin, full...)
	p.cmd.Dir = w.dir
	p.cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + w.dir, "NO_COLOR=1"}
	p.cmd.Stderr = p.out
	var err error
	if p.stdout, err = p.cmd.StdoutPipe(); err != nil {
		w.t.Fatal(err)
	}
	if err := w.agents.Start(p.cmd); err != nil {
		w.t.Fatal(err)
	}
	return p
}

// wait reads the rest of the workload's output and waits for vpnw.
func (p *agentProc) wait() string {
	rest, _ := io.ReadAll(p.stdout)
	p.cmd.Wait()
	p.code = p.cmd.ProcessState.ExitCode()
	return string(rest)
}

// runAgent runs vpnw to the end and returns the workload's output, vpnw's
// own output and the trace.
func (w *world) runAgent(name string, args []string, script string) (string, *agentProc, []events.Event) {
	w.t.Helper()
	p := w.startAgent(name, args, script)
	out := p.wait()
	var evs []events.Event
	if _, err := os.Stat(p.trace); err == nil {
		evs = readRecord(w.t, p.trace)
	}
	return out, p, evs
}

// fetch is a workload that fetches URLs through vpnw's proxy and prints one
// line per URL: the server's answer, or the error.
func fetch(urls ...string) string {
	var q []string
	for _, u := range urls {
		q = append(q, fmt.Sprintf("%q", u))
	}
	return "import urllib.request\n" +
		"for u in [" + strings.Join(q, ", ") + "]:\n" +
		"    try:\n" +
		"        print('OK', u, urllib.request.urlopen(u, timeout=15).read().decode().strip(), flush=True)\n" +
		"    except Exception as e:\n" +
		"        print('ERR', u, str(e).replace('\\n', ' '), flush=True)\n"
}

// lines returns the workload's lines that start with prefix, sorted by
// nothing: in the order they came.
func lines(out, prefix string) []string {
	var r []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, prefix) {
			r = append(r, l)
		}
	}
	return r
}

func sortedKeys(m map[string]int) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}
