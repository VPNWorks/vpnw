// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/VPNWorks/vpnw/internal/config"
	"github.com/VPNWorks/vpnw/internal/events"
	"github.com/VPNWorks/vpnw/internal/policy"
)

// recordingPath never touches the network: it records every dial and fails.
type recordingPath struct{ dials chan string }

func (recordingPath) ID() string       { return "fuzz" }
func (recordingPath) Kind() string     { return "direct" }
func (recordingPath) RemoteDNS() bool  { return false }
func (recordingPath) Describe() string { return "fuzz" }
func (r recordingPath) Dial(_ context.Context, host string, ip net.IP, port int) (net.Conn, error) {
	r.dials <- host + "|" + ip.String()
	return nil, errors.New("fuzz path does not dial")
}
func (recordingPath) Health(context.Context) error { return nil }

// FuzzHandle feeds arbitrary bytes to the broker as a sandboxed program
// would. Whatever arrives, the broker must not crash or hang, and it must
// never dial a destination the policy denies: with this policy only
// allowed.test (resolving to 93.184.215.14) may ever be dialed.
func FuzzHandle(f *testing.F) {
	for _, s := range []string{
		"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n",
		"CONNECT evil.test:443 HTTP/1.1\r\n\r\n",
		"GET http://allowed.test/x HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
		"GET http://127.0.0.1:80/ HTTP/1.1\r\n\r\n",
		"\x05\x01\x00\x05\x01\x00\x03\x0callowed.test\x01\xbb",
		"\x05\x01\x00\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50",
		"\x05\x01\x00\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00",
		"\x04\x01\x00\x50\x7f\x00\x00\x01\x00",
		"CONNECT [::ffff:127.0.0.1]:22 HTTP/1.1\r\n\r\n",
		"CONNECT allowed.test.:443 HTTP/1.1\r\n\r\n",
	} {
		f.Add([]byte(s))
	}
	pol, err := policy.New(&config.PolicySpec{Default: "deny", DenyPrivate: true, Allow: []string{"allowed.test"}}, "fuzz")
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		dials := make(chan string, 8)
		bus := events.NewBus("r-fuzz", nil)
		b := &Broker{
			Policy:   pol,
			Path:     recordingPath{dials: dials},
			Resolver: &fakeDNS{m: map[string][]net.IP{"allowed.test": {net.ParseIP("93.184.215.14")}, "evil.test": {net.ParseIP("10.0.0.1")}}},
			Bus:      bus,
		}
		c := &fakeConn{r: bytes.NewReader(input)}
		done := make(chan struct{})
		go func() {
			b.Handle(c)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("the broker hung on this input")
		}
		close(dials)
		for d := range dials {
			if d != "allowed.test|93.184.215.14" {
				t.Fatalf("dialed %s, which the policy does not allow", d)
			}
		}
	})
}

// fakeConn serves a fixed input, then EOF, and keeps what the broker writes.
type fakeConn struct {
	r   *bytes.Reader
	out bytes.Buffer
}

func (c *fakeConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c *fakeConn) Write(p []byte) (int, error)      { return c.out.Write(p) }
func (c *fakeConn) Close() error                     { return nil }
func (c *fakeConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *fakeConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }
