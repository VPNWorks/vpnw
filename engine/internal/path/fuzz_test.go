// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package path

import (
	"bytes"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// FuzzFromURL feeds arbitrary proxy URLs to the parser. Whatever it is
// given, it must not crash, and neither a description nor an error may ever
// show the password.
//
// FromURL's errors quote every value they show with %q, so the check
// unquotes each quoted part and looks for the password there. Looking in the
// whole message found passwords that weren't there: in "\x10000", the
// escape of a control byte followed by the host's digits reads "0000", and
// the message's own words, such as "host" or "port", could match a password
// too. A description is checked up to its comma, before the words about DNS.
func FuzzFromURL(f *testing.F) {
	for _, s := range []string{
		"socks5://alice:s3cret@127.0.0.1:1080", "https://vpnw:s3cret@exit.example:8443",
		"socks5+tls://vpnw:s3cret@[::1]:8443", "http://h:3128", "https://s3cret@h:1",
		"https://vpnw:s3cret@h", "socks5h://u:s3cret@h:1/x", "ftp://u:s3cret@h:21", "%zz",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		p, err := FromURL("fuzz", raw)
		if err != nil {
			pass := passwordIn(raw)
			if len(pass) >= 4 && strings.Count(raw, pass) == 1 {
				for _, q := range quotedIn(err.Error()) {
					if strings.Contains(q, pass) {
						t.Fatalf("error shows the password %q: %v", pass, err)
					}
				}
			}
			return
		}
		px := p.(*Proxy)
		desc, _, _ := strings.Cut(px.Describe(), ", ")
		if len(px.Pass) >= 4 && strings.Count(raw, px.Pass) == 1 && strings.Contains(desc, px.Pass) {
			t.Fatalf("description shows the password: %s", px.Describe())
		}
		if px.TLS != nil && px.TLS.InsecureSkipVerify {
			t.Fatal("certificate checking is off")
		}
	})
}

// quotedIn returns the parts of a message quoted with %q, unquoted.
func quotedIn(msg string) []string {
	var out []string
	for i := 0; i < len(msg); i++ {
		if msg[i] != '"' {
			continue
		}
		for j := i + 1; j < len(msg); j++ {
			if msg[j] == '\\' {
				j++
				continue
			}
			if msg[j] == '"' {
				if q, err := strconv.Unquote(msg[i : j+1]); err == nil {
					out = append(out, q)
				}
				i = j
				break
			}
		}
	}
	return out
}

// passwordIn returns what a URL holds between "user:" and "@", if anything.
func passwordIn(raw string) string {
	i := strings.Index(raw, "://")
	j := strings.LastIndex(raw, "@")
	if i < 0 || j < i {
		return ""
	}
	ui := raw[i+3 : j]
	if k := strings.Index(ui, ":"); k >= 0 {
		return ui[k+1:]
	}
	return ""
}

// FuzzExitAnswer feeds arbitrary bytes to the Agent as a VPN Works exit's
// answer to a CONNECT and to a health check. Nothing may crash or hang, and
// what reaches an error message must be printable.
func FuzzExitAnswer(f *testing.F) {
	for _, s := range []string{
		"HTTP/1.1 200 Connection established\r\n\r\nearly",
		"HTTP/1.1 403 Forbidden\r\nVPNW-Rule: deny_private\r\nVPNW-Reason: 10.0.0.5: private\r\n\r\n",
		"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
		"HTTP/1.1 502 Bad Gateway\r\nVPNW-Reason: \x00\x1b[31mred\r\n\r\n",
		"HTTP/1.0 503 Busy\r\n\r\n", "garbage", "",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, answer []byte) {
		ex := &exitIDs{conn: &Conn{Run: "r-fuzz", ID: 1}}
		c := &scripted{r: bytes.NewReader(answer)}
		_, err := httpConnect(c, "example.com", 443, "vpnw", "tok", ex)
		if err != nil {
			for _, r := range err.Error() {
				if r < 0x20 && r != '\t' || r == 0x7f {
					t.Fatalf("control character in %q", err.Error())
				}
			}
		}
		p := &Proxy{Addr: "exit.test:8443", User: "vpnw", Pass: "tok"}
		p.httpHealth(&scripted{r: bytes.NewReader(answer)})
		p.socksHealth(&scripted{r: bytes.NewReader(answer)})
	})
}

// scripted is a connection that reads a fixed answer and keeps what is
// written to it.
type scripted struct {
	r   *bytes.Reader
	out bytes.Buffer
}

func (c *scripted) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c *scripted) Write(p []byte) (int, error)      { return c.out.Write(p) }
func (c *scripted) Close() error                     { return nil }
func (c *scripted) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *scripted) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *scripted) SetDeadline(time.Time) error      { return nil }
func (c *scripted) SetReadDeadline(time.Time) error  { return nil }
func (c *scripted) SetWriteDeadline(time.Time) error { return nil }
