// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package exit

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A certificate the private CA signs passes a client's check for each
// address and name it was made for, and for nothing else.
func TestCert(t *testing.T) {
	now := time.Now()
	ca, caPEM, caKey, err := NewCA(now)
	if err != nil {
		t.Fatal(err)
	}
	crt, key, err := ca.Issue([]string{"198.51.100.2", "Exit.Example.com", "[2001:db8::2]"}, now)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := tls.X509KeyPair(crt, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(kp.Certificate[0])
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("ca.pem")
	}
	for _, name := range []string{"198.51.100.2", "exit.example.com", "2001:db8::2"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, name := range []string{"198.51.100.3", "other.example.com"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name}); err == nil {
			t.Errorf("%s passed", name)
		}
	}
	if !leaf.NotAfter.After(now.Add(CertValid-time.Hour)) || leaf.IsCA {
		t.Errorf("leaf: until %v, CA %v", leaf.NotAfter, leaf.IsCA)
	}
	// The CA comes back from its files and signs again.
	dir := t.TempDir()
	cf, kf := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	os.WriteFile(cf, caPEM, 0o644)
	os.WriteFile(kf, caKey, 0o600)
	ca2, err := LoadCA(cf, kf)
	if err != nil {
		t.Fatal(err)
	}
	crt2, _, err := ca2.Issue([]string{"203.0.113.2"}, now)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(crt2)
	leaf2, _ := x509.ParseCertificate(blk.Bytes)
	if _, err := leaf2.Verify(x509.VerifyOptions{Roots: roots, DNSName: "203.0.113.2"}); err != nil {
		t.Errorf("second exit: %v", err)
	}
	// A key that isn't the CA's, a leaf taken for a CA, and bad hosts.
	_, _, otherKey, _ := NewCA(now)
	os.WriteFile(kf, otherKey, 0o600)
	if _, err := LoadCA(cf, kf); err == nil || !strings.Contains(err.Error(), "is not the key of") {
		t.Errorf("other key: %v", err)
	}
	os.WriteFile(cf, crt, 0o644)
	if _, err := LoadCA(cf, kf); err == nil || !strings.Contains(err.Error(), "not a CA") {
		t.Errorf("leaf as CA: %v", err)
	}
	for _, hosts := range [][]string{nil, {"a b"}, {"http://x"}, {""}} {
		if _, _, err := ca.Issue(hosts, now); err == nil {
			t.Errorf("%q accepted", hosts)
		}
	}
}
