// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package exit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// An exit usually runs on a fixed address, and public CAs rarely sign
// certificates for addresses, so vpnw exit cert makes a private one: a CA
// that clients trust (vpnw --ca ca.pem), which signs each exit's
// certificate. One CA can sign several exits, so clients of a list of exits
// trust a single file.

// CAValid and CertValid are how long a CA and an exit's certificate last.
const (
	CAValid   = 10 * 365 * 24 * time.Hour
	CertValid = 2 * 365 * 24 * time.Hour
)

// CA is a private certificate authority for exits.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

// NewCA makes a CA. It returns the CA with its certificate and key in PEM.
func NewCA(now time.Time) (*CA, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: "VPN Works exit CA", Organization: []string{"VPN Works exit"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(CAValid),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	kp, err := keyPEM(key)
	if err != nil {
		return nil, nil, nil, err
	}
	return &CA{Cert: cert, Key: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), kp, nil
}

func keyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// LoadCA reads a CA that vpnw exit cert made before.
func LoadCA(certFile, keyFile string) (*CA, error) {
	cb, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	kb, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(cb)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s holds no certificate", certFile)
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", certFile, err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("%s is not a CA's certificate", certFile)
	}
	kblk, _ := pem.Decode(kb)
	if kblk == nil || kblk.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s holds no private key", keyFile)
	}
	k, err := x509.ParsePKCS8PrivateKey(kblk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", keyFile, err)
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || !key.PublicKey.Equal(cert.PublicKey) {
		return nil, fmt.Errorf("%s is not the key of %s", keyFile, certFile)
	}
	return &CA{Cert: cert, Key: key}, nil
}

// Issue makes an exit's certificate and key for hosts, each an address or a
// name the clients will use to reach it.
func (ca *CA) Issue(hosts []string, now time.Time) ([]byte, []byte, error) {
	if len(hosts) == 0 {
		return nil, nil, errors.New("give at least one address or name the clients reach the exit by")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: hosts[0], Organization: []string{"VPN Works exit"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(CertValid),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			continue
		}
		if h == "" || strings.ContainsAny(h, " /:@") {
			return nil, nil, fmt.Errorf("%q is neither an address nor a host name", h)
		}
		tmpl.DNSNames = append(tmpl.DNSNames, strings.ToLower(h))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, nil, err
	}
	kp, err := keyPEM(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), kp, nil
}
