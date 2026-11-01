// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package pluginhost_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/VPNWorks/vpnw/internal/pluginhost"
)

// Review 0.10.0 (low): two vpnw commands using the default key for the
// first time at once (parallel CI jobs) must both get the one key. The
// loser of the O_EXCL race fails, or reads the file before it is written.
func TestReview0100FirstUseRace(t *testing.T) {
	fails := 0
	for round := 0; round < 200; round++ {
		file := filepath.Join(t.TempDir(), "vpnw", "signing.key")
		var wg sync.WaitGroup
		var mu sync.Mutex
		var pubs []string
		var errs []error
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s, _, err := pluginhost.LoadSigner(file, true)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					errs = append(errs, err)
				} else {
					pubs = append(pubs, s.Public)
				}
			}()
		}
		wg.Wait()
		if len(errs) > 0 {
			fails++
			if fails == 1 {
				t.Errorf("round %d: concurrent first use failed: %v", round, errs[0])
			}
		}
	}
	if fails > 0 {
		t.Logf("%d of 200 rounds had a failing first use", fails)
	}
}

// Review 0.10.0 (low): ParsePublicKey accepts a non-canonical spelling of
// a key, which vpnw verify --key then passes on as a different string.
func TestReview0100NonCanonicalPublicKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	s := base64.StdEncoding.EncodeToString(pub)
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	b := []byte(s)
	b[len(b)-2] = alpha[strings.IndexByte(alpha, b[len(b)-2])^1]
	alt := "vpnw-ed25519:" + string(b)
	k, err := pluginhost.ParsePublicKey(alt)
	if err == nil && string(k) == string(pub) {
		t.Errorf("non-canonical %s accepted as the same key as vpnw-ed25519:%s", alt, s)
	}
}

// Review 0.10.0 (doc nit): a public key given as --sign-key is refused,
// but the message says the file "starts with" the private prefix.
func TestReview0100PublicKeyAsSignKeyMessage(t *testing.T) {
	file := filepath.Join(t.TempDir(), "k.pub")
	pluginhost.LoadSigner(file, true) // make one, then overwrite with a public key
	s, _, _ := pluginhost.LoadSigner(file, false)
	writeFile(t, file, s.Public+"\n")
	_, _, err := pluginhost.LoadSigner(file, false)
	if err == nil || strings.Contains(err.Error(), "(it starts with") {
		t.Errorf("message: %v", err)
	}
}

func writeFile(t *testing.T, f, s string) {
	t.Helper()
	if err := osWriteFile(f, []byte(s)); err != nil {
		t.Fatal(err)
	}
}
func osWriteFile(f string, b []byte) error { return os.WriteFile(f, b, 0o600) }
