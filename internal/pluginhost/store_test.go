// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package pluginhost_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VPNWorks/vpnw/internal/pluginhost"
	"github.com/VPNWorks/vpnw/plugins/builtin"
)

func TestManifest(t *testing.T) {
	good := "name = \"geo-fence\"\nversion = \"1.2.3\"\ntype = \"guard\"\nabi = 1\ndescription = \"x\"\npermissions = [\"events.emit\", \"events.emit\"]\n"
	m, err := pluginhost.ParseManifest(good)
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "geo-fence" || m.Type != "guard" || len(m.Permissions) != 1 || !m.Has("events.emit") || m.Has("console") {
		t.Errorf("%+v", m)
	}
	for _, tc := range []struct{ src, want string }{
		{"version = \"1.0.0\"\ntype = \"guard\"\nabi = 1\n", "name is missing"},
		{"name = \"Geo\"\nversion = \"1.0.0\"\ntype = \"guard\"\nabi = 1\n", "lower case"},
		{"name = \"g\"\nversion = \"one\"\ntype = \"guard\"\nabi = 1\n", "X.Y.Z"},
		{"name = \"g\"\nversion = \"1.0.0\"\ntype = \"tunnel\"\nabi = 1\n", "tunnel plugins need a later vpnw"},
		{"name = \"g\"\nversion = \"1.0.0\"\ntype = \"widget\"\nabi = 1\n", "unknown type"},
		{"name = \"g\"\nversion = \"1.0.0\"\ntype = \"guard\"\nabi = 2\n", "ABI 2"},
		{"name = \"g\"\nversion = \"1.0.0\"\ntype = \"guard\"\n", "abi is missing"},
		{"name = \"g\"\nversion = \"1.0.0\"\ntype = \"guard\"\nabi = 1\npermissions = [\"net\"]\n", "unknown permission \"net\""},
		{"name = \"g\"\nversion = \"1.0.0\"\ntype = \"guard\"\nabi = 1\nauthor = \"me\"\n", "unknown key \"author\""},
		{"name = \"g\"\nversion = \"1.0.0\"\ntype = \"guard\"\nabi = 1\n[extra]\n", "unexpected table"},
	} {
		if _, err := pluginhost.ParseManifest(tc.src); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: got %v, want %q", tc.src, err, tc.want)
		}
	}
}

func TestSignAndVerify(t *testing.T) {
	pub, priv, err := pluginhost.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	man, wasm := []byte("name = \"x\"\n"), []byte("\x00asm module")
	sig, err := pluginhost.Sign(priv, man, wasm)
	if err != nil {
		t.Fatal(err)
	}
	if who, err := pluginhost.Verify(sig, man, wasm, []string{pub}); err != nil || who != pub {
		t.Errorf("trusted: %q %v", who, err)
	}
	if who, err := pluginhost.Verify(sig, man, wasm, nil); err == nil || who != pub || !strings.Contains(err.Error(), "not a trusted key") {
		t.Errorf("untrusted: %q %v", who, err)
	}
	if _, err := pluginhost.Verify(sig, man, append(wasm, 0), []string{pub}); err == nil || !strings.Contains(err.Error(), "changed after signing") {
		t.Errorf("changed module: %v", err)
	}
	if _, err := pluginhost.Verify(sig, []byte("name = \"y\"\n"), wasm, []string{pub}); err == nil {
		t.Error("changed manifest passed")
	}
	if _, err := pluginhost.Sign(pub, man, wasm); err == nil {
		t.Error("signed with a public key")
	}
}

func store(t *testing.T) *pluginhost.Store {
	b, err := builtin.Packages()
	if err != nil {
		t.Fatal(err)
	}
	d := t.TempDir()
	return &pluginhost.Store{Dir: filepath.Join(d, "plugins"), ConfigDir: filepath.Join(d, "config"), Builtins: b}
}

func copyPlugin(t *testing.T, name string) string {
	t.Helper()
	src := plugin(t, name)
	dst := filepath.Join(t.TempDir(), name)
	os.MkdirAll(dst, 0o755)
	for _, f := range []string{"plugin.toml", "plugin.wasm"} {
		b, err := os.ReadFile(filepath.Join(src, f))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dst, f), b, 0o644)
	}
	return dst
}

func signDir(t *testing.T, dir, priv string) {
	t.Helper()
	p, _, err := pluginhost.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := pluginhost.Sign(priv, p.ManifestSrc, p.Wasm)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "plugin.sig"), []byte(sig), 0o644)
}

func TestStore(t *testing.T) {
	st, h := store(t), host(t)
	dir := copyPlugin(t, "blocker")

	if _, err := st.Install(sharedCtx, h, dir, false); err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("unsigned without --allow-unsigned: %v", err)
	}
	pub, priv, _ := pluginhost.GenerateKey()
	signDir(t, dir, priv)
	if _, err := st.Install(sharedCtx, h, dir, false); err == nil || !strings.Contains(err.Error(), "not a trusted key") {
		t.Fatalf("untrusted signer: %v", err)
	}
	if err := st.Trust(pub); err != nil {
		t.Fatal(err)
	}
	if err := st.Trust(pub); err != nil {
		t.Fatal(err)
	}
	if keys, _ := st.Trusted(); len(keys) != 1 {
		t.Errorf("trusted twice: %v", keys)
	}
	p, err := st.Install(sharedCtx, h, dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if p.Signer != pub {
		t.Errorf("signer %q", p.Signer)
	}
	list, errs := st.List()
	if len(errs) > 0 || len(list) != 3 || list[2].Manifest.Name != "blocker" {
		t.Errorf("list: %d %v", len(list), errs)
	}

	// Someone changes the installed module: Find catches it.
	wf := filepath.Join(st.Dir, "blocker", "plugin.wasm")
	b, _ := os.ReadFile(wf)
	os.WriteFile(wf, append(b, 0), 0o600)
	if _, err := st.Find("blocker"); err == nil || !strings.Contains(err.Error(), "changed after signing") {
		t.Errorf("changed after install: %v", err)
	}
	os.WriteFile(wf, b, 0o600)
	// The key is no longer trusted: Find refuses what it signed.
	os.WriteFile(filepath.Join(st.ConfigDir, "trusted-keys"), nil, 0o600)
	if _, err := st.Find("blocker"); err == nil || !strings.Contains(err.Error(), "not a trusted key") {
		t.Errorf("after untrusting: %v", err)
	}

	// Unsigned, accepted with --allow-unsigned; replaces the installed one.
	os.Remove(filepath.Join(dir, "plugin.sig"))
	if p, err = st.Install(sharedCtx, h, dir, true); err != nil || p.Signer != "" {
		t.Fatalf("allow-unsigned: %v", err)
	}
	if _, err := st.Find("blocker"); err != nil {
		t.Errorf("find unsigned: %v", err)
	}
	// What an install cut short leaves behind is not listed as a plugin.
	os.MkdirAll(filepath.Join(st.Dir, "blocker.old"), 0o700)
	os.MkdirAll(filepath.Join(st.Dir, ".install-123"), 0o700)
	if list, errs := st.List(); len(errs) > 0 || len(list) != 3 {
		t.Errorf("leftovers listed: %d %v", len(list), errs)
	}
	if err := st.Remove("blocker"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Find("blocker"); err == nil {
		t.Error("found after remove")
	}

	// A plugin that does not match its manifest is refused at install.
	if _, err := st.Install(sharedCtx, h, copyPlugin(t, "sneaky"), true); err == nil || !strings.Contains(err.Error(), "console") {
		t.Errorf("sneaky: %v", err)
	}
	// Built-in names are taken.
	tr := copyPlugin(t, "crash")
	man, _ := os.ReadFile(filepath.Join(tr, "plugin.toml"))
	os.WriteFile(filepath.Join(tr, "plugin.toml"), []byte(strings.Replace(string(man), `"crash"`, `"trace"`, 1)), 0o644)
	if _, err := st.Install(sharedCtx, h, tr, true); err == nil || !strings.Contains(err.Error(), "built-in") {
		t.Errorf("built-in name: %v", err)
	}
	if err := st.Remove("trace"); err == nil {
		t.Error("removed a built-in")
	}
	if _, err := st.Find("../etc"); err == nil {
		t.Error("found a path")
	}
}

// Text from a plugin reaches the console only cleaned: no escapes, no line
// breaks, no reordering marks, and not too long.
func TestCleanManifestDescription(t *testing.T) {
	for _, d := range []string{"two\nlines", "esc \x1b[31mred", "rtl ‮txt", strings.Repeat("x", 201)} {
		src := "name = \"g\"\nversion = \"1.0.0\"\ntype = \"guard\"\nabi = 1\ndescription = \"" + strings.ReplaceAll(strings.ReplaceAll(d, "\n", "\\n"), "\x1b", "\\u001b") + "\"\n"
		if _, err := pluginhost.ParseManifest(src); err == nil {
			t.Errorf("accepted description %q", d)
		}
	}
}
