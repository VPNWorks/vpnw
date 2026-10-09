// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package pluginhost

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// MaxWasm caps the size of a plugin module.
const MaxWasm = 64 << 20

// Built-in marks a package compiled into vpnw.
const BuiltinSource = "built-in"

// Store holds the installed plugins and the trusted signing keys.
//
// A plugin is installed as <Dir>/<name>/ with plugin.toml, plugin.wasm and,
// if it was signed, plugin.sig. Trusted keys are one per line in
// <ConfigDir>/trusted-keys.
type Store struct {
	Dir       string
	ConfigDir string
	Builtins  []*Package
}

// DefaultStore uses the XDG directories: ~/.local/share/vpnw/plugins and
// ~/.config/vpnw unless XDG_DATA_HOME or XDG_CONFIG_HOME say otherwise.
func DefaultStore(builtins []*Package) (*Store, error) {
	data, err := xdg("XDG_DATA_HOME", ".local/share")
	if err != nil {
		return nil, err
	}
	conf, err := xdg("XDG_CONFIG_HOME", ".config")
	if err != nil {
		return nil, err
	}
	return &Store{Dir: filepath.Join(data, "vpnw", "plugins"), ConfigDir: filepath.Join(conf, "vpnw"), Builtins: builtins}, nil
}

// CacheDir is where compiled plugins are kept: ~/.cache/vpnw/wasm.
func CacheDir() string {
	d, err := xdg("XDG_CACHE_HOME", ".cache")
	if err != nil {
		return ""
	}
	return filepath.Join(d, "vpnw", "wasm")
}

func xdg(env, rel string) (string, error) {
	if d := os.Getenv(env); d != "" {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("cannot find a home directory; set " + env)
	}
	return filepath.Join(home, rel), nil
}

// ReadDir reads a plugin from a directory holding plugin.toml, plugin.wasm
// and, optionally, plugin.sig.
func ReadDir(dir string) (pkg *Package, sig string, err error) {
	man, err := os.ReadFile(filepath.Join(dir, "plugin.toml"))
	if err != nil {
		return nil, "", fmt.Errorf("%s: %v", dir, err)
	}
	m, err := ParseManifest(string(man))
	if err != nil {
		return nil, "", fmt.Errorf("%s: %v", dir, err)
	}
	wf := filepath.Join(dir, "plugin.wasm")
	st, err := os.Stat(wf)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %v", dir, err)
	}
	if st.Size() > MaxWasm {
		return nil, "", fmt.Errorf("%s: plugin.wasm is larger than %d MiB", dir, MaxWasm>>20)
	}
	wasm, err := os.ReadFile(wf)
	if err != nil {
		return nil, "", err
	}
	if b, err := os.ReadFile(filepath.Join(dir, "plugin.sig")); err == nil {
		sig = string(b)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, "", err
	}
	return &Package{Manifest: m, ManifestSrc: man, Wasm: wasm, Source: dir}, sig, nil
}

// Trusted returns the trusted signing keys.
func (s *Store) Trusted() ([]string, error) {
	f, err := os.Open(filepath.Join(s.ConfigDir, "trusted-keys"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var keys []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			keys = append(keys, l)
		}
	}
	return keys, sc.Err()
}

// Trust adds a public key to the trusted keys.
func (s *Store) Trust(key string) error {
	if _, err := ParsePublicKey(key); err != nil {
		return err
	}
	have, err := s.Trusted()
	if err != nil {
		return err
	}
	for _, k := range have {
		if k == strings.TrimSpace(key) {
			return nil
		}
	}
	if err := os.MkdirAll(s.ConfigDir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(s.ConfigDir, "trusted-keys"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, strings.TrimSpace(key)); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (s *Store) builtin(name string) *Package {
	for _, p := range s.Builtins {
		if p.Manifest.Name == name {
			return p
		}
	}
	return nil
}

// Find returns a built-in or installed plugin by name. An installed plugin
// that was signed is checked against the trusted keys again, so removing a
// key from trusted-keys stops the plugins it signed.
func (s *Store) Find(name string) (*Package, error) {
	if p := s.builtin(name); p != nil {
		return p, nil
	}
	if !nameRe.MatchString(name) {
		return nil, fmt.Errorf("no plugin %q", name)
	}
	dir := filepath.Join(s.Dir, name)
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("no plugin %q; see vpnw plugin list", name)
	}
	pkg, sig, err := ReadDir(dir)
	if err != nil {
		return nil, err
	}
	if pkg.Manifest.Name != name {
		return nil, fmt.Errorf("%s holds plugin %q, not %q", dir, pkg.Manifest.Name, name)
	}
	if sig != "" {
		trusted, err := s.Trusted()
		if err != nil {
			return nil, err
		}
		if pkg.Signer, err = Verify(sig, pkg.ManifestSrc, pkg.Wasm, trusted); err != nil {
			return nil, fmt.Errorf("plugin %s: %v", name, err)
		}
	}
	return pkg, nil
}

// List returns the built-in plugins, then the installed ones by name.
// Installed plugins that cannot be read are returned as errors alongside.
func (s *Store) List() ([]*Package, []error) {
	out := append([]*Package{}, s.Builtins...)
	var errs []error
	ents, err := os.ReadDir(s.Dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return out, []error{err}
	}
	var names []string
	for _, e := range ents {
		// Only folders named like a plugin: an install that was cut short
		// leaves NAME.old or .install-* behind, which are not plugins.
		if e.IsDir() && nameRe.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, n := range names {
		p, err := s.Find(n)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, p)
	}
	return out, errs
}

// Install copies a plugin into the store after checking it: the manifest,
// the signature (unless allowUnsigned) and, by compiling it with h, that the
// module matches its manifest. It replaces an installed plugin of the same
// name.
func (s *Store) Install(ctx context.Context, h *Host, src string, allowUnsigned bool) (*Package, error) {
	pkg, sig, err := ReadDir(src)
	if err != nil {
		return nil, err
	}
	name := pkg.Manifest.Name
	if s.builtin(name) != nil {
		return nil, fmt.Errorf("%q is the name of a built-in plugin; rename it", name)
	}
	switch {
	case sig == "" && !allowUnsigned:
		return nil, errors.New("the plugin is not signed; install it anyway with --allow-unsigned if you trust where it came from")
	case sig != "":
		trusted, err := s.Trusted()
		if err != nil {
			return nil, err
		}
		pkg.Signer, err = Verify(sig, pkg.ManifestSrc, pkg.Wasm, trusted)
		switch {
		case err == nil:
		case allowUnsigned && pkg.Signer != "":
			// A valid signature from a key not trusted here: installed as
			// if unsigned, which --allow-unsigned accepts.
			pkg.Signer, sig = "", ""
		default:
			return nil, err
		}
	}
	if err := h.Check(ctx, pkg); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp(s.Dir, ".install-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	files := map[string][]byte{"plugin.toml": pkg.ManifestSrc, "plugin.wasm": pkg.Wasm}
	if sig != "" {
		files["plugin.sig"] = []byte(sig)
	}
	for fn, b := range files {
		if err := os.WriteFile(filepath.Join(tmp, fn), b, 0o600); err != nil {
			return nil, err
		}
	}
	dst := filepath.Join(s.Dir, name)
	old := dst + ".old"
	os.RemoveAll(old)
	if _, err := os.Stat(dst); err == nil {
		if err := os.Rename(dst, old); err != nil {
			return nil, err
		}
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Rename(old, dst)
		return nil, err
	}
	os.RemoveAll(old)
	pkg.Source = dst
	return pkg, nil
}

// Remove deletes an installed plugin.
func (s *Store) Remove(name string) error {
	if s.builtin(name) != nil {
		return fmt.Errorf("%q is built in and cannot be removed", name)
	}
	if !nameRe.MatchString(name) {
		return fmt.Errorf("no plugin %q", name)
	}
	dir := filepath.Join(s.Dir, name)
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("no installed plugin %q", name)
	}
	return os.RemoveAll(dir)
}
