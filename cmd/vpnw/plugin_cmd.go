// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/VPNWorks/vpnw/internal/pluginhost"
	"github.com/VPNWorks/vpnw/internal/process"
)

const pluginUsage = `Usage:
  vpnw plugin list                          built-in and installed plugins
  vpnw plugin info NAME                     what a plugin is and may do
  vpnw plugin add DIR [--allow-unsigned]    install from a folder with plugin.toml,
                                            plugin.wasm and plugin.sig
  vpnw plugin remove NAME                   uninstall
  vpnw plugin keygen -o NAME                make a signing key: NAME.key, NAME.pub
  vpnw plugin sign --key FILE DIR           sign the plugin in DIR (writes plugin.sig)
  vpnw plugin trust KEY                     trust plugins signed by KEY
  vpnw plugin keys                          list trusted keys

Plugins are WebAssembly modules. They run in a sandbox inside vpnw with no
files, network or environment, and reach vpnw only through the calls their
manifest asks for. Types: observer (watches a run's events), advisor (turns
traces into advice, with vpnw advise) and guard (can refuse connections the
policy allowed, and refuses everything if it fails).
`

func pluginCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, pluginUsage)
		return process.ExitConfig
	}
	rest := args[1:]
	switch args[0] {
	case "list", "ls":
		return pluginList(stdout, stderr)
	case "info":
		if len(rest) != 1 {
			return fail(stderr, process.ExitConfig, "usage: vpnw plugin info NAME")
		}
		return pluginInfo(rest[0], stdout, stderr)
	case "add", "install":
		return pluginAdd(rest, stdout, stderr)
	case "remove", "rm", "uninstall":
		if len(rest) != 1 {
			return fail(stderr, process.ExitConfig, "usage: vpnw plugin remove NAME")
		}
		st, err := openStore()
		if err != nil {
			return fail(stderr, process.ExitConfig, "%v", err)
		}
		if err := st.Remove(rest[0]); err != nil {
			return fail(stderr, process.ExitConfig, "%v", err)
		}
		fmt.Fprintf(stdout, "removed %s\n", rest[0])
		return 0
	case "keygen":
		return pluginKeygen(rest, stdout, stderr)
	case "sign":
		return pluginSign(rest, stdout, stderr)
	case "trust":
		if len(rest) != 1 {
			return fail(stderr, process.ExitConfig, "usage: vpnw plugin trust vpnw-ed25519:KEY (or a .pub file)")
		}
		key := rest[0]
		if b, err := os.ReadFile(key); err == nil {
			key = strings.TrimSpace(string(b))
		}
		st, err := openStore()
		if err != nil {
			return fail(stderr, process.ExitConfig, "%v", err)
		}
		if err := st.Trust(key); err != nil {
			return fail(stderr, process.ExitConfig, "%v", err)
		}
		fmt.Fprintf(stdout, "trusted %s\n", key)
		return 0
	case "keys":
		st, err := openStore()
		if err != nil {
			return fail(stderr, process.ExitConfig, "%v", err)
		}
		keys, err := st.Trusted()
		if err != nil {
			return fail(stderr, process.ExitConfig, "%v", err)
		}
		for _, k := range keys {
			fmt.Fprintln(stdout, k)
		}
		if len(keys) == 0 {
			fmt.Fprintln(stderr, "no trusted keys; add one with vpnw plugin trust KEY")
		}
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, pluginUsage)
		return 0
	}
	return fail(stderr, process.ExitConfig, "unknown plugin command %q; see vpnw plugin help", args[0])
}

// parseAnywhere parses flags before and after the other arguments, so
// "plugin add DIR --allow-unsigned" works as well as the other order.
func parseAnywhere(fs *flag.FlagSet, args []string) ([]string, error) {
	var rest []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return rest, nil
		}
		rest = append(rest, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func where(p *pluginhost.Package) string {
	if p.Builtin {
		return "built-in"
	}
	if p.Signer != "" {
		return "signed"
	}
	return "unsigned"
}

func pluginList(stdout, stderr io.Writer) int {
	st, err := openStore()
	if err != nil {
		return fail(stderr, process.ExitConfig, "%v", err)
	}
	pkgs, errs := st.List()
	fmt.Fprintf(stdout, "%-16s %-9s %-9s %-9s %s\n", "NAME", "VERSION", "TYPE", "SOURCE", "DESCRIPTION")
	for _, p := range pkgs {
		m := p.Manifest
		fmt.Fprintf(stdout, "%-16s %-9s %-9s %-9s %s\n", m.Name, m.Version, m.Type, where(p), m.Description)
	}
	for _, e := range errs {
		fmt.Fprintf(stderr, "vpnw: %v\n", e)
	}
	if len(errs) > 0 {
		return process.ExitConfig
	}
	return 0
}

func pluginInfo(name string, stdout, stderr io.Writer) int {
	st, err := openStore()
	if err != nil {
		return fail(stderr, process.ExitConfig, "%v", err)
	}
	p, err := st.Find(name)
	if err != nil {
		return fail(stderr, process.ExitConfig, "%v", err)
	}
	m := p.Manifest
	fmt.Fprintf(stdout, "name         %s\nversion      %s\ntype         %s\nabi          %d\n", m.Name, m.Version, m.Type, m.ABI)
	if m.Description != "" {
		fmt.Fprintf(stdout, "description  %s\n", m.Description)
	}
	fmt.Fprintf(stdout, "source       %s\n", p.Source)
	switch {
	case p.Builtin:
		fmt.Fprintln(stdout, "trust        built into vpnw")
	case p.Signer != "":
		fmt.Fprintf(stdout, "trust        signed by %s\n", p.Signer)
	default:
		fmt.Fprintln(stdout, "trust        unsigned (installed with --allow-unsigned)")
	}
	fmt.Fprintf(stdout, "size         %.1f MB\n", float64(len(p.Wasm))/1e6)
	if len(m.Permissions) == 0 {
		fmt.Fprintln(stdout, "permissions  none beyond logging")
	}
	for i, perm := range m.Permissions {
		label := "permissions"
		if i > 0 {
			label = ""
		}
		fmt.Fprintf(stdout, "%-12s %s: %s\n", label, perm, pluginhost.PermissionText(perm))
	}
	return 0
}

func pluginAdd(args []string, stdout, stderr io.Writer) int {
	var allow bool
	fs := flag.NewFlagSet("vpnw plugin add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&allow, "allow-unsigned", false, "")
	rest, err := parseAnywhere(fs, args)
	if err != nil || len(rest) != 1 {
		return fail(stderr, process.ExitConfig, "usage: vpnw plugin add DIR [--allow-unsigned]")
	}
	dir := rest[0]
	st, err := openStore()
	if err != nil {
		return fail(stderr, process.ExitConfig, "%v", err)
	}
	h, err := openHost()
	if err != nil {
		return fail(stderr, process.ExitInternal, "cannot start the plugin host: %v", err)
	}
	defer h.Close(context.Background())
	p, err := st.Install(context.Background(), h, dir, allow)
	if err != nil {
		return fail(stderr, process.ExitConfig, "%v", err)
	}
	m := p.Manifest
	fmt.Fprintf(stdout, "installed %s %s (%s, %s)\n", m.Name, m.Version, m.Type, where(p))
	for _, perm := range m.Permissions {
		fmt.Fprintf(stdout, "  may %s\n", pluginhost.PermissionText(perm))
	}
	return 0
}

func pluginKeygen(args []string, stdout, stderr io.Writer) int {
	var out string
	fs := flag.NewFlagSet("vpnw plugin keygen", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&out, "o", "", "")
	if err := fs.Parse(args); err != nil || out == "" {
		return fail(stderr, process.ExitConfig, "usage: vpnw plugin keygen -o NAME (writes NAME.key and NAME.pub)")
	}
	pub, priv, err := pluginhost.GenerateKey()
	if err != nil {
		return fail(stderr, process.ExitInternal, "%v", err)
	}
	if _, err := os.Stat(out + ".key"); err == nil {
		return fail(stderr, process.ExitConfig, "%s.key exists; not overwriting a key", out)
	}
	if err := os.WriteFile(out+".key", []byte(priv+"\n"), 0o600); err != nil {
		return fail(stderr, process.ExitConfig, "%v", err)
	}
	if err := os.WriteFile(out+".pub", []byte(pub+"\n"), 0o644); err != nil {
		return fail(stderr, process.ExitConfig, "%v", err)
	}
	fmt.Fprintf(stdout, "%s\n", pub)
	fmt.Fprintf(stderr, "vpnw: wrote %s.key (keep it private) and %s.pub\n", out, out)
	return 0
}

func pluginSign(args []string, stdout, stderr io.Writer) int {
	var key string
	fs := flag.NewFlagSet("vpnw plugin sign", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&key, "key", "", "")
	rest, err := parseAnywhere(fs, args)
	if err != nil || key == "" || len(rest) != 1 {
		return fail(stderr, process.ExitConfig, "usage: vpnw plugin sign --key FILE.key DIR")
	}
	dir := rest[0]
	priv, err := os.ReadFile(key)
	if err != nil {
		return fail(stderr, process.ExitConfig, "%v", err)
	}
	pkg, _, err := pluginhost.ReadDir(dir)
	if err != nil {
		return fail(stderr, process.ExitConfig, "%v", err)
	}
	sig, err := pluginhost.Sign(string(priv), pkg.ManifestSrc, pkg.Wasm)
	if err != nil {
		return fail(stderr, process.ExitConfig, "%s: %v", key, err)
	}
	fn := filepath.Join(dir, "plugin.sig")
	if err := os.WriteFile(fn, []byte(sig), 0o644); err != nil {
		return fail(stderr, process.ExitConfig, "%v", err)
	}
	fmt.Fprintf(stdout, "signed %s %s: wrote %s\n", pkg.Manifest.Name, pkg.Manifest.Version, fn)
	return 0
}

// doctorPlugins checks that the plugin host starts and the built-in plugins
// load.
func doctorPlugins(stdout io.Writer) {
	st, err := openStore()
	if err != nil {
		fmt.Fprintf(stdout, "  plugins          NOT AVAILABLE: %v\n", err)
		return
	}
	h, err := openHost()
	if err != nil {
		fmt.Fprintf(stdout, "  plugins          NOT AVAILABLE: the plugin host did not start: %v\n", err)
		return
	}
	defer h.Close(context.Background())
	for _, p := range st.Builtins {
		in, err := h.Load(context.Background(), p, pluginhost.Options{Command: "doctor"})
		if err != nil {
			fmt.Fprintf(stdout, "  plugins          NOT AVAILABLE: %v\n", err)
			return
		}
		in.Close()
	}
	pkgs, errs := st.List()
	fmt.Fprintf(stdout, "  plugins          ok: host up, %d built in, %d installed in %s\n", len(st.Builtins), len(pkgs)-len(st.Builtins), st.Dir)
	for _, e := range errs {
		fmt.Fprintf(stdout, "                   %v\n", e)
	}
}
