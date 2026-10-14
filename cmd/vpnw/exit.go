// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/VPNWorks/vpnw/internal/broker"
	"github.com/VPNWorks/vpnw/internal/events"
	"github.com/VPNWorks/vpnw/internal/exit"
	"github.com/VPNWorks/vpnw/internal/path"
	"github.com/VPNWorks/vpnw/internal/process"
	"github.com/VPNWorks/vpnw/internal/version"
)

const exitUsage = `vpnw exit: the server end of a path, with fixed addresses and each
client's policy checked again.

Usage:
  vpnw exit serve --config FILE [options]   take clients' requests over TLS
  vpnw exit check --config FILE             check an exit's file and say what
                                            each client may do
  vpnw exit token [--out FILE]              make a token for a new client
  vpnw exit token --from FILE               the token_sha256 of a token in FILE
  vpnw exit cert --host HOST... [--name NAME] [--dir DIR]
                                            make the exit's certificate, signed
                                            by a private CA

serve takes HTTP CONNECT and SOCKS5 requests inside TLS. A client is known by
its token, and each request is decided with that client's own policy before
anything is dialed, by the same code that decides a run's requests. Allowed
requests leave from the client's fixed address. The record names the client,
and its run and connection IDs, so it lines up with the client's own record.

serve runs until it gets SIGINT, SIGTERM or SIGHUP; it reads its file only
when it starts.

Options for serve:
  --out FILE          also write the record to FILE as JSON lines, added to
                      what is there, so a restart keeps the earlier record
  --json              print the record as JSON lines instead of text
  -v, --verbose       print every step, not only refusals and errors
  -q, --quiet         print nothing but errors
  --plugin NAME       run an observer or guard plugin at the exit (repeatable);
                      a guard plugin can refuse what a client's policy allowed
  --set NAME.KEY=VALUE  a setting for plugin NAME (repeatable)
  --plugin-file NAME=PATH  the file vpnw opens for plugin NAME, if it asks
                      for one (file.write); it must not exist yet
  --plugin-folder NAME=PATH  the folder plugin NAME reads, if it asks for one
                      (folder.read); the default is ~/.config/vpnw/NAME

Options for cert:
  --host HOST         an address or name clients reach the exit by (repeatable)
  --name NAME         the files' name: NAME.crt and NAME.key (default exit)
  --dir DIR           where the files go (default the current folder). A CA
                      already there (ca.pem and ca.key) signs the new
                      certificate; otherwise a new one is made

Exit codes: 0, or 121 usage or configuration, 122 not possible on this
machine (the listening address, or a source address it doesn't have), 124
any other failure.
`

func exitCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, exitUsage)
		return process.ExitConfig
	}
	switch args[0] {
	case "serve":
		return exitServe(args[1:], stderr)
	case "check":
		return exitCheck(args[1:], stdout, stderr)
	case "token":
		return exitToken(args[1:], stdout, stderr)
	case "cert":
		return exitCert(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, exitUsage)
		return 0
	}
	return fail(stderr, process.ExitConfig, "unknown exit command %q; see vpnw exit help", args[0])
}

func exitFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("vpnw exit "+name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parseExitFlags parses and refuses anything left over.
func parseExitFlags(fs *flag.FlagSet, args []string, stderr io.Writer) bool {
	if err := fs.Parse(args); err != nil {
		fail(stderr, process.ExitConfig, "%v; see vpnw exit help", err)
		return false
	}
	if fs.NArg() > 0 {
		fail(stderr, process.ExitConfig, "%s takes no arguments besides its options (got %q); see vpnw exit help", fs.Name(), fs.Arg(0))
		return false
	}
	return true
}

func loadExit(file string, stderr io.Writer) (*exit.Config, int) {
	if file == "" {
		return nil, fail(stderr, process.ExitConfig, "give the exit's file with --config FILE")
	}
	cfg, err := exit.LoadConfig(file)
	if err != nil {
		return nil, fail(stderr, process.ExitConfig, "%v", err)
	}
	return cfg, 0
}

// loadKeyPair reads the exit's certificate and key, and says until when the
// certificate is valid and for what.
func loadKeyPair(cfg *exit.Config) (tls.Certificate, *x509.Certificate, error) {
	kp, err := tls.LoadX509KeyPair(cfg.CertFile(), cfg.KeyFile())
	if err != nil {
		return kp, nil, fmt.Errorf("cannot use the certificate %s with the key %s: %v", cfg.CertFile(), cfg.KeyFile(), err)
	}
	leaf, err := x509.ParseCertificate(kp.Certificate[0])
	if err != nil {
		return kp, nil, fmt.Errorf("%s: %v", cfg.CertFile(), err)
	}
	if time.Now().After(leaf.NotAfter) {
		return kp, nil, fmt.Errorf("the certificate %s expired on %s", cfg.CertFile(), leaf.NotAfter.UTC().Format("2006-01-02"))
	}
	return kp, leaf, nil
}

func certFor(leaf *x509.Certificate) string {
	var names []string
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}
	names = append(names, leaf.DNSNames...)
	if len(names) == 0 {
		names = []string{leaf.Subject.CommonName}
	}
	return strings.Join(names, ", ")
}

func newExitRunID() string {
	var b [3]byte
	rand.Read(b[:])
	return "x-" + hex.EncodeToString(b[:])
}

func exitServe(args []string, stderr io.Writer) int {
	var file, out string
	var jsonOut, verbose, quiet bool
	var plugins, sets, pluginFiles, pluginFolders multi
	fs := exitFlags("serve")
	fs.StringVar(&file, "config", "", "")
	fs.StringVar(&out, "out", "", "")
	fs.BoolVar(&jsonOut, "json", false, "")
	fs.BoolVar(&verbose, "verbose", false, "")
	fs.BoolVar(&verbose, "v", false, "")
	fs.BoolVar(&quiet, "quiet", false, "")
	fs.BoolVar(&quiet, "q", false, "")
	fs.Var(&plugins, "plugin", "")
	fs.Var(&sets, "set", "")
	fs.Var(&pluginFiles, "plugin-file", "")
	fs.Var(&pluginFolders, "plugin-folder", "")
	if !parseExitFlags(fs, args, stderr) {
		return process.ExitConfig
	}
	cfg, code := loadExit(file, stderr)
	if cfg == nil {
		return code
	}
	settings, err := parseSets(sets, true)
	if err != nil {
		return fail(stderr, process.ExitConfig, "%v", err)
	}
	if !quiet {
		for _, w := range cfg.Warnings {
			fmt.Fprintf(stderr, "vpnw: warning: %s\n", w)
		}
	}
	kp, leaf, err := loadKeyPair(cfg)
	if err != nil {
		return fail(stderr, process.ExitConfig, "%v", err)
	}
	if err := cfg.CheckSources(); err != nil {
		return fail(stderr, process.ExitNoEnforcement, "%v; each client's connections leave from its own address, so the exit needs them all", err)
	}
	l, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fail(stderr, process.ExitNoEnforcement, "cannot listen on %s: %v", cfg.Listen, err)
	}
	tl := tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{kp}, MinVersion: tls.VersionTLS12})

	bus := events.NewBus(newExitRunID(), nil)
	pfiles, err := parsePluginFiles(pluginFiles)
	if err != nil {
		l.Close()
		return fail(stderr, process.ExitConfig, "%v", err)
	}
	pfolders, err := parsePluginFolders(pluginFolders)
	if err != nil {
		l.Close()
		return fail(stderr, process.ExitConfig, "%v", err)
	}
	pr := &pluginRun{mode: "exit", bus: bus, stderr: stderr, settings: settings, verbose: verbose, files: pfiles, folders: pfolders}
	defer pr.close()
	if !quiet {
		if jsonOut {
			bus.Add(events.NewJSONL(stderr))
		} else {
			set := map[string]string{"level": "decisions"}
			if verbose {
				set["level"] = "all"
			}
			for k, v := range settings["trace"] {
				set[k] = v
			}
			if err := pr.console(set); err != nil {
				fmt.Fprintf(stderr, "vpnw: %v; printing the record as JSON instead\n", err)
				bus.Add(events.NewJSONL(stderr))
			}
		}
	}
	for _, name := range plugins {
		if err := pr.attach(name); err != nil {
			l.Close()
			return fail(stderr, process.ExitConfig, "%v", err)
		}
	}
	if err := pr.unused(); err != nil {
		l.Close()
		return fail(stderr, process.ExitConfig, "%v", err)
	}
	var outFile *events.JSONL
	if out != "" {
		f, err := os.OpenFile(out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			l.Close()
			return fail(stderr, process.ExitConfig, "cannot write %s: %v", out, err)
		}
		outFile = events.NewJSONL(f)
		bus.Add(outFile)
		defer outFile.Close()
	}

	br := &broker.Broker{
		Exit:     &broker.Exit{Name: cfg.Name, Clients: cfg.BrokerClients()},
		Resolver: path.SystemResolver{},
		Bus:      bus,
		Guards:   pr.brokerGuards(),
	}
	// The broker waits out errors taking connections (a flood can run the
	// machine out of file descriptors); say so now and then.
	var lastSaid time.Time
	var saidMu sync.Mutex
	br.OnAcceptError = func(err error) {
		saidMu.Lock()
		defer saidMu.Unlock()
		if time.Since(lastSaid) >= time.Minute {
			lastSaid = time.Now()
			fmt.Fprintf(stderr, "vpnw: cannot take new connections: %v; trying again\n", err)
		}
	}
	start := map[string]any{
		"mode": "exit", "exit": cfg.Name, "listen": l.Addr().String(), "clients": len(cfg.Clients),
		"version": version.Version, "cert_for": certFor(leaf), "cert_until": leaf.NotAfter.UTC().Format("2006-01-02"),
	}
	if names := pr.names(); len(names) > 0 {
		start["plugins"] = names
	}
	bus.Emit(events.RunStart, 0, "", 0, start)

	// Serve returns only when the listener is closed, below.
	go br.Serve(tl)
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	why := "stopped by " + (<-sigs).String()
	signal.Stop(sigs)
	l.Close()
	br.Shutdown(5 * time.Second)
	st := br.Stats()
	bus.Emit(events.RunEnd, 0, "", 0, map[string]any{
		"connections": st.Connections, "opened": st.Opened, "allowed": st.Allowed, "denied": st.Denied, "failed": st.Failed,
		"bytes_up": st.BytesUp, "bytes_down": st.BytesDown, "auth_denied": st.AuthDenied, "health_checks": st.HealthChecks,
		"tls_failed": st.TLSFailed, "over_limit": st.OverLimit, "accept_errors": st.AcceptErrors, "why": why,
	})
	pr.close()
	return 0
}

func exitCheck(args []string, stdout, stderr io.Writer) int {
	var file string
	fs := exitFlags("check")
	fs.StringVar(&file, "config", "", "")
	if !parseExitFlags(fs, args, stderr) {
		return process.ExitConfig
	}
	cfg, code := loadExit(file, stderr)
	if cfg == nil {
		return code
	}
	_, leaf, err := loadKeyPair(cfg)
	if err != nil {
		return fail(stderr, process.ExitConfig, "%v", err)
	}
	fmt.Fprintf(stdout, "exit %s listens on %s\n", cfg.Name, cfg.Listen)
	fmt.Fprintf(stdout, "certificate %s: for %s, valid until %s\n", filepath.Base(cfg.CertFile()), certFor(leaf), leaf.NotAfter.UTC().Format("2006-01-02"))
	noun := "clients"
	if len(cfg.Clients) == 1 {
		noun = "client"
	}
	fmt.Fprintf(stdout, "%d %s:\n", len(cfg.Clients), noun)
	for _, cl := range cfg.Clients {
		fmt.Fprintf(stdout, "  %s\n", cl.Describe())
	}
	if err := cfg.CheckSources(); err != nil {
		fmt.Fprintf(stdout, "note: %v; serve needs them\n", err)
	}
	for _, w := range cfg.Warnings {
		fmt.Fprintf(stdout, "warning: %s\n", w)
	}
	return 0
}

func exitToken(args []string, stdout, stderr io.Writer) int {
	var out, from string
	fs := exitFlags("token")
	fs.StringVar(&out, "out", "", "")
	fs.StringVar(&from, "from", "", "")
	if !parseExitFlags(fs, args, stderr) {
		return process.ExitConfig
	}
	if out != "" && from != "" {
		return fail(stderr, process.ExitConfig, "give --out to make a token, or --from to hash one, not both")
	}
	if from != "" {
		tok, err := path.ReadToken(from)
		if err != nil {
			return fail(stderr, process.ExitConfig, "%v", err)
		}
		if len(tok) < 32 {
			fmt.Fprintf(stderr, "vpnw: warning: the token in %s has %d characters; one that short can be guessed. vpnw exit token makes 43-character ones\n", from, len(tok))
		}
		fmt.Fprintf(stdout, "token_sha256 = %q\n", exit.HashHex(tok))
		return 0
	}
	tok, err := exit.NewToken()
	if err != nil {
		return fail(stderr, process.ExitInternal, "cannot make a token: %v", err)
	}
	if out != "" {
		f, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				return fail(stderr, process.ExitConfig, "%s already exists; a token file is never overwritten", out)
			}
			return fail(stderr, process.ExitConfig, "cannot write %s: %v", out, err)
		}
		_, werr := fmt.Fprintln(f, tok)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return fail(stderr, process.ExitInternal, "cannot write %s: %v", out, werr)
		}
		fmt.Fprintf(stdout, "wrote a new token to %s, for the client: vpnw --token-file %s\n", out, out)
	} else {
		fmt.Fprintf(stdout, "token: %s\n", tok)
	}
	fmt.Fprintf(stdout, "for the client's table in the exit's file:\ntoken_sha256 = %q\n", exit.HashHex(tok))
	return 0
}

// writeNew writes a file that must not exist yet.
func writeNew(name string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists; it is never overwritten", name)
		}
		return err
	}
	_, werr := f.Write(b)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

func exitCert(args []string, stdout, stderr io.Writer) int {
	var hosts multi
	var name, dir string
	fs := exitFlags("cert")
	fs.Var(&hosts, "host", "")
	fs.StringVar(&name, "name", "exit", "")
	fs.StringVar(&dir, "dir", ".", "")
	if !parseExitFlags(fs, args, stderr) {
		return process.ExitConfig
	}
	if len(hosts) == 0 {
		return fail(stderr, process.ExitConfig, "give the addresses or names clients reach the exit by, with --host (repeatable)")
	}
	if name == "" || strings.ContainsAny(name, `/\`) || name == "ca" {
		return fail(stderr, process.ExitConfig, "--name %q: give a plain file name other than ca", name)
	}
	caCert, caKey := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	crt, key := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	for _, f := range []string{crt, key} {
		if _, err := os.Stat(f); err == nil {
			return fail(stderr, process.ExitConfig, "%s already exists; it is never overwritten", f)
		}
	}
	now := time.Now()
	_, errC := os.Stat(caCert)
	_, errK := os.Stat(caKey)
	var ca *exit.CA
	made := false
	switch {
	case errC == nil && errK == nil:
		var err error
		if ca, err = exit.LoadCA(caCert, caKey); err != nil {
			return fail(stderr, process.ExitConfig, "%v", err)
		}
	case errC == nil || errK == nil:
		return fail(stderr, process.ExitConfig, "%s and %s go together; one of them is missing", caCert, caKey)
	default:
		c, cp, kp, err := exit.NewCA(now)
		if err != nil {
			return fail(stderr, process.ExitInternal, "cannot make a CA: %v", err)
		}
		if err := writeNew(caKey, kp, 0o600); err != nil {
			return fail(stderr, process.ExitConfig, "%v", err)
		}
		if err := writeNew(caCert, cp, 0o644); err != nil {
			return fail(stderr, process.ExitConfig, "%v", err)
		}
		ca, made = c, true
	}
	cp, kp, err := ca.Issue(hosts, now)
	if err != nil {
		return fail(stderr, process.ExitConfig, "%v", err)
	}
	if err := writeNew(key, kp, 0o600); err != nil {
		return fail(stderr, process.ExitConfig, "%v", err)
	}
	if err := writeNew(crt, cp, 0o644); err != nil {
		return fail(stderr, process.ExitConfig, "%v", err)
	}
	if made {
		fmt.Fprintf(stdout, "made a private CA: %s, for the clients (vpnw --ca %s), and %s, which stays here and signs more exits\n", caCert, filepath.Base(caCert), caKey)
	} else {
		fmt.Fprintf(stdout, "signed with the CA in %s\n", caCert)
	}
	fmt.Fprintf(stdout, "made %s and %s for %s, valid until %s; in the exit's file:\ncert = %q\nkey  = %q\n",
		crt, key, strings.Join(hosts, ", "), now.Add(exit.CertValid).UTC().Format("2006-01-02"), filepath.Base(crt), filepath.Base(key))
	return 0
}
