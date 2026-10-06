// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Command vpnw-ledger keeps a record of every connection that can't be
// changed without it showing, and checks it offline.
//
//	vpnw-ledger keygen       make the key pair that signs and checks
//	vpnw-ledger seal         seal a JSON Lines file, or follow one as it grows
//	vpnw-ledger verify       check the records against the ledger and the public key
//	vpnw-ledger prove        write a proof that one record is in the log
//	vpnw-ledger check-proof  check such a proof with the public key alone
package main

import (
	"bufio"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"vpnw.com/vpnw/internal/config"
	"vpnw.com/vpnw/internal/ledger"
)

const usage = `vpnw-ledger %s: a record of every connection, which can't be changed without it showing.

Usage:
  vpnw-ledger keygen -o NAME
  vpnw-ledger seal   --key FILE [--every N] [--follow [--interval D]] [--log NAME] [--ledger FILE] RECORDS
  vpnw-ledger verify --pub FILE [--witness FILE] [--ledger FILE] RECORDS
  vpnw-ledger prove  --line N [--ledger FILE] [-o FILE] RECORDS
  vpnw-ledger check-proof --pub FILE PROOF [RECORD]
  vpnw-ledger version

keygen       writes NAME.key, the private key that signs (mode 0600; keep it
             secret), and NAME.pub, the public key for whoever checks.
seal         writes RECORDS.ledger next to RECORDS, a JSON Lines file such as
             vpnw's trace or vpnw-scope's flows, which it leaves untouched: a
             line per record with its hash, and a signed checkpoint every N
             records and at the end. It prints each checkpoint it signs, to
             keep elsewhere as a witness. Run again, it checks what was sealed,
             then seals what was added. With --follow it seals lines as they
             are written, like tail -f, until stopped (Ctrl-C or SIGTERM), and
             then signs a last checkpoint.
verify       recomputes every hash from RECORDS and checks every checkpoint
             with the public key. It names the first line that was changed,
             deleted, inserted or moved, an end cut off, and lines never sealed.
prove        writes a proof that the record on line N is in the log: the
             record, its hash, the hashes that link it to the root of the last
             checkpoint, and that checkpoint, signed.
check-proof  checks a proof with the public key alone. Given a RECORD file
             (one line), it checks that record instead of the proof's own.

Options:
  --key FILE       seal: the private key, from keygen
  --pub FILE       verify, check-proof: the public key, from keygen
  --ledger FILE    the ledger (default: RECORDS.ledger)
  --every N        seal: sign a checkpoint every N records (default 1000)
  --follow         seal: keep sealing RECORDS as it grows
  --interval D     seal --follow: sign a checkpoint when a record has waited
                   this long, such as 10s or 2m (default 10s)
  --log NAME       seal: the log's name in its checkpoints, set when the ledger
                   is made (default: the file name of RECORDS)
  --witness FILE   verify: checkpoints kept elsewhere, such as seal's output in
                   a system log; the ledger must hold each one, which catches a
                   ledger cut back to an earlier checkpoint
  --line N         prove: the record's line in RECORDS
  -o NAME          keygen: the key files' name; prove: write the proof to NAME
                   instead of standard output

Exit codes: 0 intact; 120 the check found something: a line changed,
deleted, inserted, moved or never sealed, an end cut off, a checkpoint that
doesn't hold, or a proof that doesn't; 121 usage or input error; 124 any
other failure.
`

const (
	exitFound   = 120
	exitInput   = 121
	exitFailure = 124
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, usage, ledger.Version)
		return exitInput
	}
	switch args[0] {
	case "keygen":
		return keygenCmd(args[1:], stdout, stderr)
	case "seal":
		return sealCmd(args[1:], stdout, stderr)
	case "verify":
		return verifyCmd(args[1:], stdout, stderr)
	case "prove":
		return proveCmd(args[1:], stdout, stderr)
	case "check-proof":
		return checkProofCmd(args[1:], stdout, stderr)
	case "version", "--version", "-V":
		fmt.Fprintf(stdout, "vpnw-ledger %s (%s/%s, %s)\n", ledger.Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return 0
	case "help", "-h", "--help":
		fmt.Fprintf(stdout, usage, ledger.Version)
		return 0
	}
	fmt.Fprintf(stderr, "vpnw-ledger: unknown command %q; see vpnw-ledger help\n", args[0])
	return exitInput
}

func fail(stderr io.Writer, code int, format string, a ...any) int {
	fmt.Fprintf(stderr, "vpnw-ledger: "+format+"\n", a...)
	return code
}

// failErr reports err with the exit code its kind calls for: a problem the
// check found, an input error, or any other failure.
func failErr(stderr io.Writer, err error) int {
	var p *ledger.Problem
	var ce *config.Error
	switch {
	case errors.As(err, &p):
		return fail(stderr, exitFound, "%v", err)
	case errors.As(err, &ce), errors.Is(err, fs.ErrNotExist):
		return fail(stderr, exitInput, "%v", err)
	}
	return fail(stderr, exitFailure, "%v", err)
}

type opts struct {
	key, pub, ledger, log, witness, out string
	every, line                         int
	follow                              bool
	interval                            time.Duration
}

// parse reads the options of one command and its file arguments, from min
// to max of them, in any order with the options; first names the first
// file, for the message when it is missing.
func parse(name string, args []string, min, max int, first string) (*opts, []string, error) {
	var o opts
	fs := flag.NewFlagSet("vpnw-ledger "+name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.key, "key", "", "")
	fs.StringVar(&o.pub, "pub", "", "")
	fs.StringVar(&o.ledger, "ledger", "", "")
	fs.StringVar(&o.log, "log", "", "")
	fs.StringVar(&o.witness, "witness", "", "")
	fs.StringVar(&o.out, "o", "", "")
	fs.IntVar(&o.every, "every", 1000, "")
	fs.IntVar(&o.line, "line", 0, "")
	fs.BoolVar(&o.follow, "follow", false, "")
	fs.DurationVar(&o.interval, "interval", 10*time.Second, "")
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, nil, err
		}
		if fs.NArg() == 0 {
			break
		}
		pos, args = append(pos, fs.Arg(0)), fs.Args()[1:]
	}
	switch {
	case len(pos) < min:
		return nil, nil, errors.New("give the " + first)
	case len(pos) > max:
		return nil, nil, fmt.Errorf("unexpected argument %q", pos[max])
	}
	return &o, pos, nil
}

// readSmall reads a key, proof or record file, which is never large.
func readSmall(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err == nil && len(b) > 1<<20 {
		err = &config.Error{File: path, Msg: "larger than 1 MB: not a key, a proof or a record"}
	}
	return b, err
}

func readPublic(path string) (*ledger.PublicKey, error) {
	if path == "" {
		return nil, &config.Error{Msg: "--pub FILE is required: the public key, from keygen"}
	}
	src, err := readSmall(path)
	if err != nil {
		return nil, err
	}
	return ledger.ParsePublicKey(string(src), path)
}

func readPrivate(path string) (*ledger.PrivateKey, error) {
	if path == "" {
		return nil, &config.Error{Msg: "--key FILE is required: the private key, from keygen"}
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, &config.Error{File: path, Msg: fmt.Sprintf("its permissions %#o let others read the private key; run chmod 600 %s", fi.Mode().Perm(), path)}
	}
	src, err := readSmall(path)
	if err != nil {
		return nil, err
	}
	return ledger.ParsePrivateKey(string(src), path)
}

func keygenCmd(args []string, stdout, stderr io.Writer) int {
	o, _, err := parse("keygen", args, 0, 0, "")
	if err != nil {
		return fail(stderr, exitInput, "keygen: %v", err)
	}
	if o.out == "" {
		return fail(stderr, exitInput, "keygen: -o NAME is required")
	}
	privPath, pubPath := o.out+".key", o.out+".pub"
	for _, p := range []string{privPath, pubPath} {
		if _, err := os.Lstat(p); err == nil {
			return fail(stderr, exitInput, "keygen: %s exists; vpnw-ledger never writes over a key", p)
		}
	}
	k, err := ledger.NewKey(rand.Reader)
	if err != nil {
		return fail(stderr, exitFailure, "keygen: %v", err)
	}
	for _, f := range []struct {
		path string
		text string
		mode os.FileMode
	}{{privPath, k.Text(), 0o600}, {pubPath, k.Public().Text(), 0o644}} {
		file, err := os.OpenFile(f.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, f.mode)
		if err != nil {
			return failErr(stderr, err)
		}
		_, err = file.WriteString(f.text)
		if cerr := file.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return fail(stderr, exitFailure, "keygen: %v", err)
		}
	}
	fmt.Fprintf(stdout, "Key %s.\n  %s  the private key, which signs: keep it secret, on the machine that seals.\n  %s  the public key, which checks: give it to whoever checks the ledger.\n",
		k.ID, privPath, pubPath)
	return 0
}

// interrupt is what stops seal --follow. Tests replace it.
var interrupt = defaultInterrupt

// defaultInterrupt returns a channel that closes on Ctrl-C or SIGTERM.
func defaultInterrupt() <-chan struct{} {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	stop := make(chan struct{})
	go func() {
		<-sig
		signal.Stop(sig)
		close(stop)
	}()
	return stop
}

func sealCmd(args []string, stdout, stderr io.Writer) int {
	o, pos, err := parse("seal", args, 1, 1, "records file")
	if err != nil {
		return fail(stderr, exitInput, "seal: %v", err)
	}
	if o.every < 1 {
		return fail(stderr, exitInput, "seal: --every must be 1 or more")
	}
	if o.interval <= 0 {
		return fail(stderr, exitInput, "seal: --interval must be more than 0")
	}
	records := pos[0]
	key, err := readPrivate(o.key)
	if err != nil {
		return failErr(stderr, err)
	}
	ledgerPath := o.ledger
	if ledgerPath == "" {
		ledgerPath = records + ".ledger"
	}
	rf, err := os.Open(records)
	if err != nil {
		return failErr(stderr, err)
	}
	defer rf.Close()
	lf, err := os.OpenFile(ledgerPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return failErr(stderr, err)
	}
	defer lf.Close()
	if err := lock(lf); err != nil {
		return fail(stderr, exitFailure, "seal: %v", err)
	}
	opt := ledger.Options{Every: o.every, Interval: o.interval}
	var s *ledger.Sealer
	line := 0
	if fi, err := lf.Stat(); err != nil {
		return fail(stderr, exitFailure, "seal: %v", err)
	} else if fi.Size() == 0 {
		name := o.log
		if name == "" {
			name = filepath.Base(records)
		}
		if s, err = ledger.NewSealer(lf, key, name, opt); err != nil {
			return fail(stderr, exitInput, "seal: %v; give a name with --log", err)
		}
	} else {
		led, err := ledger.ReadLedger(lf, ledgerPath)
		if err != nil {
			return failErr(stderr, err)
		}
		if o.log != "" && o.log != led.Log {
			return fail(stderr, exitInput, "seal: %s is the ledger of log %q; --log can't change it", ledgerPath, led.Log)
		}
		recs, end, err := ledger.HashRecords(rf, len(led.Leaves))
		if err != nil {
			return failErr(stderr, err)
		}
		rep := ledger.Verify(recs, records, led, key.Public(), ledger.VerifyOptions{Tail: true})
		if p := rep.Problem; p != nil && p.Kind == "key" && rep.Checked == 0 {
			return fail(stderr, exitInput, "seal: %s was sealed with another key: %s", ledgerPath, p.Msg)
		}
		if rep.Problem != nil {
			fmt.Fprintf(stdout, "%v\n", rep.Problem)
			return fail(stderr, exitFound, "seal: %s doesn't verify, so nothing more was sealed", records)
		}
		if s, err = ledger.ResumeSealer(lf, key, led, rep, opt); err != nil {
			return failErr(stderr, err)
		}
		if _, err := rf.Seek(end, io.SeekStart); err != nil {
			return failErr(stderr, err)
		}
		line = len(led.Leaves)
	}
	s.OnCheckpoint = func(c *ledger.Checkpoint) { stdout.Write(append(c.AppendJSON(nil), '\n')) }
	start := time.Now()
	var n int
	if o.follow {
		fmt.Fprintf(stderr, "vpnw-ledger: following %s from line %d into %s; stop with Ctrl-C.\n", records, line+1, ledgerPath)
		n, err = s.Follow(rf, records, line, interrupt())
	} else {
		n, err = s.SealAll(rf, records, line)
	}
	if serr := lf.Sync(); err == nil && serr != nil {
		err = serr
	}
	if err != nil {
		return failErr(stderr, err)
	}
	took := time.Since(start).Round(time.Millisecond)
	if c := s.Last(); c != nil {
		fmt.Fprintf(stderr, "vpnw-ledger: sealed %s new records of %s in %s. %s holds %s records under %d checkpoints signed by %s.\n",
			comma(n), records, took, ledgerPath, comma(s.Sealed()), c.Seq, c.Key)
	} else {
		fmt.Fprintf(stderr, "vpnw-ledger: %s has no records yet; %s has its header.\n", records, ledgerPath)
	}
	return 0
}

func verifyCmd(args []string, stdout, stderr io.Writer) int {
	o, pos, err := parse("verify", args, 1, 1, "records file")
	if err != nil {
		return fail(stderr, exitInput, "verify: %v", err)
	}
	records := pos[0]
	pub, err := readPublic(o.pub)
	if err != nil {
		return failErr(stderr, err)
	}
	ledgerPath := o.ledger
	if ledgerPath == "" {
		ledgerPath = records + ".ledger"
	}
	led, err := readLedgerFile(ledgerPath)
	if err != nil {
		return failErr(stderr, err)
	}
	rf, err := os.Open(records)
	if err != nil {
		return failErr(stderr, err)
	}
	defer rf.Close()
	recs, _, err := ledger.HashRecords(rf, 0)
	if err != nil {
		return failErr(stderr, err)
	}
	var opt ledger.VerifyOptions
	if o.witness != "" {
		wf, err := os.Open(o.witness)
		if err != nil {
			return failErr(stderr, err)
		}
		opt.Witness, err = ledger.ReadWitness(wf, o.witness, pub)
		wf.Close()
		if err != nil {
			return failErr(stderr, err)
		}
	}
	rep := ledger.Verify(recs, records, led, pub, opt)
	if rep.Problem != nil {
		fmt.Fprintf(stdout, "%v\n%s is not intact.\n", rep.Problem, records)
		return exitFound
	}
	if rep.Last == nil {
		fmt.Fprintf(stdout, "%s holds no records yet, and nothing is sealed.\n", records)
		return 0
	}
	fmt.Fprintf(stdout, "%s is intact: %s records, all sealed and signed. %d checkpoints signed by %s; the last was signed %s.\n",
		records, comma(rep.Records), rep.Checked, rep.Last.Key, rep.Last.When())
	switch n := len(opt.Witness); {
	case n == 1:
		fmt.Fprintf(stdout, "The checkpoint in %s is in the ledger.\n", o.witness)
	case n > 1:
		fmt.Fprintf(stdout, "The %d checkpoints in %s are all in the ledger.\n", n, o.witness)
	}
	return 0
}

func readLedgerFile(path string) (*ledger.Ledger, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, &config.Error{File: path, Msg: "no such ledger: seal the records first, or give it with --ledger"}
		}
		return nil, err
	}
	defer f.Close()
	return ledger.ReadLedger(f, path)
}

// lineOf returns line n of a file, without its newline.
func lineOf(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), ledger.MaxLine+2)
	for i := 1; sc.Scan(); i++ {
		if i == n {
			return sc.Bytes(), nil
		}
	}
	if errors.Is(sc.Err(), bufio.ErrTooLong) {
		return nil, &ledger.Problem{File: path, Line: n, Kind: "changed", Msg: "longer than any record seal accepts: the record was changed"}
	} else if sc.Err() != nil {
		return nil, sc.Err()
	}
	return nil, &config.Error{File: path, Line: n, Msg: "the file has fewer lines"}
}

func proveCmd(args []string, stdout, stderr io.Writer) int {
	o, pos, err := parse("prove", args, 1, 1, "records file")
	if err != nil {
		return fail(stderr, exitInput, "prove: %v", err)
	}
	if o.line < 1 {
		return fail(stderr, exitInput, "prove: --line N is required: the record's line, 1 for the first")
	}
	records := pos[0]
	ledgerPath := o.ledger
	if ledgerPath == "" {
		ledgerPath = records + ".ledger"
	}
	led, err := readLedgerFile(ledgerPath)
	if err != nil {
		return failErr(stderr, err)
	}
	rec, err := lineOf(records, o.line)
	if err != nil {
		return failErr(stderr, err)
	}
	p, err := ledger.Prove(led, records, o.line, rec)
	if err != nil {
		return failErr(stderr, err)
	}
	js := p.JSON()
	if o.out == "" || o.out == "-" {
		stdout.Write(js)
	} else if err := os.WriteFile(o.out, js, 0o644); err != nil {
		return failErr(stderr, err)
	}
	fmt.Fprintf(stderr, "vpnw-ledger: a proof that line %d of %s is in the log: %d hashes to the root of checkpoint %d, which covers %s records; %s bytes.\n",
		p.Line, records, len(p.Path), p.Checkpoint.Seq, comma(p.Checkpoint.Size), comma(len(js)))
	return 0
}

func checkProofCmd(args []string, stdout, stderr io.Writer) int {
	o, pos, err := parse("check-proof", args, 1, 2, "proof file")
	if err != nil {
		return fail(stderr, exitInput, "check-proof: %v", err)
	}
	pub, err := readPublic(o.pub)
	if err != nil {
		return failErr(stderr, err)
	}
	b, err := readSmall(pos[0])
	if err != nil {
		return failErr(stderr, err)
	}
	p, err := ledger.ParseProof(b)
	if err != nil {
		return fail(stderr, exitInput, "%s: %v", pos[0], err)
	}
	if len(pos) == 2 {
		b, err := readSmall(pos[1])
		if err != nil {
			return failErr(stderr, err)
		}
		rec, rest, _ := strings.Cut(string(b), "\n")
		if rest != "" {
			return fail(stderr, exitInput, "%s: more than one line; give the one record", pos[1])
		}
		p.Record = []byte(rec)
	}
	if err := p.Check(pub); err != nil {
		fmt.Fprintf(stdout, "%s: the proof doesn't hold: %v.\n", pos[0], err)
		return exitFound
	}
	c := p.Checkpoint
	fmt.Fprintf(stdout, "The proof holds. Line %d of log %s, under checkpoint %d (%s records, signed %s by %s), is:\n%s\n",
		p.Line, c.Log, c.Seq, comma(c.Size), c.When(), c.Key, p.Record)
	return 0
}

// comma writes n with thousands separators.
func comma(n int) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0 && s[i-1] != '-'; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
