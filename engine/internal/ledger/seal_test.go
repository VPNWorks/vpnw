// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"vpnw.com/vpnw/internal/config"
)

func TestSealAndVerify(t *testing.T) {
	k := testKey(t, 1)
	records := text(agentLines(20))
	var cps []*Checkpoint
	var led bytes.Buffer
	s, err := NewSealer(&led, k, "test.jsonl", Options{Every: 8, Now: clock()})
	if err != nil {
		t.Fatal(err)
	}
	s.OnCheckpoint = func(c *Checkpoint) { cps = append(cps, c) }
	if n, err := s.SealAll(bytes.NewReader(records), "test.jsonl", 0); err != nil || n != 20 || s.Sealed() != 20 {
		t.Fatalf("sealed %d: %v", n, err)
	}
	ls := lines(led.Bytes())
	if len(ls) != 24 || ls[0] != `{"vpnw-ledger":1,"log":"test.jsonl"}` || !strings.HasPrefix(ls[1], `{"n":1,"leaf":"`+LeafHash([]byte(agentLines(1)[0])).String()) {
		t.Fatalf("ledger:\n%s", led.String())
	}
	if len(cps) != 3 || cps[0].Size != 8 || cps[1].Size != 16 || cps[2].Size != 20 || s.Last() != cps[2] {
		t.Fatalf("checkpoints %+v", cps)
	}
	if cps[0].Prev != (Hash{}) || cps[1].Prev != cps[0].Hash() || cps[2].Prev != cps[1].Hash() || cps[2].Seq != 3 {
		t.Fatal("checkpoints don't link")
	}
	if !cps[0].Time.After(t0) || cps[0].Time.Nanosecond() != 0 || cps[0].Key != k.ID {
		t.Fatalf("time %s, key %s", cps[0].Time, cps[0].Key)
	}
	rep := check(t, records, led.Bytes(), k.Public(), VerifyOptions{})
	if rep.Problem != nil || rep.Records != 20 || rep.Sealed != 20 || rep.Checked != 3 || rep.Last.Size != 20 {
		t.Fatalf("%+v %v", rep, rep.Problem)
	}
	// A last line without its newline is a record all the same.
	noNL := records[:len(records)-1]
	if rep := check(t, noNL, seal(t, k, noNL, 8), k.Public(), VerifyOptions{}); rep.Problem != nil || rep.Records != 20 {
		t.Fatalf("no newline at the end: %v", rep.Problem)
	}
	if _, err := NewSealer(&led, k, "a\"b", Options{}); err == nil {
		t.Error("a bad log name")
	}
	if _, err := NewSealer(failWriter{}, k, "x", Options{}); err == nil {
		t.Error("write error lost")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// resume reads what is there, checks it, and seals what was added.
func resume(t testing.TB, k *PrivateKey, records []byte, ledger *bytes.Buffer, every int) (int, error) {
	t.Helper()
	led, err := ReadLedger(bytes.NewReader(ledger.Bytes()), "test.jsonl.ledger")
	if err != nil {
		t.Fatal(err)
	}
	recs, end, err := HashRecords(bytes.NewReader(records), len(led.Leaves))
	if err != nil {
		t.Fatal(err)
	}
	rep := Verify(recs, "test.jsonl", led, k.Public(), VerifyOptions{Tail: true})
	s, err := ResumeSealer(ledger, k, led, rep, Options{Every: every, Now: clock()})
	if err != nil {
		return 0, err
	}
	return s.SealAll(bytes.NewReader(records[end:]), "test.jsonl", len(led.Leaves))
}

func TestSealResume(t *testing.T) {
	k := testKey(t, 1)
	all := agentLines(15)
	led := bytes.NewBuffer(seal(t, k, text(all[:10]), 4))
	if n, err := resume(t, k, text(all), led, 4); err != nil || n != 5 {
		t.Fatalf("resume: %d %v", n, err)
	}
	rep := check(t, text(all), led.Bytes(), k.Public(), VerifyOptions{})
	if rep.Problem != nil || rep.Checked != 5 || rep.Last.Size != 15 {
		t.Fatalf("%+v %v\n%s", rep, rep.Problem, led.String())
	}
	before := led.Len()
	if n, err := resume(t, k, text(all), led, 4); err != nil || n != 0 || led.Len() != before {
		t.Fatalf("nothing new: %d %v, the ledger grew by %d", n, err, led.Len()-before)
	}

	// Sealed without a newline at the end; the newline and more came later.
	led = bytes.NewBuffer(seal(t, k, []byte(all[0]+"\n"+all[1]), 4))
	if n, err := resume(t, k, []byte(all[0]+"\n"+all[1]+"\n"+all[2]+"\n"), led, 4); err != nil || n != 1 {
		t.Fatalf("after a last line without a newline: %d %v", n, err)
	}
	// The last line sealed grew instead.
	led = bytes.NewBuffer(seal(t, k, []byte(all[0]+"\n"+all[1]), 4))
	var p *Problem
	if _, err := resume(t, k, []byte(all[0]+"\n"+all[1]+" \n"), led, 4); !errors.As(err, &p) || p.Line != 2 || p.Kind != "changed" {
		t.Fatalf("a sealed line that grew: %v", err)
	}
	// A record changed before the new ones: nothing more is sealed.
	led = bytes.NewBuffer(seal(t, k, text(all[:10]), 4))
	changed := append([]string{}, all...)
	changed[2] = strings.Replace(changed[2], "h3.example", "h4.example", 1)
	before = led.Len()
	if _, err := resume(t, k, text(changed), led, 4); !errors.As(err, &p) || p.Line != 3 || p.Kind != "changed" || led.Len() != before {
		t.Fatalf("resume over a changed record: %v", err)
	}
	// Another key.
	led = bytes.NewBuffer(seal(t, k, text(all[:10]), 4))
	if _, err := resume(t, testKey(t, 2), text(all), led, 4); err == nil {
		t.Fatal("resumed with another key")
	}
	l, _ := ReadLedger(bytes.NewReader(led.Bytes()), "x.ledger")
	if _, err := ResumeSealer(led, testKey(t, 2), l, &Report{Last: l.Checkpoints[0]}, Options{}); err == nil || !strings.Contains(err.Error(), "x.ledger was sealed with key "+k.ID) {
		t.Fatalf("another key: %v", err)
	}
}

func TestSealRefuses(t *testing.T) {
	k := testKey(t, 1)
	good := agentLines(3)
	for in, want := range map[string]string{
		good[0] + "\n" + good[1] + "\n{oops\n":          "test.jsonl:3: not valid JSON",
		good[0] + "\n\n" + good[1] + "\n":               "test.jsonl:2: an empty line",
		good[0] + "\n" + strings.Repeat(" ", MaxLine+1): "test.jsonl:2: longer than 65536 bytes",
		"\"\xfe\"\n": "test.jsonl:1: not valid UTF-8",
	} {
		var led bytes.Buffer
		s, _ := NewSealer(&led, k, "test.jsonl", Options{Every: 1})
		_, err := s.SealAll(strings.NewReader(in), "test.jsonl", 0)
		var ce *config.Error
		if !errors.As(err, &ce) || !strings.Contains(err.Error(), want) {
			t.Errorf("%.30q: %v, want %q", in, err, want)
		}
		// What was sealed before the bad line still verifies.
		if rep := check(t, []byte(in), led.Bytes(), k.Public(), VerifyOptions{}); rep.Problem == nil || rep.Problem.Kind != "unsealed" {
			t.Errorf("%.30q: after the refusal: %v", in, rep.Problem)
		}
	}
	s, _ := NewSealer(io.Discard, k, "test.jsonl", Options{Every: 2})
	s.w = failWriter{}
	if _, err := s.SealAll(bytes.NewReader(text(good)), "test.jsonl", 0); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Errorf("write error: %v", err)
	}
	if _, err := s.SealAll(failReader{}, "test.jsonl", 0); err == nil {
		t.Error("read error lost")
	}
}

// fakeClock is a clock the test moves.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type follow struct {
	path   string
	w      *os.File // the writer's end
	led    bytes.Buffer
	cps    chan *Checkpoint
	clk    *fakeClock
	stop   chan struct{}
	done   chan error
	sealed int
}

// startFollow starts Follow on a records file in its own goroutine.
func startFollow(t *testing.T, k *PrivateKey, path string, every int) *follow {
	t.Helper()
	f := &follow{path: path, cps: make(chan *Checkpoint, 1000), clk: &fakeClock{now: t0}, stop: make(chan struct{}), done: make(chan error, 1)}
	var err error
	if f.w, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSealer(&f.led, k, "follow.jsonl", Options{Every: every, Interval: time.Minute, Poll: 2 * time.Millisecond, Now: f.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	s.OnCheckpoint = func(c *Checkpoint) { f.cps <- c }
	go func() {
		n, err := s.Follow(r, path, 0, f.stop)
		r.Close()
		f.sealed = n
		f.done <- err
	}()
	t.Cleanup(func() { f.w.Close() })
	return f
}

func (f *follow) write(t *testing.T, s string) {
	t.Helper()
	if _, err := f.w.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

// waitCheckpoint moves the clock on until a record has waited long enough
// for a checkpoint, and returns it.
func (f *follow) waitCheckpoint(t *testing.T) *Checkpoint {
	t.Helper()
	deadline := time.After(60 * time.Second)
	for {
		f.clk.Add(2 * time.Minute)
		select {
		case c := <-f.cps:
			return c
		case <-deadline:
			t.Fatal("no checkpoint while records waited")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (f *follow) finish(t *testing.T) error {
	t.Helper()
	close(f.stop)
	select {
	case err := <-f.done:
		return err
	case <-time.After(60 * time.Second):
		t.Fatal("Follow didn't stop")
	}
	return nil
}

func TestFollow(t *testing.T) {
	k := testKey(t, 1)
	path := filepath.Join(t.TempDir(), "follow.jsonl")
	all := agentLines(9)
	f := startFollow(t, k, path, 1000)
	for _, l := range all[:5] {
		f.write(t, l+"\n")
	}
	if c := f.waitCheckpoint(t); c.Seq != 1 || c.Size < 1 || c.Size > 5 {
		t.Fatalf("first checkpoint %+v", c)
	}
	f.write(t, all[5]+"\n"+all[6]+"\n"+all[7]+"\n"+all[8][:20]) // the last line is half written
	if err := f.finish(t); err != nil {
		t.Fatal(err)
	}
	if f.sealed != 8 {
		t.Fatalf("sealed %d", f.sealed)
	}
	led := f.led.Bytes()
	records, _ := os.ReadFile(path)
	if rep := check(t, records, led, k.Public(), VerifyOptions{}); rep.Problem == nil || rep.Problem.Line != 9 || rep.Problem.Kind != "unsealed" || rep.Last.Size != 8 {
		t.Fatalf("with the half-written line: %+v %v", rep, rep.Problem)
	}
	// The line is finished, and a second follow carries on.
	f.write(t, all[8][20:]+"\n")
	records, _ = os.ReadFile(path)
	rd, _ := ReadLedger(bytes.NewReader(led), "follow.jsonl.ledger")
	recs, end, _ := HashRecords(bytes.NewReader(records), 8)
	rep := Verify(recs, path, rd, k.Public(), VerifyOptions{Tail: true})
	ledBuf := bytes.NewBuffer(led)
	s, err := ResumeSealer(ledBuf, k, rd, rep, Options{Poll: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	r, _ := os.Open(path)
	defer r.Close()
	r.Seek(end, io.SeekStart)
	stop := make(chan struct{})
	close(stop)
	if n, err := s.Follow(r, path, 8, stop); err != nil || n != 1 {
		t.Fatalf("second follow: %d %v", n, err)
	}
	if rep := check(t, records, ledBuf.Bytes(), k.Public(), VerifyOptions{}); rep.Problem != nil || rep.Last.Size != 9 || rep.Checked < 3 {
		t.Fatalf("after both: %+v %v", rep, rep.Problem)
	}
}

// A writer goroutine appends lines, some in two writes, while Follow seals
// them and the clock moves; at the stop every line is sealed and checked.
func TestFollowWriter(t *testing.T) {
	k := testKey(t, 3)
	path := filepath.Join(t.TempDir(), "w.jsonl")
	all := agentLines(300)
	f := startFollow(t, k, path, 64)
	wrote := make(chan struct{})
	go func() {
		for i, l := range all {
			if i%3 == 0 {
				f.w.WriteString(l[:10])
				time.Sleep(time.Millisecond)
				f.w.WriteString(l[10:] + "\n")
			} else {
				f.w.WriteString(l + "\n")
			}
			if i%50 == 0 {
				time.Sleep(3 * time.Millisecond)
			}
		}
		close(wrote)
	}()
	f.waitCheckpoint(t)
	<-wrote
	if err := f.finish(t); err != nil {
		t.Fatal(err)
	}
	records, _ := os.ReadFile(path)
	rep := check(t, records, f.led.Bytes(), k.Public(), VerifyOptions{})
	if f.sealed != 300 || rep.Problem != nil || rep.Last.Size != 300 || rep.Checked < 5 {
		t.Fatalf("sealed %d: %+v %v", f.sealed, rep, rep.Problem)
	}
}

func TestFollowErrors(t *testing.T) {
	k := testKey(t, 1)
	dir := t.TempDir()
	// The file gets shorter while it is followed.
	path := filepath.Join(dir, "cut.jsonl")
	f := startFollow(t, k, path, 1)
	for _, l := range agentLines(4) {
		f.write(t, l+"\n")
	}
	for len(f.cps) < 4 {
		time.Sleep(time.Millisecond)
	}
	if err := os.Truncate(path, 10); err != nil {
		t.Fatal(err)
	}
	var p *Problem
	select {
	case err := <-f.done:
		if !errors.As(err, &p) || p.Kind != "cut" || !strings.Contains(p.Msg, "got shorter while it was followed") {
			t.Fatalf("cut while followed: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("Follow didn't notice the cut")
	}
	// A bad line stops it, with the line.
	f = startFollow(t, k, filepath.Join(dir, "bad.jsonl"), 1)
	f.write(t, agentLines(1)[0]+"\nnot json\n")
	var ce *config.Error
	select {
	case err := <-f.done:
		if !errors.As(err, &ce) || ce.Line != 2 {
			t.Fatalf("bad line: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("Follow went on past a bad line")
	}
	// And so does a ledger that can't be written.
	path = filepath.Join(dir, "full.jsonl")
	os.WriteFile(path, text(agentLines(2)), 0o644)
	r, _ := os.Open(path)
	defer r.Close()
	s, _ := NewSealer(io.Discard, k, "full.jsonl", Options{Every: 1})
	s.w = failWriter{}
	if _, err := s.Follow(r, path, 0, make(chan struct{})); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("write error: %v", err)
	}
	if _, err := s.Follow(badFile{}, path, 0, nil); err == nil {
		t.Fatal("seek error lost")
	}
}

type badFile struct{ io.ReadSeeker }

func (badFile) Read([]byte) (int, error)       { return 0, io.EOF }
func (badFile) Seek(int64, int) (int64, error) { return 0, fmt.Errorf("no seeking") }
func (badFile) Stat() (os.FileInfo, error)     { return nil, fmt.Errorf("no stat") }
