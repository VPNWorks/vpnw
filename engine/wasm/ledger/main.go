// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build js && wasm

// Command ledger-wasm runs Ledger's own code in the browser demo: key
// generation, sealing, verifying, proofs and the tamper matrix. The page
// draws; every hash, line number and verdict it shows comes from these
// calls. The private keys are made here, with the browser's random source,
// and never leave this module.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"strings"
	"syscall/js"
	"time"

	"vpnw.com/vpnw/internal/ledger"
	"vpnw.com/vpnw/internal/ledger/tamper"
)

const (
	recName = "1-trace-1.jsonl"
	ledName = "1-trace-1.jsonl.ledger"
)

// keys holds the page's private keys: "main", which seals, and "other",
// for the wrong-key case.
var keys = map[string]*ledger.PrivateKey{}

func main() {
	js.Global().Set("vpnwLedger", js.ValueOf(map[string]any{
		"version":    ledger.Version,
		"keygen":     js.FuncOf(keygenFn),
		"seal":       js.FuncOf(sealFn),
		"verify":     js.FuncOf(verifyFn),
		"prove":      js.FuncOf(proveFn),
		"checkProof": js.FuncOf(checkProofFn),
		"matrix":     js.FuncOf(matrixFn),
	}))
	select {}
}

func out(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"ok":false,"error":"` + err.Error() + `"}`
	}
	return string(b)
}

type failure struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

func fail(err error) any { return out(failure{Error: err.Error()}) }

func arg(args []js.Value, i int) string {
	if i < len(args) && args[i].Type() == js.TypeString {
		return args[i].String()
	}
	return ""
}

func key(slot string) *ledger.PrivateKey {
	if k := keys[slot]; k != nil {
		return k
	}
	return keys["main"]
}

// keygenFn makes the key in a slot and returns its public half.
func keygenFn(_ js.Value, args []js.Value) any {
	k, err := ledger.NewKey(rand.Reader)
	if err != nil {
		return fail(err)
	}
	slot := arg(args, 0)
	if slot == "" {
		slot = "main"
	}
	keys[slot] = k
	return out(struct {
		OK  bool   `json:"ok"`
		ID  string `json:"id"`
		Pub string `json:"pub"`
	}{true, k.ID, k.Public().Text()})
}

type checkpoint struct {
	CP    int    `json:"cp"`
	Size  int    `json:"size"`
	Root  string `json:"root"`
	Chain string `json:"chain"`
	Prev  string `json:"prev"`
	Time  string `json:"time"`
	Key   string `json:"key"`
	Line  int    `json:"line"`
	Text  string `json:"text"` // the signed message
}

func describe(c *ledger.Checkpoint, line int) checkpoint {
	return checkpoint{c.Seq, c.Size, c.Root.String(), c.Chain.String(), c.Prev.String(), c.When(), c.Key, line, string(c.Message())}
}

// sealFn seals records with the main key, a checkpoint every n records.
func sealFn(_ js.Value, args []js.Value) any {
	k := keys["main"]
	if k == nil {
		return fail(errNoKey)
	}
	every := 8
	if len(args) > 1 && args[1].Type() == js.TypeNumber {
		every = args[1].Int()
	}
	var led bytes.Buffer
	start := time.Now()
	s, err := ledger.NewSealer(&led, k, recName, ledger.Options{Every: every})
	if err != nil {
		return fail(err)
	}
	n, err := s.SealAll(strings.NewReader(arg(args, 0)), recName, 0)
	if err != nil {
		return fail(err)
	}
	ms := time.Since(start).Seconds() * 1000
	l, err := ledger.ReadLedger(bytes.NewReader(led.Bytes()), ledName)
	if err != nil {
		return fail(err)
	}
	var res struct {
		OK          bool         `json:"ok"`
		Ledger      string       `json:"ledger"`
		Records     int          `json:"records"`
		Checkpoints []checkpoint `json:"checkpoints"`
		MS          float64      `json:"ms"`
	}
	res.OK, res.Ledger, res.Records, res.MS = true, led.String(), n, ms
	for i, c := range l.Checkpoints {
		res.Checkpoints = append(res.Checkpoints, describe(c, l.CPLines[i]))
	}
	return out(res)
}

type problem struct {
	File string `json:"file"` // "records" or "ledger"
	Line int    `json:"line"`
	Kind string `json:"kind"`
	Msg  string `json:"msg"`
	Said string `json:"said"` // as vpnw-ledger verify prints it
}

func describeProblem(p *ledger.Problem) *problem {
	if p == nil {
		return nil
	}
	file := "records"
	if p.File == ledName || p.File == "ledger" {
		file = "ledger"
	}
	return &problem{file, p.Line, p.Kind, p.Msg, p.Error()}
}

// verifyFn checks records against a ledger with the public half of a key
// slot, and optionally checkpoint lines kept elsewhere.
func verifyFn(_ js.Value, args []js.Value) any {
	k := key(arg(args, 2))
	if k == nil {
		return fail(errNoKey)
	}
	start := time.Now()
	recs, _, err := ledger.HashRecords(strings.NewReader(arg(args, 0)), 0)
	if err != nil {
		return fail(err)
	}
	led, err := ledger.ReadLedger(strings.NewReader(arg(args, 1)), ledName)
	if err != nil {
		return fail(err)
	}
	var opt ledger.VerifyOptions
	if w := arg(args, 3); w != "" {
		if opt.Witness, err = ledger.ReadWitness(strings.NewReader(w), "witness", k.Public()); err != nil {
			return fail(err)
		}
	}
	rep := ledger.Verify(recs, recName, led, k.Public(), opt)
	var res struct {
		OK      bool        `json:"ok"`
		Intact  bool        `json:"intact"`
		Problem *problem    `json:"problem"`
		Records int         `json:"records"`
		Sealed  int         `json:"sealed"`
		Checked int         `json:"checked"`
		Last    *checkpoint `json:"last"`
		MS      float64     `json:"ms"`
	}
	res.OK, res.Intact, res.Problem = true, rep.Problem == nil, describeProblem(rep.Problem)
	res.Records, res.Sealed, res.Checked = rep.Records, rep.Sealed, rep.Checked
	if rep.Last != nil {
		c := describe(rep.Last, led.CPLines[rep.Checked-1])
		res.Last = &c
	}
	res.MS = time.Since(start).Seconds() * 1000
	return out(res)
}

// proveFn makes the proof for one line.
func proveFn(_ js.Value, args []js.Value) any {
	records, n := arg(args, 0), 0
	if len(args) > 2 && args[2].Type() == js.TypeNumber {
		n = args[2].Int()
	}
	led, err := ledger.ReadLedger(strings.NewReader(arg(args, 1)), ledName)
	if err != nil {
		return fail(err)
	}
	lines := strings.Split(records, "\n")
	if n < 1 || n > len(lines) {
		return fail(errNoLine)
	}
	p, err := ledger.Prove(led, recName, n, []byte(lines[n-1]))
	if err != nil {
		return fail(err)
	}
	var res struct {
		OK    bool       `json:"ok"`
		Proof string     `json:"proof"`
		Line  int        `json:"line"`
		Leaf  string     `json:"leaf"`
		Path  []string   `json:"path"`
		Bytes int        `json:"bytes"`
		CP    checkpoint `json:"checkpoint"`
	}
	text := p.JSON()
	res.OK, res.Proof, res.Line, res.Leaf, res.Bytes = true, string(text), p.Line, p.Leaf.String(), len(text)
	for _, h := range p.Path {
		res.Path = append(res.Path, h.String())
	}
	res.CP = describe(p.Checkpoint, 0)
	return out(res)
}

// checkProofFn checks a proof with the public half of a key slot, and
// nothing else.
func checkProofFn(_ js.Value, args []js.Value) any {
	k := key(arg(args, 1))
	if k == nil {
		return fail(errNoKey)
	}
	var res struct {
		OK     bool   `json:"ok"`
		Holds  bool   `json:"holds"`
		Msg    string `json:"msg"`
		Line   int    `json:"line"`
		Record string `json:"record"`
	}
	res.OK = true
	p, err := ledger.ParseProof([]byte(arg(args, 0)))
	if err != nil {
		res.Msg = err.Error()
		return out(res)
	}
	res.Line, res.Record = p.Line, string(p.Record)
	if err := p.Check(k.Public()); err != nil {
		res.Msg = err.Error()
		return out(res)
	}
	c := p.Checkpoint
	res.Holds = true
	res.Msg = "line " + itoa(p.Line) + " of log " + c.Log + ", under checkpoint " + itoa(c.Seq) + " (" + itoa(c.Size) + " records, signed " + c.When() + " by " + c.Key + ")"
	return out(res)
}

// matrixFn runs the tamper matrix around one line of a sealed log.
func matrixFn(_ js.Value, args []js.Value) any {
	if keys["main"] == nil || keys["other"] == nil {
		return fail(errNoKey)
	}
	f := tamper.Files{Records: tamper.Split([]byte(arg(args, 0))), Ledger: tamper.Split([]byte(arg(args, 1)))}
	target := 25
	if len(args) > 2 && args[2].Type() == js.TypeNumber {
		target = args[2].Int()
	}
	cases, err := tamper.Matrix(f, target)
	if err != nil {
		return fail(err)
	}
	type row struct {
		Name    string   `json:"name"`
		File    string   `json:"file"`
		Line    int      `json:"line"`
		Kind    string   `json:"kind"`
		Problem *problem `json:"problem"`
		Caught  bool     `json:"caught"`
	}
	var res struct {
		OK   bool  `json:"ok"`
		Rows []row `json:"rows"`
	}
	res.OK = true
	for _, c := range cases {
		r, err := tamper.Run(c, f, keys["main"].Public(), keys["other"].Public())
		if err != nil {
			return fail(err)
		}
		res.Rows = append(res.Rows, row{c.Name, c.File, c.Line, c.Kind, describeProblem(r.Problem), r.Caught})
	}
	return out(res)
}

type demoError string

func (e demoError) Error() string { return string(e) }

const (
	errNoKey  = demoError("make a key first")
	errNoLine = demoError("no such line")
)

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
