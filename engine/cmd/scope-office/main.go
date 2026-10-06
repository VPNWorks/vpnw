// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Command scope-office writes the made-up office that Scope's tests,
// measurements and demo use: its people file and its generated flows. It
// is a tool for the prototype, not part of the product.
//
//	scope-office [--large N] [--seed S] DIR
//
// It writes DIR/people.toml, DIR/learn.jsonl (the two weeks to learn from),
// DIR/replay.jsonl (the week after) and DIR/stolen.jsonl (a stolen login
// trying every system).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"vpnw.com/vpnw/internal/scope"
	"vpnw.com/vpnw/internal/scope/office"
)

func main() {
	large := flag.Int("large", 0, "people in a large office (0: the 30-person demo office)")
	seed := flag.Uint64("seed", office.DemoSeed, "seed for the traffic")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: scope-office [--large N] [--seed S] DIR")
		os.Exit(2)
	}
	dir := flag.Arg(0)
	o := office.Demo()
	if *large > 0 {
		o = office.Large(*large, *seed)
	}
	check := func(err error) {
		if err != nil {
			fmt.Fprintln(os.Stderr, "scope-office:", err)
			os.Exit(1)
		}
	}
	check(os.MkdirAll(dir, 0o755))
	check(os.WriteFile(filepath.Join(dir, "people.toml"), []byte(o.PeopleFile()), 0o644))
	write := func(name string, from, to int) int {
		f, err := os.Create(filepath.Join(dir, name))
		check(err)
		fw := scope.NewFlowWriter(f)
		n := 0
		o.Flows(from, to, *seed, func(fl scope.Flow) { check(fw.Write(fl)); n++ })
		check(fw.Flush())
		check(f.Close())
		return n
	}
	a := write("learn.jsonl", office.DemoLearnFrom, office.DemoLearnTo)
	b := write("replay.jsonl", office.DemoReplayFrom, office.DemoReplayTo)
	f, err := os.Create(filepath.Join(dir, "stolen.jsonl"))
	check(err)
	fw := scope.NewFlowWriter(f)
	stolen := o.StolenLogin(o.Members[0].ID, office.DemoStolenAt)
	for _, fl := range stolen {
		check(fw.Write(fl))
	}
	check(fw.Flush())
	check(f.Close())
	fmt.Printf("%s: %s people, %d systems; %s flows to learn from, %s to replay, %s stolen-login attempts by %s\n",
		o.Name, scope.Comma(len(o.Members)), len(o.Systems), scope.Comma(a), scope.Comma(b), scope.Comma(len(stolen)), o.Members[0].ID)
}
