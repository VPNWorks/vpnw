// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package exittest runs VPN Works Exit and Agent 0.2.0 end to end in a
// private test network: two agents, two exits in two "countries" with
// addresses of their own, stand-in partner servers that report the source
// address they saw, and a stand-in DNS server, each in a Linux network
// namespace. The real vpnw and vpnw-exit binaries run in them, over real TLS
// with certificates made in the test.
package exittest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"vpnw.com/vpnw/internal/testnet"
)

var (
	vpnwBin, exitBin string
	// binCover, if set, is where vpnw-exit writes its coverage counters.
	binCover = os.Getenv("VPNW_EXIT_BINCOVER")
)

// exitEnv is the environment vpnw-exit runs with.
func exitEnv() []string {
	env := append(os.Environ(), "NO_COLOR=1")
	if binCover != "" {
		env = append(env, "GOCOVERDIR="+binCover)
	}
	return env
}

func TestMain(m *testing.M) {
	if runtime.GOOS != "linux" {
		fmt.Println("exit tests need Linux")
		os.Exit(0)
	}
	if err := testnet.Reexec(); err != nil {
		fmt.Println("exit tests need user namespaces:", err)
		os.Exit(0)
	}
	dir, _ := os.MkdirTemp("", "vpnw-exit-it-")
	vpnwBin = filepath.Join(dir, "vpnw")
	exitBin = filepath.Join(dir, "vpnw-exit")
	for bin, pkg := range map[string]string{vpnwBin: "vpnw.com/vpnw/cmd/vpnw", exitBin: "vpnw.com/vpnw/cmd/vpnw-exit"} {
		args := []string{"build", "-o", bin}
		if binCover != "" && bin == exitBin {
			// tools/measure-exit.sh: count what vpnw-exit runs here.
			args = append(args, "-cover", "-coverpkg=vpnw.com/vpnw/internal/exit/...,vpnw.com/vpnw/cmd/vpnw-exit")
		}
		build := exec.Command("go", append(args, pkg)...)
		build.Stderr = os.Stderr
		if err := build.Run(); err != nil {
			fmt.Println("build failed:", err)
			os.Exit(1)
		}
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
