// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package pluginhost_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/VPNWorks/vpnw/internal/path"
	"github.com/VPNWorks/vpnw/internal/pluginhost"
	"github.com/VPNWorks/vpnw/plugins/builtin"
)

// tunneler loads the test tunnel plugin with a folder of the given files.
func tunneler(t *testing.T, set map[string]string, files map[string]string) (*pluginhost.TunnelPlugin, *pluginhost.Instance) {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	d, err := pluginhost.OpenFolder(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	in, err := host(t).Load(sharedCtx, pkg(t, "tunneler"), pluginhost.Options{Run: "r-tun", Settings: set, Folder: d, FolderName: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(in.Close)
	return pluginhost.NewTunnel(in), in
}

// A tunnel plugin hands over the configs it reads from its folder, and
// how long to keep each.
func TestTunnelPluginHandsOverConfigs(t *testing.T) {
	tp, _ := tunneler(t, map[string]string{"keep": "30"}, map[string]string{"a.conf": "config A", "b.conf": "config B"})
	if tp.Name() != "tunneler" {
		t.Errorf("name %q", tp.Name())
	}
	off, none, err := tp.Next(sharedCtx, path.TunnelQuery{Reason: "start"})
	if err != nil || off == nil || off.Name != "a.conf" || off.Text != "config A" || off.Keep != 30*time.Second {
		t.Fatalf("start: %+v %q %v", off, none, err)
	}
	off, _, err = tp.Next(sharedCtx, path.TunnelQuery{Reason: "due", Current: "a.conf"})
	if err != nil || off.Name != "b.conf" || off.Text != "config B" {
		t.Fatalf("due: %+v %v", off, err)
	}
	off, _, err = tp.Next(sharedCtx, path.TunnelQuery{Reason: "failed", Current: "a.conf", Config: "b.conf", Error: "no handshake"})
	if err != nil || off.Name != "a.conf" {
		t.Fatalf("failed: %+v %v", off, err)
	}
}

// The plugin is told everything about why it is asked.
func TestTunnelPluginRequest(t *testing.T) {
	tp, _ := tunneler(t, map[string]string{"mode": "echo"}, nil)
	off, _, err := tp.Next(sharedCtx, path.TunnelQuery{Reason: "refused", Current: "a.conf", Config: "b.conf", Error: "line 3: PostUp is a wg-quick shell hook"})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(off.Text), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"run": "r-tun", "reason": "refused", "current": "a.conf", "config": "b.conf", "error": "line 3: PostUp is a wg-quick shell hook"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("the plugin was asked %v, want %v", got, want)
	}
}

// A plugin with nothing to give says why, and isn't stopped for it.
func TestTunnelPluginNone(t *testing.T) {
	tp, in := tunneler(t, map[string]string{"mode": "none"}, nil)
	off, none, err := tp.Next(sharedCtx, path.TunnelQuery{Reason: "start"})
	if off != nil || none != "nothing here" || err != nil || in.Err() != nil {
		t.Fatalf("%+v %q %v; stopped: %v", off, none, err, in.Err())
	}
	tp2, in2 := tunneler(t, nil, nil)
	if off, none, err := tp2.Next(sharedCtx, path.TunnelQuery{Reason: "start"}); off != nil || none != "an empty folder" || err != nil || in2.Err() != nil {
		t.Fatalf("empty folder: %+v %q %v", off, none, err)
	}
}

// A plugin that fails in any way is stopped and not asked again; the
// failure is reported once, and only after the run has started.
func TestTunnelPluginFailures(t *testing.T) {
	for mode, want := range map[string]string{
		"panic":   "panic: tunneler exploded",
		"error":   "tunneler failed on purpose",
		"badname": "isn't a config offer: a name must be printable",
		"huge":    "handed over 102427 bytes, more than a config of 65536 bytes takes",
		"spin":    "ran past its 5s time budget",
	} {
		t.Run(mode, func(t *testing.T) {
			tp, in := tunneler(t, map[string]string{"mode": mode}, nil)
			var mu sync.Mutex
			var heard []string
			tp.OnFail(func(name string, err error) {
				mu.Lock()
				heard = append(heard, name+": "+err.Error())
				mu.Unlock()
			})
			_, _, err := tp.Next(sharedCtx, path.TunnelQuery{Reason: "start"})
			if err == nil || !strings.Contains(err.Error(), want) || in.Err() == nil {
				t.Fatalf("err = %v, want %q; stopped: %v", err, want, in.Err())
			}
			if _, _, err := tp.Next(sharedCtx, path.TunnelQuery{Reason: "due"}); !errors.Is(err, pluginhost.ErrStopped) {
				t.Errorf("asked again: %v", err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(heard) != 1 || !strings.HasPrefix(heard[0], "tunneler: ") {
				t.Errorf("heard %q", heard)
			}
		})
	}
	// Without OnFail, as at the start of a run, the failure is only the
	// error.
	tp, _ := tunneler(t, map[string]string{"mode": "panic"}, nil)
	if _, _, err := tp.Next(sharedCtx, path.TunnelQuery{Reason: "start"}); err == nil {
		t.Error("no error")
	}
	// A run that ends while the plugin is asked isn't the plugin's failure.
	tp, _ = tunneler(t, map[string]string{"mode": "spin"}, nil)
	called := false
	tp.OnFail(func(string, error) { called = true })
	ctx, cancel := context.WithTimeout(sharedCtx, 200*time.Millisecond)
	defer cancel()
	if _, _, err := tp.Next(ctx, path.TunnelQuery{Reason: "start"}); err == nil || called {
		t.Errorf("cut short by the end of the run: %v, reported: %v", err, called)
	}
}

// Only tunnel plugins can be asked for a config.
func TestTunnelOnlyFromTunnelPlugins(t *testing.T) {
	in, err := host(t).Load(sharedCtx, pkg(t, "echo"), pluginhost.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if _, _, err := in.Tunnel(sharedCtx, map[string]string{}); err == nil || !strings.Contains(err.Error(), "not a tunnel plugin") {
		t.Errorf("err = %v", err)
	}
}

// folderLog runs the folderer test plugin on a folder and returns its log.
func folderLog(t *testing.T, plugin string, d pluginhost.Folder, dir, read string) ([]string, error) {
	t.Helper()
	var mu sync.Mutex
	var logs []string
	in, err := host(t).Load(sharedCtx, pkg(t, plugin), pluginhost.Options{Folder: d, FolderName: dir,
		Settings: map[string]string{"read": read},
		Log: func(_, l string) {
			mu.Lock()
			logs = append(logs, l)
			mu.Unlock()
		}})
	if err == nil {
		in.Close()
	}
	mu.Lock()
	defer mu.Unlock()
	return append([]string(nil), logs...), err
}

func sum(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }

// A plugin reads the regular files directly in its folder, a link to one
// in the folder included, and nothing else: not a file outside, not a
// link out, not a subfolder, not a named pipe, not a file over 1 MiB.
func TestFolderRead(t *testing.T) {
	base := t.TempDir()
	secret := filepath.Join(base, "secret")
	os.WriteFile(secret, []byte("not for plugins"), 0o600)
	dir := filepath.Join(base, "configs")
	os.Mkdir(dir, 0o700)
	small, mid := []byte("[Interface]\n"), []byte(strings.Repeat("x", 20<<10))
	os.WriteFile(filepath.Join(dir, "a.conf"), small, 0o600)
	os.WriteFile(filepath.Join(dir, "mid.conf"), mid, 0o600)
	os.WriteFile(filepath.Join(dir, "big.bin"), make([]byte, pluginhost.MaxFolderRead+1), 0o600)
	os.WriteFile(filepath.Join(dir, ".hidden"), []byte("h"), 0o600)
	os.Mkdir(filepath.Join(dir, "sub"), 0o700)
	os.WriteFile(filepath.Join(dir, "sub", "deep.conf"), []byte("deep"), 0o600)
	os.Symlink("a.conf", filepath.Join(dir, "link-in"))
	os.Symlink(secret, filepath.Join(dir, "link-out"))
	os.Symlink("../secret", filepath.Join(dir, "link-up"))
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := pluginhost.OpenFolder(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	logs, err := folderLog(t, "folderer", d, dir, "a.conf,mid.conf,big.bin,.hidden,sub,sub/deep.conf,link-in,link-out,link-up,fifo,../secret,"+secret+",nosuch,.,..")
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(logs, "\n")
	want := []string{
		"folder " + dir,
		fmt.Sprintf("list .hidden:1 a.conf:%d big.bin:%d link-in:%d mid.conf:%d", len(small), pluginhost.MaxFolderRead+1, len(small), len(mid)),
		fmt.Sprintf("read a.conf %d %s", len(small), sum(small)),
		fmt.Sprintf("read mid.conf %d %s", len(mid), sum(mid)),
		"read big.bin failed",
		"read .hidden 1",
		"read sub failed",
		"read sub/deep.conf failed",
		fmt.Sprintf("read link-in %d %s", len(small), sum(small)),
		"read link-out failed",
		"read link-up failed",
		"read fifo failed",
		"read ../secret failed",
		"read " + secret + " failed",
		"read nosuch failed",
		"read . failed",
		"read .. failed",
	}
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("log lacks %q", w)
		}
	}
	if strings.Contains(got, sum([]byte("not for plugins"))) {
		t.Error("the plugin read the file outside its folder")
	}
	for _, why := range []string{"is 1048577 bytes, over the 1048576-byte limit", "sub is not a regular file", "fifo is not a regular file", "is not the name of a file in the folder", "nosuch: no such file"} {
		if !strings.Contains(got, why) {
			t.Errorf("log lacks the reason %q:\n%s", why, got)
		}
	}
}

// Without a folder (vpnw advise, say), listing and reading fail, and the
// log says why.
func TestFolderReadWithoutFolder(t *testing.T) {
	logs, err := folderLog(t, "folderer", nil, "", "a.conf")
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(logs, "\n")
	for _, w := range []string{"list failed", "read a.conf failed", "no folder is open for this plugin"} {
		if !strings.Contains(got, w) {
			t.Errorf("log lacks %q:\n%s", w, got)
		}
	}
}

// A module that imports the folder calls without asking for folder.read is
// refused before any of its code runs.
func TestFolderNeedsPermission(t *testing.T) {
	d, err := pluginhost.OpenFolder(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	_, err = folderLog(t, "foldersneak", d, "", "")
	if err == nil || !strings.Contains(err.Error(), `but its manifest does not ask for the "folder.read" permission`) {
		t.Fatalf("err = %v", err)
	}
}

func TestOpenFolder(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	os.WriteFile(f, nil, 0o600)
	if _, err := pluginhost.OpenFolder(f); err == nil || !strings.Contains(err.Error(), "is not a folder") {
		t.Errorf("a file: %v", err)
	}
	if _, err := pluginhost.OpenFolder(filepath.Join(t.TempDir(), "nope")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
}

func TestParseOffer(t *testing.T) {
	o, err := pluginhost.ParseOffer([]byte(`{"name":"de-1.conf","config":"[Interface]\n","keep":600}`))
	if err != nil || o.Name != "de-1.conf" || o.Text != "[Interface]\n" || o.Keep != 10*time.Minute {
		t.Fatalf("%+v %v", o, err)
	}
	if o, err := pluginhost.ParseOffer([]byte(`{"name":"a","config":"x"}`)); err != nil || o.Keep != 0 {
		t.Errorf("no keep: %+v %v", o, err)
	}
	for src, want := range map[string]string{
		`{"name":"a","config":"x","extra":1}`:          "unknown field",
		`{"name":"a","config":"x"}{}`:                  "more than one JSON object",
		`{"config":"x"}`:                               "no name",
		`{"name":"a"}`:                                 "no config",
		`{"name":"a\u0007","config":"x"}`:              "printable",
		`{"name":"a","config":"x","keep":-1}`:          "keep must be whole seconds",
		`{"name":"a","config":"x","keep":1.5}`:         "keep must be whole seconds",
		`{"name":"a","config":"x","keep":99999999999}`: "keep must be whole seconds",
		`[1]`:  "cannot unmarshal",
		`"x"`:  "cannot unmarshal",
		`{"na`: "unexpected EOF",
		`{"name":"` + strings.Repeat("n", 129) + `","config":"x"}`:                   "at most 128",
		`{"name":"a","config":"` + strings.Repeat("c", pluginhost.MaxOffer+1) + `"}`: "over the 65536-byte limit",
	} {
		if _, err := pluginhost.ParseOffer([]byte(src)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%.60s: %v, want %q", src, err, want)
		}
	}
}

// BenchmarkRotateNext is the built-in rotate plugin asked for the next
// config, with its folder of 20 configs listed and one read.
func BenchmarkRotateNext(b *testing.B) {
	dir := b.TempDir()
	for i := range 20 {
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("se-%02d.conf", i)), []byte(strings.Repeat("# a WireGuard config\n", 15)), 0o600)
	}
	d, err := pluginhost.OpenFolder(dir)
	if err != nil {
		b.Fatal(err)
	}
	defer d.Close()
	h, err := pluginhost.New(sharedCtx, cacheDir)
	if err != nil {
		b.Fatal(err)
	}
	defer h.Close(sharedCtx)
	pkgs, _ := builtin.Packages()
	var rot *pluginhost.Package
	for _, p := range pkgs {
		if p.Manifest.Name == "rotate" {
			rot = p
		}
	}
	in, err := h.Load(sharedCtx, rot, pluginhost.Options{Run: "r-bench", Folder: d, FolderName: dir})
	if err != nil {
		b.Fatal(err)
	}
	defer in.Close()
	tp := pluginhost.NewTunnel(in)
	cur := ""
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		off, _, err := tp.Next(sharedCtx, path.TunnelQuery{Reason: "due", Current: cur})
		if err != nil || off == nil {
			b.Fatal(err)
		}
		cur = off.Name
	}
}
