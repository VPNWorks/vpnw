// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"bytes"
	"strings"
	"testing"
)

// The hooks decode what vpnw sends; RawEvents skips the decoding.
func TestHooks(t *testing.T) {
	var got []string
	var cfg *Config
	Register(Plugin{
		Init: func(c *Config) error { cfg = c; return nil },
		OnEvent: func(e *Event) error {
			got = append(got, e.Type+" "+e.Str("host")+" "+string(rune('0'+e.Int("port")%10)))
			return nil
		},
		OnDecide: func(r *Request) (bool, string) { return r.Host == "evil.example", "no " + r.Host },
	})
	if err := CallInit([]byte(`{"plugin":"p","command":"trace","tz_offset":10800,"tz_name":"IDT"}`)); err != nil {
		t.Fatal(err)
	}
	if cfg.Settings == nil || cfg.Command != "trace" || cfg.Zone().String() != "IDT" {
		t.Errorf("config %+v", cfg)
	}
	if err := CallEvent([]byte(`{"type":"connection.attempt","fields":{"host":"a.example","port":443}}`)); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ";") != "connection.attempt a.example 3" {
		t.Errorf("events %v", got)
	}
	if deny, why, err := CallDecide([]byte(`{"host":"evil.example","port":443}`)); !deny || why != "no evil.example" || err != nil {
		t.Errorf("decide %v %q %v", deny, why, err)
	}
	if deny, _, _ := CallDecide([]byte(`{"host":"good.example"}`)); deny {
		t.Error("good.example refused")
	}
	if _, _, err := CallDecide([]byte(`not json`)); err == nil {
		t.Error("bad request accepted")
	}

	var raw []byte
	Register(Plugin{RawEvents: true, OnEvent: func(e *Event) error { raw = e.Raw; return nil }})
	CallEvent([]byte(`{"type":"x"}`))
	if string(raw) != `{"type":"x"}` {
		t.Errorf("raw %q", raw)
	}

	var out, errOut bytes.Buffer
	var emitted []string
	TestStdout, TestStderr, TestEmit = &out, &errOut, func(b []byte) { emitted = append(emitted, string(b)) }
	Stdout("o")
	Stderr("e")
	Emit("seen", map[string]any{"n": 1})
	if out.String() != "o" || errOut.String() != "e" || len(emitted) != 1 || emitted[0] != `{"type":"seen","fields":{"n":1}}` {
		t.Errorf("out %q err %q emitted %v", out.String(), errOut.String(), emitted)
	}
}
