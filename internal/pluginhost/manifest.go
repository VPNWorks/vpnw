// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package pluginhost

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/VPNWorks/vpnw/internal/config"
)

// ABI is the plugin interface version this vpnw speaks.
const ABI = 1

// Plugin types this vpnw can run, and the ones reserved for later versions.
const (
	Observer = "observer"
	Advisor  = "advisor"
	Guard    = "guard"
)

var reservedTypes = map[string]bool{"tunnel": true, "exit": true, "identity": true}

// Permissions a manifest can ask for. Logging, reporting an error and giving
// a reason for a refusal are always allowed.
const (
	PermConsole = "console"     // write to vpnw's standard output and error
	PermEmit    = "events.emit" // add events to the run's record
)

var knownPerms = map[string]string{
	PermConsole: "write to vpnw's standard output and error",
	PermEmit:    "add its own events to the run's record",
}

// PermissionText says in a few words what a permission lets a plugin do.
func PermissionText(p string) string { return knownPerms[p] }

// Manifest is a plugin's plugin.toml.
type Manifest struct {
	Name        string
	Version     string
	Type        string
	ABI         int
	Description string
	Permissions []string
}

// Has reports whether the manifest asks for a permission.
func (m *Manifest) Has(p string) bool {
	for _, x := range m.Permissions {
		if x == p {
			return true
		}
	}
	return false
}

var (
	nameRe    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)
	versionRe = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$`)
)

// ParseManifest reads plugin.toml. Like vpnw's other files, anything it does
// not know is an error, never silently skipped.
func ParseManifest(src string) (*Manifest, error) {
	doc, err := config.Parse(src)
	if err != nil {
		return nil, fmt.Errorf("plugin.toml: %w", err)
	}
	for _, name := range doc.Order {
		if name != "" {
			return nil, fmt.Errorf("plugin.toml: unexpected table [%s]; the manifest is plain keys", name)
		}
	}
	root := doc.Tables[""]
	if root == nil {
		return nil, fmt.Errorf("plugin.toml is empty")
	}
	m := &Manifest{}
	str := func(k string, required bool) (string, error) {
		v, ok := root.Keys[k]
		if !ok {
			if required {
				return "", fmt.Errorf("plugin.toml: %s is missing", k)
			}
			return "", nil
		}
		if v.Kind != config.KString {
			return "", fmt.Errorf("plugin.toml line %d: %s must be a string", v.Line, k)
		}
		return v.Str, nil
	}
	for _, k := range root.Order {
		switch k {
		case "name", "version", "type", "abi", "description", "permissions":
		default:
			return nil, fmt.Errorf("plugin.toml line %d: unknown key %q", root.Keys[k].Line, k)
		}
	}
	if m.Name, err = str("name", true); err != nil {
		return nil, err
	}
	if !nameRe.MatchString(m.Name) {
		return nil, fmt.Errorf("plugin.toml: name %q must be lower case letters, digits and dashes, starting with a letter, at most 40", m.Name)
	}
	if m.Version, err = str("version", true); err != nil {
		return nil, err
	}
	if !versionRe.MatchString(m.Version) {
		return nil, fmt.Errorf("plugin.toml: version %q is not of the form X.Y.Z", m.Version)
	}
	if m.Type, err = str("type", true); err != nil {
		return nil, err
	}
	switch {
	case m.Type == Observer || m.Type == Advisor || m.Type == Guard:
	case reservedTypes[m.Type]:
		return nil, fmt.Errorf("plugin.toml: %s plugins need a later vpnw; this one runs observer, advisor and guard plugins", m.Type)
	default:
		return nil, fmt.Errorf("plugin.toml: unknown type %q (observer, advisor or guard)", m.Type)
	}
	if m.Description, err = str("description", false); err != nil {
		return nil, err
	}
	if len(m.Description) > 200 || clean(m.Description, 200) != m.Description {
		return nil, fmt.Errorf("plugin.toml: description must be one line of at most 200 characters, with no control characters")
	}
	abi, ok := root.Keys["abi"]
	if !ok {
		return nil, fmt.Errorf("plugin.toml: abi is missing")
	}
	if abi.Kind != config.KInt {
		return nil, fmt.Errorf("plugin.toml line %d: abi must be a number", abi.Line)
	}
	m.ABI = int(abi.Int)
	if m.ABI != ABI {
		return nil, fmt.Errorf("plugin.toml: built for plugin ABI %d; this vpnw runs ABI %d", m.ABI, ABI)
	}
	if v, ok := root.Keys["permissions"]; ok {
		if v.Kind != config.KArray {
			return nil, fmt.Errorf("plugin.toml line %d: permissions must be a list of strings", v.Line)
		}
		seen := map[string]bool{}
		for _, p := range v.Arr {
			if p.Kind != config.KString {
				return nil, fmt.Errorf("plugin.toml line %d: permissions must be a list of strings", v.Line)
			}
			if _, ok := knownPerms[p.Str]; !ok {
				return nil, fmt.Errorf("plugin.toml line %d: unknown permission %q (known: %s)", v.Line, p.Str, strings.Join(permNames(), ", "))
			}
			if !seen[p.Str] {
				m.Permissions = append(m.Permissions, p.Str)
				seen[p.Str] = true
			}
		}
	}
	return m, nil
}

func permNames() []string { return []string{PermConsole, PermEmit} }
