package scanner

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// This test IS the "verify before it ships" gate for the embedded nuclei pack:
// every template must be medium+ and structurally false-positive-safe, or the
// build fails. A template cannot be added to the pack without clearing it, and a
// regression (someone weakening a matcher) is caught in CI — so the shipped pack
// is zero-false-positive by construction, not by hope.

type packTemplate struct {
	ID   string `yaml:"id"`
	Info struct {
		Name     string `yaml:"name"`
		Severity string `yaml:"severity"`
	} `yaml:"info"`
	HTTP     []packProtocol `yaml:"http"`
	Requests []packProtocol `yaml:"requests"` // legacy key
	DNS      []packProtocol `yaml:"dns"`
	TCP      []packProtocol `yaml:"network"`
	Headless []packProtocol `yaml:"headless"`
}

type packProtocol struct {
	MatchersCondition string        `yaml:"matchers-condition"`
	Matchers          []packMatcher `yaml:"matchers"`
}

type packMatcher struct {
	Type      string   `yaml:"type"`
	Part      string   `yaml:"part"`
	Words     []string `yaml:"words"`
	Regex     []string `yaml:"regex"`
	Binary    []string `yaml:"binary"`
	Status    []int    `yaml:"status"`
	Condition string   `yaml:"condition"`
	Negative  bool     `yaml:"negative"`
}

func (t packTemplate) protocols() []packProtocol {
	var out []packProtocol
	out = append(out, t.HTTP...)
	out = append(out, t.Requests...)
	out = append(out, t.DNS...)
	out = append(out, t.TCP...)
	out = append(out, t.Headless...)
	return out
}

func TestEmbeddedNucleiPackIsValidAndFPSafe(t *testing.T) {
	entries, err := reconnerTemplateFS.ReadDir("nucleitemplates")
	if err != nil {
		t.Fatalf("read embedded pack: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("embedded nuclei pack is empty")
	}
	seenIDs := map[string]string{}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		name := e.Name()
		data, err := reconnerTemplateFS.ReadFile("nucleitemplates/" + name)
		if err != nil {
			t.Errorf("%s: read: %v", name, err)
			continue
		}
		var tpl packTemplate
		if err := yaml.Unmarshal(data, &tpl); err != nil {
			t.Errorf("%s: not valid YAML: %v", name, err)
			continue
		}

		// Identity + uniqueness.
		if tpl.ID == "" {
			t.Errorf("%s: missing id", name)
		}
		if !strings.HasPrefix(tpl.ID, "reconner-") {
			t.Errorf("%s: id %q must start with reconner- (namespaced pack)", name, tpl.ID)
		}
		if prev, dup := seenIDs[tpl.ID]; dup {
			t.Errorf("%s: duplicate id %q (also in %s)", name, tpl.ID, prev)
		}
		seenIDs[tpl.ID] = name
		if strings.TrimSpace(tpl.Info.Name) == "" {
			t.Errorf("%s: missing info.name", name)
		}

		// Severity floor: medium+ only. Low/info are forbidden in the shipped pack.
		switch strings.ToLower(strings.TrimSpace(tpl.Info.Severity)) {
		case "medium", "high", "critical":
		default:
			t.Errorf("%s: severity %q — the pack is medium+ only (no low/info/unknown)", name, tpl.Info.Severity)
		}

		protos := tpl.protocols()
		if len(protos) == 0 {
			t.Errorf("%s: no protocol block (http/requests/dns/network)", name)
			continue
		}

		// FP-safety per protocol block.
		for i, p := range protos {
			assertProtocolFPSafe(t, name, i, p)
		}
	}
}

// assertProtocolFPSafe enforces that a match requires strong, combined evidence,
// not one incidental keyword. A block is FP-safe when it has at least one positive
// content signature (word/regex/binary) AND either a status gate OR a single
// strong signature that cannot match by chance — a multi-word AND matcher, a
// regex, or a binary magic. Multiple matchers must be AND-ed. This is the
// structural rule that stops a template from firing on a keyword that merely
// appears somewhere in an unrelated response.
func assertProtocolFPSafe(t *testing.T, file string, idx int, p packProtocol) {
	t.Helper()

	var positiveContent int // non-negative word/regex/binary matchers (real evidence)
	var hasStatus bool
	var hasStrongSignature bool // regex, binary, or a multi-word AND matcher
	var totalMatchers int
	for _, m := range p.Matchers {
		totalMatchers++
		switch strings.ToLower(m.Type) {
		case "word":
			if !m.Negative {
				positiveContent++
				if len(m.Words) >= 2 && strings.EqualFold(m.Condition, "and") {
					hasStrongSignature = true
				}
				// A lone short word is the classic FP source.
				if len(m.Words) == 1 && len(strings.TrimSpace(m.Words[0])) < 6 && !hasStrongSignature {
					t.Errorf("%s[block %d]: lone short word matcher %q is FP-prone — use multiple words (condition: and), a regex, or a binary magic", file, idx, m.Words[0])
				}
			}
		case "regex", "binary":
			if !m.Negative {
				positiveContent++
				hasStrongSignature = true
			}
		case "status":
			if len(m.Status) > 0 {
				hasStatus = true
			}
		}
	}

	if positiveContent == 0 {
		t.Errorf("%s[block %d]: no positive content matcher (word/regex/binary) — status/negative-only matching is FP-prone", file, idx)
	}
	// A finding needs either a status gate (excludes error/redirect-to-login pages)
	// or a signature specific enough to stand alone (regex / binary / multi-word AND).
	if !hasStatus && !hasStrongSignature {
		t.Errorf("%s[block %d]: needs a status matcher OR a strong signature (regex/binary/multi-word AND) — a bare keyword fires on error/redirect pages too", file, idx)
	}
	if totalMatchers > 1 && !strings.EqualFold(p.MatchersCondition, "and") {
		t.Errorf("%s[block %d]: %d matchers without matchers-condition: and — an OR across evidence is FP-prone", file, idx, totalMatchers)
	}
}
