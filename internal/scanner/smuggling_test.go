package scanner

import (
	"strings"
	"testing"
)

func TestBuildSmugProbesCoversObfuscations(t *testing.T) {
	probes := buildSmugProbes("victim.example", "User-Agent: t\r\n")
	if len(probes) != len(teObfuscations)+1 {
		t.Fatalf("expected %d probes, got %d", len(teObfuscations)+1, len(probes))
	}

	names := map[string]string{}
	for _, p := range probes {
		names[p.name] = p.raw
	}
	// The classic variants plus the key obfuscations must be present.
	for _, want := range []string{
		"CL.TE/plain", "CL.TE/space-before-colon", "CL.TE/tab-after-colon",
		"CL.TE/vertical-tab", "CL.TE/dual-header", "CL.TE/obs-fold", "TE.CL",
	} {
		if _, ok := names[want]; !ok {
			t.Errorf("probe set missing %q", want)
		}
	}

	// Every CL.TE probe must declare Content-Length: 4 and carry a complete,
	// VALID chunked body — that validity is what keeps the time-based test from
	// false-positiving on an ordinary chunked-honouring server.
	for name, raw := range names {
		if !strings.HasPrefix(name, "CL.TE/") {
			continue
		}
		if !strings.Contains(raw, "Content-Length: 4\r\n") {
			t.Errorf("%s: missing CL header", name)
		}
		if !strings.HasSuffix(raw, "1\r\nA\r\n0\r\n\r\n") {
			t.Errorf("%s: must end with a complete valid chunked body", name)
		}
		if !strings.Contains(strings.ToLower(raw), "transfer-encoding") {
			t.Errorf("%s: missing Transfer-Encoding header", name)
		}
	}

	// Obfuscation bytes must actually appear (not get normalised away by the builder).
	if !strings.Contains(names["CL.TE/tab-after-colon"], "Transfer-Encoding:\tchunked") {
		t.Error("tab obfuscation byte missing")
	}
	if !strings.Contains(names["CL.TE/vertical-tab"], "\x0bchunked") {
		t.Error("vertical-tab obfuscation byte missing")
	}
	if strings.Count(names["CL.TE/dual-header"], "Transfer-Encoding") != 2 {
		t.Error("dual-header variant must carry two TE headers")
	}
}
