package scanner

import "testing"

func TestNcrackExtractorMatchesOnlyItsOwnService(t *testing.T) {
	rdp := ncrackExtractor("rdp")
	out := "Discovered credentials on rdp://10.0.0.5:3389 'Administrator' 'Passw0rd!'\n"
	res, ok := rdp(out)
	if !ok || res.User != "Administrator" || res.Pass != "Passw0rd!" {
		t.Fatalf("rdp extractor = %+v, ok=%v", res, ok)
	}

	// The two-line final-summary variant must also match.
	summary := "Discovered credentials for vnc on 10.0.0.5 5900/tcp:\n10.0.0.5 5900/tcp vnc: '' 'letmein123'\n"
	vnc := ncrackExtractor("vnc")
	res2, ok2 := vnc(summary)
	if !ok2 || res2.Pass != "letmein123" {
		t.Fatalf("vnc summary extractor = %+v, ok=%v", res2, ok2)
	}

	// An rdp hit must never satisfy the vnc extractor, and vice versa.
	if _, ok := vnc(out); ok {
		t.Error("vnc extractor matched an rdp line — cross-protocol false positive")
	}
	if _, ok := rdp(summary); ok {
		t.Error("rdp extractor matched a vnc line — cross-protocol false positive")
	}
}

func TestNcrackExtractorIgnoresUnrelatedOutput(t *testing.T) {
	rdp := ncrackExtractor("rdp")
	if _, ok := rdp("Starting Ncrack 0.7 at 2026-01-01\nStats: 00:00:05 elapsed\n"); ok {
		t.Error("ordinary progress output must never be reported as a hit")
	}
}

func TestHydraExtractorMatchesCanonicalSuccessLine(t *testing.T) {
	line := "[445][smb2] host: 10.0.0.9   login: administrator   password: hunter2\n"
	res, ok := hydraExtractor(line)
	if !ok || res.User != "administrator" || res.Pass != "hunter2" {
		t.Fatalf("hydra extractor = %+v, ok=%v", res, ok)
	}
}

func TestHydraExtractorIgnoresProgressOutput(t *testing.T) {
	if _, ok := hydraExtractor("[STATUS] 14.00 tries/min, 14 tries in 00:01h\n"); ok {
		t.Error("ordinary progress output must never be reported as a hit")
	}
	// A line merely mentioning "login:"/"password:" out of hydra's exact
	// bracketed format must not match either.
	if _, ok := hydraExtractor("some unrelated login: x password: y line\n"); ok {
		t.Error("a non-canonical line must never be reported as a hit")
	}
}
