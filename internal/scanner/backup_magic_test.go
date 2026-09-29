package scanner

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDomainBrandNames(t *testing.T) {
	cases := map[string][]string{
		"shop.example.com":    {"shop", "example"},
		"example.com":         {"example"},
		"https://app.acme.io": {"app", "acme"},
		"www.example.co.uk":   {"www", "co"},
		"example.com:8443":    {"example"},
		"":                    nil,
	}
	for domain, want := range cases {
		got := domainBrandNames(domain)
		if len(got) != len(want) {
			t.Errorf("domainBrandNames(%q) = %v, want %v", domain, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("domainBrandNames(%q)[%d] = %q, want %q", domain, i, got[i], want[i])
			}
		}
	}
}

// The core real-world naming pattern this feature exists to catch: a backup
// named after the SITE ITSELF, combined with a backup-flavored word — not
// either alone. Proves both directions (brand+suffix and prefix+brand).
func TestGenerateBrandedBackupCandidatesCombinesBrandWithBackupWords(t *testing.T) {
	got := generateBrandedBackupCandidates([]string{"acmecorp"}, 5)
	want := []string{
		"/acmecorp_backup.zip", "/acmecorp-backup.zip", "/acmecorp_bak.zip",
		"/acmecorp_old.zip", "/acmecorp_db.sql", "/acmecorp_dump.sql",
		"/backup_acmecorp.zip", "/backup-acmecorp.zip", "/old_acmecorp.zip", "/db_acmecorp.sql",
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected branded candidate %q, got %v", w, got)
		}
	}
}

func TestGenerateBrandedBackupCandidatesIncludesDatedVariants(t *testing.T) {
	got := generateBrandedBackupCandidates([]string{"acmecorp"}, 5)
	year := strconv.Itoa(time.Now().Year())
	wantSubstr := "acmecorp_" + year + ".zip"
	found := false
	for _, g := range got {
		if strings.Contains(g, wantSubstr) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a dated branded candidate containing %q, got %v", wantSubstr, got)
	}
}

func TestGenerateBrandedBackupCandidatesRespectsLimitAndDedup(t *testing.T) {
	words := []string{"one", "two", "three", "four", "five"}
	got := generateBrandedBackupCandidates(words, 2)
	for _, g := range got {
		if strings.Contains(g, "three") || strings.Contains(g, "four") || strings.Contains(g, "five") {
			t.Fatalf("expected only the first 2 brand words to be used, got candidate %q", g)
		}
	}
	seen := map[string]bool{}
	for _, g := range got {
		if seen[g] {
			t.Fatalf("duplicate branded candidate %q", g)
		}
		seen[g] = true
	}
}

func TestGenerateBrandedBackupCandidatesRejectsNoiseWords(t *testing.T) {
	// A word that fails normalizeAdaptiveWord (too short, all-digits, etc.)
	// must not leak through into a candidate path.
	got := generateBrandedBackupCandidates([]string{"ab", "12345", "ok"}, 5)
	for _, g := range got {
		if strings.Contains(g, "/ab_") || strings.HasPrefix(g, "/ab.") || strings.Contains(g, "12345") {
			t.Fatalf("expected noise words to be rejected, got candidate %q", g)
		}
	}
}

// generateBackupCandidates must still work after being refactored onto the
// shared domainBrandNames helper — same domain-derived names as before.
func TestGenerateBackupCandidatesStillUsesDomainBrandNames(t *testing.T) {
	got := generateBackupCandidates("shop.example.com")
	for _, want := range []string{"/shop.zip", "/example.zip"} {
		found := false
		for _, g := range got {
			if g == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected domain-derived candidate %q, got missing from %d candidates", want, len(got))
		}
	}
}
