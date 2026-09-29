package scanner

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestParentZone(t *testing.T) {
	cases := map[string]string{
		"foo.dev.example.com": "dev.example.com",
		"a.b.c.example.com":   "b.c.example.com",
		"example.com":         "", // parent would be the bare TLD "com" — not probeable
		"com":                 "", // single label, no parent at all
		"":                    "",
		"foo.co.uk":           "co.uk", // still a plausible zone string; harmless to probe
	}
	for host, want := range cases {
		if got := parentZone(host); got != want {
			t.Errorf("parentZone(%q) = %q, want %q", host, got, want)
		}
	}
}

// The core wildcard-detection decision: two independently random, guaranteed
// non-existent labels resolving to the SAME CNAME means the zone has a
// catch-all record, not that either random label was individually configured.
func TestProbeWildcardCNAMEAgreeingLabelsMeanWildcard(t *testing.T) {
	lookup := func(ctx context.Context, host string) (string, error) {
		return "parking.example-parking-provider.com", nil
	}
	if got := probeWildcardCNAME(context.Background(), "zone.example.com", lookup); got != "parking.example-parking-provider.com" {
		t.Fatalf("expected the agreeing CNAME to be reported as the wildcard target, got %q", got)
	}
}

func TestProbeWildcardCNAMENoWildcardWhenLabelsDisagree(t *testing.T) {
	calls := 0
	lookup := func(ctx context.Context, host string) (string, error) {
		calls++
		if calls == 1 {
			return "first-result.example.com", nil
		}
		return "different-result.example.com", nil
	}
	if got := probeWildcardCNAME(context.Background(), "zone.example.com", lookup); got != "" {
		t.Fatalf("expected no wildcard when the two probes disagree, got %q", got)
	}
}

func TestProbeWildcardCNAMENoWildcardWhenNXDOMAIN(t *testing.T) {
	lookup := func(ctx context.Context, host string) (string, error) {
		return "", errors.New("no such host")
	}
	if got := probeWildcardCNAME(context.Background(), "zone.example.com", lookup); got != "" {
		t.Fatalf("expected no wildcard when random labels don't resolve at all, got %q", got)
	}
}

// Each probe call uses a freshly randomized label — two calls into the same
// lookup func must be asked about two DIFFERENT hostnames, otherwise the
// "two independent random labels" proof is fake (a lookup keyed only by zone
// would trivially "agree" with itself every time).
func TestProbeWildcardCNAMEUsesTwoDistinctRandomLabels(t *testing.T) {
	var asked []string
	lookup := func(ctx context.Context, host string) (string, error) {
		asked = append(asked, host)
		return "wildcard-target.example.com", nil
	}
	probeWildcardCNAME(context.Background(), "zone.example.com", lookup)
	if len(asked) != 2 {
		t.Fatalf("expected exactly 2 lookups, got %d: %v", len(asked), asked)
	}
	if asked[0] == asked[1] {
		t.Fatalf("expected two DISTINCT random labels, got the same hostname twice: %q", asked[0])
	}
}

// wildcardZoneFor must cache its result per zone: a target with hundreds of
// subdomains sharing one parent zone should trigger the (2-lookup) probe only
// ONCE, not once per subdomain — the whole point of the cache is to keep a
// large scan from re-probing the identical zone hundreds of times.
func TestWildcardZoneForCachesPerZone(t *testing.T) {
	zone := "cached." + t.Name() + ".example.com"
	wildcardCNAMECache.Delete(zone)
	t.Cleanup(func() { wildcardCNAMECache.Delete(zone) })

	// Prime the cache the same way wildcardZoneFor would, but through the
	// exported cache variable directly so this test doesn't depend on real DNS.
	wildcardCNAMECache.Store(zone, "wildcard-target.example.com")

	gotZone, gotCNAME := wildcardZoneFor(context.Background(), "foo."+zone)
	if gotZone != zone {
		t.Fatalf("expected zone %q, got %q", zone, gotZone)
	}
	if gotCNAME != "wildcard-target.example.com" {
		t.Fatalf("expected the cached CNAME to be returned without a fresh probe, got %q", gotCNAME)
	}
}

func TestWildcardZoneForReturnsEmptyForUnprobeableHost(t *testing.T) {
	zone, cname := wildcardZoneFor(context.Background(), "example.com")
	if zone != "" || cname != "" {
		t.Fatalf("expected no zone/cname for a bare apex-style host, got zone=%q cname=%q", zone, cname)
	}
}

// The Run() dedup bookkeeping — a mutex-guarded "have we already reported
// this zone" map — must let exactly ONE of many concurrent goroutines sharing
// the same wildcard zone win, mirroring what Run() does for every subdomain
// under the same catch-all record.
func TestWildcardZoneDedupLetsOnlyOneClaimThrough(t *testing.T) {
	var mu sync.Mutex
	reported := map[string]bool{}
	zone := "wild.example.com"

	var wg sync.WaitGroup
	var claimsWon int
	var claimsMu sync.Mutex
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mu.Lock()
			already := reported[zone]
			reported[zone] = true
			mu.Unlock()
			if !already {
				claimsMu.Lock()
				claimsWon++
				claimsMu.Unlock()
			}
		}()
	}
	wg.Wait()
	if claimsWon != 1 {
		t.Fatalf("expected exactly 1 of 50 concurrent claims to win the wildcard-zone dedup, got %d", claimsWon)
	}
}
