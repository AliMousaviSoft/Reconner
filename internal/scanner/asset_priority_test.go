package scanner

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func seedSubdomain(t *testing.T, dbTID string, exec func(query string, args ...any) error, host string, alive bool, status int, title, server, tech, waf, source string) {
	t.Helper()
	aliveInt := 0
	if alive {
		aliveInt = 1
	}
	if err := exec(`INSERT INTO subdomains (id,target_id,subdomain,is_alive,status_code,page_title,server,technologies,waf,source) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		uuid.NewString(), dbTID, host, aliveInt, status, title, server, tech, waf, source); err != nil {
		t.Fatal(err)
	}
}

// The main/apex domain must always sort first, even against a subdomain that
// scores far higher on every other signal (admin panel, interesting name,
// parameters) — this is an explicit, non-negotiable requirement: the primary
// asset of a program is always the first thing tested.
func TestComputeAssetPriorityMainDomainAlwaysFirst(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	if _, err := db.Exec(`UPDATE targets SET domain=? WHERE id=?`, "example.test", tid); err != nil {
		t.Fatal(err)
	}
	exec := func(q string, args ...any) error { _, err := db.Exec(q, args...); return err }

	seedSubdomain(t, tid, exec, "example.test", true, 200, "Example Corp — Home", "nginx", "[]", "", "dns")
	seedSubdomain(t, tid, exec, "admin.example.test", true, 200, "Admin Login", "nginx", `["jenkins"]`, "", "dns")
	if _, err := db.Exec(`INSERT INTO admin_panel_findings (id,target_id,url,status_code,panel_type,product,title,group_key) VALUES (?,?,?,?,?,?,?,?)`,
		uuid.NewString(), tid, "https://admin.example.test/", 200, "jenkins", "Jenkins", "Admin Login", "g1"); err != nil {
		t.Fatal(err)
	}

	plan, err := ComputeAssetPriority(context.Background(), db, tid)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Ordered) < 2 {
		t.Fatalf("expected at least 2 ordered assets, got %+v", plan.Ordered)
	}
	if plan.Ordered[0].Host != "example.test" || !plan.Ordered[0].IsMainDomain {
		t.Fatalf("main domain must be first regardless of score; got order %+v", plan.Ordered)
	}
	// admin.example.test should still score well above a boring subdomain would,
	// even though it lost the #1 spot to the main domain.
	if plan.Ordered[1].Host != "admin.example.test" {
		t.Fatalf("expected admin.example.test second (highest non-main score), got %+v", plan.Ordered)
	}
}

// Interesting-looking hosts (admin/api/staging/etc.) must outrank generic
// infrastructure hosts (cdn/static/mail/etc.) with otherwise-equal signals.
func TestComputeAssetPriorityRanksInterestingAboveGenericInfra(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	if _, err := db.Exec(`UPDATE targets SET domain=? WHERE id=?`, "example.test", tid); err != nil {
		t.Fatal(err)
	}
	exec := func(q string, args ...any) error { _, err := db.Exec(q, args...); return err }

	seedSubdomain(t, tid, exec, "api.example.test", true, 200, "API Gateway", "nginx", "[]", "", "dns")
	seedSubdomain(t, tid, exec, "cdn.example.test", true, 200, "CDN Origin", "nginx", "[]", "", "dns")

	plan, err := ComputeAssetPriority(context.Background(), db, tid)
	if err != nil {
		t.Fatal(err)
	}
	idx := map[string]int{}
	for i, a := range plan.Ordered {
		idx[a.Host] = i
	}
	if idx["api.example.test"] >= idx["cdn.example.test"] {
		t.Fatalf("api.example.test must rank above cdn.example.test, got order %+v", plan.Ordered)
	}
}

// A host that was never confirmed alive must sink to the bottom (still present
// for inventory, but heavily deprioritized) rather than competing for the same
// scan budget as a confirmed live, interesting-looking host.
func TestComputeAssetPriorityDeprioritizesDeadHosts(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	if _, err := db.Exec(`UPDATE targets SET domain=? WHERE id=?`, "example.test", tid); err != nil {
		t.Fatal(err)
	}
	exec := func(q string, args ...any) error { _, err := db.Exec(q, args...); return err }

	seedSubdomain(t, tid, exec, "dead.example.test", false, 0, "", "", "[]", "", "dns")
	seedSubdomain(t, tid, exec, "app.example.test", true, 200, "My App", "nginx", "[]", "", "dns")

	plan, err := ComputeAssetPriority(context.Background(), db, tid)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Ordered) != 2 || plan.Ordered[0].Host != "app.example.test" || plan.Ordered[1].Host != "dead.example.test" {
		t.Fatalf("expected [app, dead] order, got %+v", plan.Ordered)
	}
	if plan.Ordered[1].Score >= plan.Ordered[0].Score {
		t.Fatalf("dead host must score far below the live one: %+v", plan.Ordered)
	}
}

// Two hosts that agree on status/server/technologies/favicon/title are almost
// certainly the same application (a wildcard catch-all or a duplicate CDN edge)
// and must be collapsed to one representative for the full pipeline — testing
// both wastes the scan budget on byte-identical content.
func TestComputeAssetPriorityDedupesWildcardHosts(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	if _, err := db.Exec(`UPDATE targets SET domain=? WHERE id=?`, "example.test", tid); err != nil {
		t.Fatal(err)
	}
	exec := func(q string, args ...any) error { _, err := db.Exec(q, args...); return err }

	// Wildcard catch-all: random.example.test and other.example.test both hit
	// the same parked/default app.
	seedSubdomain(t, tid, exec, "random123.example.test", true, 200, "Parked Domain", "nginx", `["nginx"]`, "", "dns")
	seedSubdomain(t, tid, exec, "other456.example.test", true, 200, "Parked Domain", "nginx", `["nginx"]`, "", "dns")
	// A real, distinct app that happens to share status+server, but a DIFFERENT
	// title — must NOT be folded in.
	seedSubdomain(t, tid, exec, "shop.example.test", true, 200, "Shop — Checkout", "nginx", `["nginx"]`, "", "dns")

	plan, err := ComputeAssetPriority(context.Background(), db, tid)
	if err != nil {
		t.Fatal(err)
	}
	orderedHosts := map[string]bool{}
	for _, a := range plan.Ordered {
		orderedHosts[a.Host] = true
	}
	if len(plan.Ordered) != 2 {
		t.Fatalf("expected 2 distinct assets after dedup (one wildcard rep + shop), got %+v", plan.Ordered)
	}
	if !orderedHosts["shop.example.test"] {
		t.Fatalf("distinct app (different title) must not be deduped away: %+v", plan.Ordered)
	}
	if len(plan.Duplicates) != 1 {
		t.Fatalf("expected exactly 1 host collapsed as a duplicate, got %+v", plan.Duplicates)
	}
	dup := plan.Duplicates[0]
	if dup.DedupOf == "" || dup.DedupOf == dup.Host {
		t.Fatalf("duplicate must point at a different representative host: %+v", dup)
	}
	if orderedHosts[dup.Host] {
		t.Fatalf("a deduped host must not ALSO appear in Ordered: %+v / dup=%+v", plan.Ordered, dup)
	}
}

// A short interesting-name token like "cd" (meant for an exact "cd.example.
// test" CI/CD host) must NOT substring-match inside an unrelated low-value
// host like "cdn7.example.test" — that would hand a CDN node the same +25
// "interesting" bonus a real CI/CD host gets, cancelling its own low-value
// demotion and defeating the light-tier cutoff that exists to skip the full
// pipeline on exactly this kind of host.
func TestComputeAssetPriorityShortTokenRequiresWordBoundary(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	if _, err := db.Exec(`UPDATE targets SET domain=? WHERE id=?`, "example.test", tid); err != nil {
		t.Fatal(err)
	}
	exec := func(q string, args ...any) error { _, err := db.Exec(q, args...); return err }

	seedSubdomain(t, tid, exec, "cdn7.example.test", true, 200, "", "", "[]", "", "dns")
	seedSubdomain(t, tid, exec, "cd.example.test", true, 200, "", "", "[]", "", "dns")

	plan, err := ComputeAssetPriority(context.Background(), db, tid)
	if err != nil {
		t.Fatal(err)
	}
	scores := map[string]int{}
	for _, a := range plan.Ordered {
		scores[a.Host] = a.Score
	}
	if scores["cd.example.test"] <= scores["cdn7.example.test"] {
		t.Fatalf("exact 'cd' host should score above the merely-substring 'cdn7' host: %+v", scores)
	}
	if scores["cdn7.example.test"] >= 15 {
		t.Fatalf("cdn7 must stay below the light-tier score threshold (no bogus 'cd' interesting bonus), got %d", scores["cdn7.example.test"])
	}
}

// A host with no title at all (or a generic server-default title) must never
// be folded into another host just because they share status/server — the
// grouping signal is too weak to trust without real content to compare.
func TestComputeAssetPriorityNeverDedupesHostsWithoutRealTitle(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	if _, err := db.Exec(`UPDATE targets SET domain=? WHERE id=?`, "example.test", tid); err != nil {
		t.Fatal(err)
	}
	exec := func(q string, args ...any) error { _, err := db.Exec(q, args...); return err }

	seedSubdomain(t, tid, exec, "a.example.test", true, 200, "", "nginx", "[]", "", "dns")
	seedSubdomain(t, tid, exec, "b.example.test", true, 200, "", "nginx", "[]", "", "dns")

	plan, err := ComputeAssetPriority(context.Background(), db, tid)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Ordered) != 2 || len(plan.Duplicates) != 0 {
		t.Fatalf("hosts with no title must never be deduped; got ordered=%+v duplicates=%+v", plan.Ordered, plan.Duplicates)
	}
}
