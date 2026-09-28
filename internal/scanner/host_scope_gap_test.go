package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
)

// IDOR's collectTargets and its authz-crawl seed query read http_services/
// parameters directly by target_id with no host-scope filter, so a per-asset scan
// (WithHostScope) silently leaked into testing the WHOLE target instead of just
// the one asset the operator scoped the scan to. Covers both raw queries in
// idor.go's collectTargets (path-based and param-based ID discovery).
func TestIDORCollectTargetsRespectsHostScope(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()

	if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code) VALUES
		(?,?,?,200), (?,?,?,200)`,
		uuid.NewString(), tid, "https://in-scope.example.test/items/1052",
		uuid.NewString(), tid, "https://out-of-scope.example.test/items/2064"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO parameters (id,target_id,url,parameter,value,source) VALUES
		(?,?,?,?,?, 'test'), (?,?,?,?,?, 'test')`,
		uuid.NewString(), tid, "https://in-scope.example.test/order?order_id=101", "order_id", "101",
		uuid.NewString(), tid, "https://out-of-scope.example.test/order?order_id=202", "order_id", "202"); err != nil {
		t.Fatal(err)
	}

	s := &IDORScanner{db: db, cfg: &config.Config{}}
	ctx := WithHostScope(context.Background(), []string{"in-scope.example.test"})

	targets := s.collectTargets(ctx, tid)
	if len(targets) == 0 {
		t.Fatal("expected the in-scope targets to be present")
	}
	for _, tg := range targets {
		if strings.Contains(tg.template, "out-of-scope") {
			t.Fatalf("out-of-scope path target leaked into a host-scoped IDOR scan: %+v", tg)
		}
		if tg.kind == "param" && tg.baseID == 202 {
			t.Fatalf("out-of-scope param target (order_id=202) leaked into a host-scoped IDOR scan: %+v", tg)
		}
	}
	foundInScopePath := false
	foundInScopeParam := false
	for _, tg := range targets {
		if tg.kind == "path" && strings.Contains(tg.template, "in-scope") {
			foundInScopePath = true
		}
		if tg.kind == "param" && tg.baseID == 101 {
			foundInScopeParam = true
		}
	}
	if !foundInScopePath || !foundInScopeParam {
		t.Fatalf("expected both in-scope path and param targets, got %+v", targets)
	}
}

// Smuggling's aliveRoots also read http_services with no host-scope filter.
func TestSmugglingAliveRootsRespectsHostScope(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()

	if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,source) VALUES
		(?,?,?,200,'probe'), (?,?,?,200,'probe')`,
		uuid.NewString(), tid, "https://in-scope.example.test/",
		uuid.NewString(), tid, "https://out-of-scope.example.test/"); err != nil {
		t.Fatal(err)
	}

	s := &SmugglingScanner{db: db}
	ctx := WithHostScope(context.Background(), []string{"in-scope.example.test"})

	roots := s.aliveRoots(ctx, tid)
	if len(roots) == 0 {
		t.Fatal("expected the in-scope root to be present")
	}
	for _, r := range roots {
		if strings.Contains(r, "out-of-scope") {
			t.Fatalf("out-of-scope root leaked into a host-scoped smuggling scan: %q (roots=%v)", r, roots)
		}
	}
}
