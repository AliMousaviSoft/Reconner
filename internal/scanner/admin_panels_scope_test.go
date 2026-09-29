package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
)

// classifyStoredServicePanels (part of DirScanner — a per-asset module) queried
// the whole http_services table with no host-scope filter, so a per-asset
// prioritized scan scoped to one host still recorded admin-panel findings for
// every OTHER host in the target (and re-scanned all services once per asset).
// This is the same scope-leak class already fixed for IDOR/smuggling. The fix
// makes it honor the ctx host scope; this test proves an out-of-scope service is
// no longer classified while the in-scope one still is.
func TestClassifyStoredServicePanelsRespectsHostScope(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()

	// Both are unambiguous admin panels (high-signal title, HTTP 200).
	if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,title) VALUES
		(?,?,?,200,?), (?,?,?,200,?)`,
		uuid.NewString(), tid, "https://in-scope.example.test/", "Admin Login",
		uuid.NewString(), tid, "https://out-of-scope.example.test/", "Admin Login"); err != nil {
		t.Fatal(err)
	}

	s := &DirScanner{db: db, cfg: &config.Config{}}
	ctx := WithHostScope(context.Background(), []string{"in-scope.example.test"})
	s.classifyStoredServicePanels(ctx, tid)

	rows, err := db.Query(`SELECT url FROM admin_panel_findings WHERE target_id=?`, tid)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var urls []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) == nil {
			urls = append(urls, u)
		}
	}
	if len(urls) != 1 || !strings.Contains(urls[0], "in-scope") {
		t.Fatalf("expected exactly the in-scope admin panel to be recorded, got %v", urls)
	}
}

// The same method with NO host scope set (a full-target scan) must still
// classify every stored service — urlHostInScope is a no-op when scope is unset.
func TestClassifyStoredServicePanelsUnscopedClassifiesAll(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()

	if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,title) VALUES
		(?,?,?,200,?), (?,?,?,200,?)`,
		uuid.NewString(), tid, "https://a.example.test/", "Admin Login",
		uuid.NewString(), tid, "https://b.example.test/", "Administrator Login"); err != nil {
		t.Fatal(err)
	}

	s := &DirScanner{db: db, cfg: &config.Config{}}
	s.classifyStoredServicePanels(context.Background(), tid)

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM admin_panel_findings WHERE target_id=?`, tid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("a full-target scan must classify all stored admin panels, got %d", n)
	}
}
