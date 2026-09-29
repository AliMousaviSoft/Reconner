package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/recon-platform/internal/config"
)

// TestIDORRunFallsBackToSingleIdentityHeuristic proves IDOR still scans a
// target that only has ONE captured identity (or the legacy single
// auth_headers blob — the common case for any target set up before
// multi-identity capture existed). Run() used to require >= 2 identities just
// to start at all, so it silently produced zero IDOR coverage for every
// single-auth target; the fix falls back to the pre-existing single-account
// differential heuristic (testTarget) instead of returning BlockedPhase.
func TestIDORRunFallsBackToSingleIdentityHeuristic(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()

	// A tiny app: /items/{id} returns a distinct, substantial JSON object per id
	// when Authorization is present, and denies access without it — the exact
	// shape testTarget's auth-gate + neighbour-differential logic looks for.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/items/")
		w.Header().Set("Content-Type", "application/json")
		// testTarget requires a "substantial" baseline object (>= 120 bytes) — pad
		// generously so this clears that bar with margin.
		_, _ = fmt.Fprintf(w, `{"id":%q,"owner":"user-%s","secret_notes":"private record padding padding padding padding padding padding padding padding padding padding"}`, id, id)
	}))
	defer srv.Close()

	if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code) VALUES (?,?,?,200)`,
		"svc1", tid, srv.URL+"/items/1050"); err != nil {
		t.Fatal(err)
	}
	// Legacy single-identity setup: only targets.auth_headers is set, no rows in
	// the identities table — LoadIdentities must still surface exactly one
	// baseline identity from this fallback.
	if _, err := db.Exec(`UPDATE targets SET auth_headers = ? WHERE id = ?`,
		`{"Authorization":"Bearer testtoken"}`, tid); err != nil {
		t.Fatal(err)
	}

	s := &IDORScanner{db: db, cfg: &config.Config{}}
	var logs []string
	err := s.Run(context.Background(), tid, func(level, module, msg string) {
		logs = append(logs, msg)
	})
	if err != nil {
		t.Fatalf("Run() with a single legacy identity must not be blocked, got: %v", err)
	}

	var n int
	if scanErr := db.QueryRow(`SELECT COUNT(*) FROM candidates WHERE target_id=? AND type='idor'`, tid).Scan(&n); scanErr != nil {
		t.Fatal(scanErr)
	}
	if n == 0 {
		t.Fatalf("expected the single-identity heuristic to produce at least one IDOR candidate; logs=%v", logs)
	}
}

// TestIDORRunBlockedWithoutAnyIdentity proves the zero-identity case is still
// correctly blocked (unlike the single-identity case, there is no session to
// even tell an auth-gated object apart from a public one).
func TestIDORRunBlockedWithoutAnyIdentity(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()

	s := &IDORScanner{db: db, cfg: &config.Config{}}
	err := s.Run(context.Background(), tid, func(level, module, msg string) {})
	if err == nil {
		t.Fatal("Run() with no identity configured at all must return a blocked-phase error")
	}
}
