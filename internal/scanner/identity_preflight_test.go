package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/secret"
	"github.com/recon-platform/pkg/logger"
)

func preflightDB(t *testing.T) (*database.DB, string) {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "pf.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	tid := uuid.New().String()
	if _, err := db.Exec(`INSERT INTO targets (id, domain, priority) VALUES (?,?, 'medium')`, tid, "lab.local"); err != nil {
		t.Fatal(err)
	}
	return db, tid
}

func seedIdentity(t *testing.T, db *database.DB, tid, label, authz, validationURL, signal string) {
	t.Helper()
	box := secret.New("") // cfg.SessionSecret is "" in the test scanner
	hjson := box.Encrypt(`{"Authorization":"` + authz + `"}`)
	if _, err := db.Exec(`INSERT INTO identities
		(id, target_id, label, role, headers_json, is_baseline, auth_method, validation_url, validation_signal, status)
		VALUES (?,?,?,?,?,?, 'headers', ?, ?, 'unknown')`,
		uuid.New().String(), tid, label, "user", hjson, 0, validationURL, signal); err != nil {
		t.Fatal(err)
	}
}

// A provably-expired session must be reported and its status persisted, while a
// live one must not raise the alarm — so the operator learns the login is dead
// before the scan wastes itself, with no false alarm on a healthy session.
func TestPreflightSessionsDetectsExpiry(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer live" {
			_, _ = w.Write([]byte(repeatX(200) + "\nusername: alice"))
			return
		}
		http.Error(w, "login required", http.StatusUnauthorized)
	}))
	defer srv.Close()

	db, tid := preflightDB(t)
	seedIdentity(t, db, tid, "live-user", "Bearer live", srv.URL+"/me", "username: alice")
	seedIdentity(t, db, tid, "dead-user", "Bearer stale", srv.URL+"/me", "username: alice")

	s := NewHTTPScanner(db, nil, &config.Config{}, logger.New("error"))
	expired := PreflightSessions(context.Background(), s, tid, func(_, _, _ string) {})
	if expired != 1 {
		t.Fatalf("expected exactly 1 expired session, got %d", expired)
	}

	// Status must be persisted for both identities.
	var liveStatus, deadStatus string
	db.QueryRow(`SELECT status FROM identities WHERE label='live-user'`).Scan(&liveStatus)
	db.QueryRow(`SELECT status FROM identities WHERE label='dead-user'`).Scan(&deadStatus)
	if liveStatus != "authenticated" {
		t.Errorf("live identity status = %q, want authenticated", liveStatus)
	}
	if deadStatus != "expired" {
		t.Errorf("dead identity status = %q, want expired", deadStatus)
	}
}

// No configured identities → unauthenticated scan → preflight is a silent no-op.
func TestPreflightSessionsNoIdentities(t *testing.T) {
	db, tid := preflightDB(t)
	s := NewHTTPScanner(db, nil, &config.Config{}, logger.New("error"))
	if n := PreflightSessions(context.Background(), s, tid, func(_, _, _ string) {}); n != 0 {
		t.Fatalf("no identities must yield 0 expired, got %d", n)
	}
}

func repeatX(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'x'
	}
	return string(b)
}
