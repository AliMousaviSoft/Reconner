package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/secret"
)

func TestAuthGateNoIdentitiesIsReady(t *testing.T) {
	db, tid := preflightDB(t)
	ready, configured, _ := AuthGate(context.Background(), db, secret.New(""), tid)
	if !ready || configured {
		t.Fatalf("no identities → ready, not configured; got ready=%v configured=%v", ready, configured)
	}
}

func TestAuthGateHealthyIsReady(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err == nil && c.Value == "live" {
			w.Write([]byte(repeatX(200) + "\nusername: alice"))
			return
		}
		http.Error(w, "login", http.StatusUnauthorized)
	}))
	defer srv.Close()
	db, tid := preflightDB(t)
	box := secret.New("")
	id := uuid.NewString()
	hjson := box.Encrypt(`{"Cookie":"session=live"}`)
	if _, err := db.Exec(`INSERT INTO identities (id,target_id,label,role,headers_json,is_baseline,validation_url,validation_signal)
		VALUES (?,?,?,?,?,1,?,?)`, id, tid, "user", "user", hjson, srv.URL+"/me", "username: alice"); err != nil {
		t.Fatal(err)
	}
	ready, configured, state := AuthGate(context.Background(), db, box, tid)
	if !ready || !configured || state != SessHealthy {
		t.Fatalf("healthy session → ready+configured+healthy; got ready=%v configured=%v state=%q", ready, configured, state)
	}
}

func TestAuthGateExpiredUnrefreshableBlocks(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "login required", http.StatusUnauthorized) // always denies → session is dead
	}))
	defer srv.Close()
	db, tid := preflightDB(t)
	box := secret.New("")
	id := uuid.NewString()
	hjson := box.Encrypt(`{"Cookie":"session=dead"}`)
	// refresh_strategy none → cannot self-heal.
	if _, err := db.Exec(`INSERT INTO identities (id,target_id,label,role,headers_json,is_baseline,validation_url,validation_signal,refresh_strategy)
		VALUES (?,?,?,?,?,1,?,?, 'none')`, id, tid, "user", "user", hjson, srv.URL+"/me", "username: alice"); err != nil {
		t.Fatal(err)
	}
	ready, configured, state := AuthGate(context.Background(), db, box, tid)
	if ready || !configured {
		t.Fatalf("expired un-refreshable → NOT ready but configured; got ready=%v configured=%v", ready, configured)
	}
	if state != SessExpired && state != SessRefreshFailed {
		t.Errorf("state = %q, want expired/refresh_failed", state)
	}
	// A blocked auth event must be recorded (explicit, not silent).
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM auth_events WHERE target_id=? AND event=?`, tid, AuthEventBlocked).Scan(&n)
	if n == 0 {
		t.Error("a 'blocked' auth event must be recorded when the gate fails closed")
	}
}
