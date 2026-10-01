package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/secret"
)

// authRefreshServer serves a login endpoint that mints a session cookie and a
// validation endpoint gated by it — a faithful cookie-session app.
func authRefreshServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "fresh-valid"})
			w.WriteHeader(200)
			w.Write([]byte("logged in"))
		case "/me":
			if c, err := r.Cookie("session"); err == nil && c.Value == "fresh-valid" {
				w.Write([]byte(repeatX(200) + "\nusername: alice"))
				return
			}
			http.Error(w, "login required", http.StatusUnauthorized)
		default:
			w.WriteHeader(200)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func seedRefreshIdentity(t *testing.T, db *database.DB, tid, strategy, rawReq, validationURL string) string {
	t.Helper()
	box := secret.New("")
	id := uuid.NewString()
	// Starts with a STALE cookie (expired session) so validation fails pre-refresh.
	hjson := box.Encrypt(`{"Cookie":"session=stale-dead"}`)
	rr := ""
	if rawReq != "" {
		rr = box.Encrypt(rawReq)
	}
	if _, err := db.Exec(`INSERT INTO identities
		(id,target_id,label,role,headers_json,is_baseline,auth_method,validation_url,validation_signal,status,refresh_strategy,refresh_request)
		VALUES (?,?,?,?,?,1,'headers',?,?, 'expired', ?, ?)`,
		id, tid, "user", "user", hjson, validationURL, "username: alice", strategy, rr); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestRefreshSessionReplayRestoresSession(t *testing.T) {
	withLoopbackAllowed(t)
	base := authRefreshServer(t)
	db, tid := preflightDB(t)
	// Absolute request line so the replay keeps the http scheme (not the https default).
	hostPort := strings.TrimPrefix(base, "http://")
	rawReq := fmt.Sprintf("GET %s/login HTTP/1.1\r\nHost: %s\r\n\r\n", base, hostPort)
	id := seedRefreshIdentity(t, db, tid, RefreshReplay, rawReq, base+"/me")

	identity := Identity{ID: id, Label: "user", Headers: map[string]string{"Cookie": "session=stale-dead"},
		ValidationURL: base + "/me", ValidationSignal: "username: alice"}

	state, ok := RefreshSession(context.Background(), db, secret.New(""), tid, identity)
	if !ok || state != SessHealthy {
		t.Fatalf("replay refresh must restore the session, got state=%q ok=%v", state, ok)
	}

	// The refreshed cookie must be persisted (and a refresh event recorded).
	var attempts int
	db.QueryRow(`SELECT refresh_attempts FROM identities WHERE id=?`, id).Scan(&attempts)
	if attempts < 1 {
		t.Errorf("refresh_attempts should have incremented, got %d", attempts)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM auth_events WHERE target_id=? AND event=?`, tid, AuthEventRefreshed).Scan(&n)
	if n == 0 {
		t.Error("a 'refreshed' auth event should have been recorded")
	}
}

func TestRefreshSessionNoneStrategyStaysExpired(t *testing.T) {
	withLoopbackAllowed(t)
	db, tid := preflightDB(t)
	id := seedRefreshIdentity(t, db, tid, RefreshNone, "", "http://unused.test/me")
	identity := Identity{ID: id, Label: "user", Headers: map[string]string{"Cookie": "session=stale-dead"}}
	if state, ok := RefreshSession(context.Background(), db, secret.New(""), tid, identity); ok || state != SessExpired {
		t.Fatalf("none strategy must not refresh, got state=%q ok=%v", state, ok)
	}
}

func TestRefreshSessionManualStrategyIsRefreshRequired(t *testing.T) {
	withLoopbackAllowed(t)
	db, tid := preflightDB(t)
	id := seedRefreshIdentity(t, db, tid, RefreshManual, "", "http://unused.test/me")
	identity := Identity{ID: id, Label: "user"}
	if state, ok := RefreshSession(context.Background(), db, secret.New(""), tid, identity); ok || state != SessRefreshRequired {
		t.Fatalf("manual strategy must report refresh_required, got state=%q ok=%v", state, ok)
	}
}
