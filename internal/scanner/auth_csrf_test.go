package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestExtractCSRFTokenSources(t *testing.T) {
	inputBody := `<form><input type="hidden" name="csrf_token" value="AbC123tok-ENoughLong"></form>`
	if got := extractCSRFToken(csrfSpec{Source: csrfSourceHTMLInput, Name: "csrf_token"}, inputBody); got != "AbC123tok-ENoughLong" {
		t.Errorf("html_input (name-before-value) = %q", got)
	}
	inputRev := `<input value="revOrder-TOKEN-1234" name="authenticity_token">`
	if got := extractCSRFToken(csrfSpec{Source: csrfSourceHTMLInput, Name: "authenticity_token"}, inputRev); got != "revOrder-TOKEN-1234" {
		t.Errorf("html_input (value-before-name) = %q", got)
	}
	metaBody := `<head><meta name="csrf-token" content="meta-TOKEN-5678abcd"></head>`
	if got := extractCSRFToken(csrfSpec{Source: csrfSourceHTMLMeta, Name: "csrf-token"}, metaBody); got != "meta-TOKEN-5678abcd" {
		t.Errorf("html_meta = %q", got)
	}
	jsonBody := `{"data":{"csrf":"json-TOKEN-9abcdef0"}}`
	if got := extractCSRFToken(csrfSpec{Source: csrfSourceJSON, Name: "data.csrf"}, jsonBody); got != "json-TOKEN-9abcdef0" {
		t.Errorf("json path = %q", got)
	}
	// Wrong field name must NOT match some other field's value.
	if got := extractCSRFToken(csrfSpec{Source: csrfSourceHTMLInput, Name: "nope"}, inputBody); got != "" {
		t.Errorf("mismatched name must yield empty, got %q", got)
	}
}

func TestFetchFreshCSRFEndToEnd(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Token is only served to the authenticated identity.
		if c, err := r.Cookie("session"); err != nil || c.Value != "live" {
			http.Error(w, "nope", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<form><input name="csrf_token" value="fresh-CSRF-abcdef123456"></form>`))
	}))
	defer srv.Close()

	db, tid := preflightDB(t)
	id := uuid.NewString()
	cfg := `{"url":"` + srv.URL + `/form","source":"html_input","name":"csrf_token","header":"X-CSRF-Token"}`
	if _, err := db.Exec(`INSERT INTO identities (id,target_id,label,role,headers_json,is_baseline,csrf_config)
		VALUES (?,?,?,?,?,1,?)`, id, tid, "user", "user", `{"Cookie":"session=live"}`, cfg); err != nil {
		t.Fatal(err)
	}

	identity := Identity{ID: id, Label: "user", Headers: map[string]string{"Cookie": "session=live"}}
	spec, token, ok := FetchFreshCSRF(context.Background(), db, identity)
	if !ok || token != "fresh-CSRF-abcdef123456" {
		t.Fatalf("expected a fresh CSRF token, got token=%q ok=%v", token, ok)
	}
	if spec.Header != "X-CSRF-Token" {
		t.Errorf("spec.Header = %q", spec.Header)
	}
}

func TestFetchFreshCSRFNoConfig(t *testing.T) {
	db, tid := preflightDB(t)
	id := uuid.NewString()
	if _, err := db.Exec(`INSERT INTO identities (id,target_id,label,role,headers_json,is_baseline)
		VALUES (?,?,?,?,?,1)`, id, tid, "user", "user", `{}`); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := FetchFreshCSRF(context.Background(), db, Identity{ID: id}); ok {
		t.Fatal("no csrf_config must yield ok=false")
	}
}
