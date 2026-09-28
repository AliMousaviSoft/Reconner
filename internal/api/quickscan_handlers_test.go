package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
)

func newQuickScanTestHandler(t *testing.T) (*database.DB, *Handler) {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "quickscan-api.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	return db, &Handler{db: db, cfg: &config.Config{SessionSecret: "quickscan-test-secret"}}
}

// A pasted raw request with a query parameter must produce a working
// project: a targets row scoped to the request's own URL, one sealed
// capture template, and at least one automatically-classified vulnerability
// class (xss/sqli on a query parameter is unambiguous). The scheduler is
// nil in this test (as in every other guided-handler test in this package),
// so queueing itself is not exercised here -- the handler must degrade
// gracefully rather than fail the whole request when h.sched is unavailable.
func TestHandleQuickScanCreatesProjectAndClassifiesFromRawRequest(t *testing.T) {
	db, h := newQuickScanTestHandler(t)
	raw := "GET /search?q=test HTTP/1.1\r\nHost: shop.example.test\r\n\r\n"
	body, _ := json.Marshal(map[string]string{"raw_request": raw, "name": "quick scan test"})
	req := httptest.NewRequest(http.MethodPost, "/api/targets/quick-scan", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.handleQuickScan(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			TargetID        string   `json:"target_id"`
			CaptureID       string   `json:"capture_id"`
			TemplateID      string   `json:"template_id"`
			ModulesDetected []string `json:"modules_detected"`
			ModulesQueued   int      `json:"modules_queued"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("could not decode response: %v body=%s", err, rec.Body.String())
	}
	if resp.Data.TargetID == "" || resp.Data.CaptureID == "" || resp.Data.TemplateID == "" {
		t.Fatalf("missing IDs in response: %+v", resp.Data)
	}
	if len(resp.Data.ModulesDetected) == 0 {
		t.Fatalf("expected at least one auto-classified module for a query-parameter request, got none")
	}

	var domain, name string
	if err := db.QueryRow(`SELECT domain,name FROM targets WHERE id=?`, resp.Data.TargetID).Scan(&domain, &name); err != nil {
		t.Fatalf("target row not found: %v", err)
	}
	if domain != "https://shop.example.test/search?q=test" || name != "quick scan test" {
		t.Fatalf("target domain=%q name=%q, want the request's own URL and given name", domain, name)
	}
	var templateCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM request_templates WHERE target_id=? AND capture_session_id=?`, resp.Data.TargetID, resp.Data.CaptureID).Scan(&templateCount); err != nil || templateCount != 1 {
		t.Fatalf("expected exactly one sealed request template, count=%d err=%v", templateCount, err)
	}
}

// A raw request with no Host header and no absolute URL cannot be scoped to
// any project and must be rejected with a clear error, not silently create
// an unusable project.
func TestHandleQuickScanRejectsUnresolvableHost(t *testing.T) {
	_, h := newQuickScanTestHandler(t)
	body, _ := json.Marshal(map[string]string{"raw_request": "GET / HTTP/1.1\r\n\r\n"})
	req := httptest.NewRequest(http.MethodPost, "/api/targets/quick-scan", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.handleQuickScan(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400 for an unresolvable host", rec.Code, rec.Body.String())
	}
}

// A request with no testable insertion points (a bare GET to a static path,
// no query/body/JSON) must still create the project -- just with zero
// modules queued and a clear explanation, not an error.
func TestHandleQuickScanHandlesRequestWithNoTestableSurface(t *testing.T) {
	db, h := newQuickScanTestHandler(t)
	body, _ := json.Marshal(map[string]string{"raw_request": "GET /health HTTP/1.1\r\nHost: shop.example.test\r\n\r\n"})
	req := httptest.NewRequest(http.MethodPost, "/api/targets/quick-scan", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.handleQuickScan(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			TargetID      string `json:"target_id"`
			ModulesQueued int    `json:"modules_queued"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.TargetID == "" {
		t.Fatal("expected the project to still be created")
	}
	if resp.Data.ModulesQueued != 0 {
		t.Fatalf("modules_queued=%d, want 0 for a request with no testable surface", resp.Data.ModulesQueued)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM targets WHERE id=?`, resp.Data.TargetID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("target row missing: count=%d err=%v", count, err)
	}
}
