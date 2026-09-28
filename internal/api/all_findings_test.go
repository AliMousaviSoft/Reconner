package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/recon-platform/internal/auth"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/pkg/logger"
)

// The global Findings page (GET /findings) is the top-level "what did Reconner
// actually find" view. It must carry the reproduction payload alongside the
// evidence text -- otherwise a reviewer has no way to replay a finding from
// that page without opening the per-target detail view first.
func TestHandleListAllFindingsIncludesPayload(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "all-findings.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AdminUsername: "admin", AdminPassword: config.DefaultAdminPassword}
	a := auth.New(db, cfg)
	if err := a.EnsureAdminUser(); err != nil {
		t.Fatal(err)
	}
	var adminID int64
	if err := db.QueryRow("SELECT id FROM users WHERE username='admin'").Scan(&adminID); err != nil {
		t.Fatal(err)
	}
	h := &Handler{db: db, cfg: cfg, auth: a, logger: logger.New("error")}

	if _, err := db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t1','example.test',?)`, adminID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO vuln_findings (id, target_id, type, severity, url, parameter, payload, evidence, status)
		VALUES ('f1','t1','sqli','high','https://example.test/?id=1','id',?,'DB error triggered by boundary','finding')`,
		"1' AND (1=1)-- -"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/findings", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxUserIDKey, adminID))
	rec := httptest.NewRecorder()
	h.handleListAllFindings(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Success bool         `json:"success"`
		Data    []allFinding `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if len(resp.Data) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(resp.Data))
	}
	if resp.Data[0].Payload != "1' AND (1=1)-- -" {
		t.Fatalf("expected the finding's reproduction payload to be included, got %q", resp.Data[0].Payload)
	}
}
