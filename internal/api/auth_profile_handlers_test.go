package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Revoking a profile must mark it revoked AND wipe its stored secret material,
// and record a sanitized audit event — a revoked session can never be replayed.
func TestRevokeIdentityWipesSecretsAndAudits(t *testing.T) {
	h, _ := newIsoHandler(t)
	tid := uuid.NewString()
	if _, err := h.db.Exec(`INSERT INTO targets (id, domain) VALUES (?, 'x.test')`, tid); err != nil {
		t.Fatal(err)
	}
	iid := uuid.NewString()
	if _, err := h.db.Exec(`INSERT INTO identities
		(id,target_id,label,role,headers_json,is_baseline,refresh_strategy,refresh_request,storage_json,status)
		VALUES (?,?,?,?,?,1,'replay',?,?, 'authenticated')`,
		iid, tid, "admin", "admin", `{"Cookie":"session=secretvalue"}`, "GET /login HTTP/1.1", `{"ls":"x"}`); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/targets/"+tid+"/identities/"+iid+"/revoke", nil)
	req = mux.SetURLVars(req, map[string]string{"id": tid, "iid": iid})
	rec := httptest.NewRecorder()
	h.handleRevokeIdentity(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", rec.Code, rec.Body.String())
	}

	var status, headers, refreshReq, storage, strategy string
	if err := h.db.QueryRow(`SELECT status, headers_json, refresh_request, storage_json, refresh_strategy
		FROM identities WHERE id=?`, iid).Scan(&status, &headers, &refreshReq, &storage, &strategy); err != nil {
		t.Fatal(err)
	}
	if status != "revoked" {
		t.Errorf("status = %q, want revoked", status)
	}
	if strings.Contains(headers, "secretvalue") || refreshReq != "" || storage != "" || strategy != "none" {
		t.Errorf("secrets not wiped: headers=%q refresh=%q storage=%q strategy=%q", headers, refreshReq, storage, strategy)
	}

	// The revoke must appear in the sanitized audit timeline.
	eReq := httptest.NewRequest(http.MethodGet, "/api/targets/"+tid+"/auth-events", nil)
	eReq = mux.SetURLVars(eReq, map[string]string{"id": tid})
	eRec := httptest.NewRecorder()
	h.handleListAuthEvents(eRec, eReq)
	if eRec.Code != http.StatusOK {
		t.Fatalf("auth-events status=%d", eRec.Code)
	}
	var resp struct {
		Data []struct {
			Event  string `json:"event"`
			State  string `json:"state"`
			Detail string `json:"detail"`
		} `json:"data"`
	}
	if err := json.Unmarshal(eRec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range resp.Data {
		if e.Event == "revoked" {
			found = true
		}
		if strings.Contains(e.Detail, "secretvalue") {
			t.Errorf("auth event leaked a secret: %q", e.Detail)
		}
	}
	if !found {
		t.Error("revoke event missing from auth-events timeline")
	}
}

// The redacted identity list must never return secret columns.
func TestListIdentitiesIsRedacted(t *testing.T) {
	h, _ := newIsoHandler(t)
	tid := uuid.NewString()
	if _, err := h.db.Exec(`INSERT INTO targets (id, domain) VALUES (?, 'x.test')`, tid); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO identities (id,target_id,label,role,headers_json,is_baseline)
		VALUES (?,?,?,?,?,1)`, uuid.NewString(), tid, "admin", "admin", `{"Cookie":"session=topsecret"}`); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/targets/"+tid+"/identities", nil)
	req = mux.SetURLVars(req, map[string]string{"id": tid})
	rec := httptest.NewRecorder()
	h.handleListIdentities(rec, req)
	if strings.Contains(rec.Body.String(), "topsecret") || strings.Contains(rec.Body.String(), "headers_json") {
		t.Fatalf("identity listing leaked secret material: %s", rec.Body.String())
	}
}
