package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/capture"
	"github.com/recon-platform/internal/scanner"
	"github.com/recon-platform/internal/secret"
)

// handleQuickScan turns one pasted raw HTTP request into a fully working,
// already-tested project in a single call: create a project scoped to the
// request's own URL, import the request as that project's one capture
// template, classify which vulnerability classes apply to it (the same
// heuristic Guided Analyze itself uses), and queue every applicable
// automated check immediately -- no manual step-through required. This is
// deliberately the SAME storage and execution pipeline as a normal Burp/HAR
// capture import + "run recommended checks" click; it does not add a
// separate, weaker path.
func (h *Handler) handleQuickScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RawRequest string `json:"raw_request"`
		Name       string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.RawRequest) == "" {
		h.writeError(w, http.StatusBadRequest, "raw_request is required")
		return
	}
	if len(req.RawRequest) > capture.MaxMessageBytes {
		h.writeError(w, http.StatusBadRequest, "raw request exceeds the size limit")
		return
	}
	// http.ReadRequest needs the header block terminated by a blank line.
	// TrimSpace on the whole string would strip that mandatory trailing
	// CRLFCRLF along with any incidental leading/trailing whitespace a paste
	// picked up, so trim first, then restore the terminator explicitly --
	// robust to a paste missing it, and a no-op when it was already there.
	raw := strings.TrimRight(strings.TrimLeft(req.RawRequest, "\r\n\t "), "\r\n\t ") + "\r\n\r\n"
	ex, err := capture.ParseRawHTTPRequest([]byte(raw))
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "could not parse raw request: "+err.Error())
		return
	}
	parsedURL, err := url.Parse(ex.Request.URL)
	if err != nil || parsedURL.Host == "" {
		h.writeError(w, http.StatusBadRequest, "raw request has no resolvable host; add a Host header or paste an absolute request line")
		return
	}

	ctx := r.Context()
	targetID := uuid.New().String()
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = ex.Request.Method + " " + capture.SafeDisplayURL(ex.Request.URL)
	}
	if _, err := h.db.ExecContext(ctx, `
		INSERT INTO targets (id, domain, name, priority, kind, status, scan_status, owner_id)
		VALUES (?, ?, ?, 'medium', 'web', 'idle', 'idle', ?)
	`, targetID, ex.Request.URL, name, h.currentUserID(r)); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			h.writeError(w, http.StatusConflict, "a project for this exact request already exists")
			return
		}
		h.writeError(w, http.StatusInternalServerError, "failed to create project")
		return
	}

	// Import the single parsed request as this project's one capture
	// template. The project's own domain is exactly this request's URL, so
	// admission trivially accepts it -- this mirrors a normal capture import,
	// just pre-scoped to the project just created FROM this exact request.
	preview := capture.BuildPreview([]capture.Exchange{ex}, func(u string) bool {
		return scanner.GuidedURLInScope(ctx, h.db, targetID, u)
	})
	if preview.Accepted == 0 {
		h.writeError(w, http.StatusBadRequest, "parsed request was rejected by admission checks")
		return
	}
	box := secret.New(h.cfg.SessionSecret)
	captureID := uuid.New().String()
	reqJSON, _ := json.Marshal(ex.Request)
	previewJSON, _ := json.Marshal(preview.Items[0])
	templateID := uuid.New().String()
	shapeHash := keyedCaptureHash(h.cfg.SessionSecret, reqJSON)
	sealedReq := box.Encrypt(string(reqJSON))
	if !strings.HasPrefix(sealedReq, "enc:v1:") {
		h.writeError(w, http.StatusInternalServerError, "capture encryption failed")
		return
	}
	if _, err := h.db.ExecContext(ctx, `INSERT INTO capture_sessions
		(id,target_id,source,identity_label,label,status,imported_count,accepted_count,rejected_count,expires_at)
		VALUES (?,?,?,?,?,'imported',1,1,0,datetime('now','+7 days'))`,
		captureID, targetID, "raw_request", "", "quick scan"); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to save capture session")
		return
	}
	policy := "manual_only"
	if preview.Items[0].OperationKind == "read_only" || preview.Items[0].OperationKind == "query_like" {
		policy = "proof_only"
	}
	if _, err := h.db.ExecContext(ctx, `INSERT INTO request_templates
		(id,target_id,capture_session_id,method,norm_url,content_type,operation_kind,
		 request_shape_hash,encrypted_request,redacted_preview,replay_policy,source,sequence)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0)`,
		templateID, targetID, captureID, ex.Request.Method,
		scanner.NormalizeURL(capture.SafeDisplayURL(ex.Request.URL)), ex.Request.MimeType, preview.Items[0].OperationKind,
		shapeHash, sealedReq, string(previewJSON), policy, ex.Source); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to seal request template")
		return
	}

	// Auto-classify (the same heuristic behind Guided Analyze's own test
	// suggestions) and queue every applicable automated module for this one
	// request -- equivalent to clicking "Validate & run recommended checks",
	// done automatically with no manual step.
	opportunities := scanner.DiscoverGuidedOpportunities(ex.Request)
	moduleSet := map[string]bool{}
	for _, opportunity := range opportunities {
		if opportunity.Automated {
			moduleSet[opportunity.Module] = true
		}
	}
	modules := make([]string, 0, len(moduleSet))
	checks := make([]scanner.GuidedCheck, 0, len(moduleSet))
	for module := range moduleSet {
		modules = append(modules, module)
		checks = append(checks, scanner.GuidedCheck{TemplateID: templateID, Module: module})
	}

	response := map[string]any{
		"target_id": targetID, "capture_id": captureID, "template_id": templateID,
		"modules_detected": modules,
	}
	if len(checks) == 0 {
		response["modules_queued"] = 0
		response["note"] = "project created, but this request has no automatically testable insertion points (e.g. no query/body/JSON parameters or multipart file field); open it in Guided Analyze to inspect manually"
		h.writeSuccess(w, response)
		return
	}
	if h.sched == nil {
		response["modules_queued"] = 0
		response["note"] = "project created, but the scheduler is unavailable so automated checks could not be queued; open it in Guided Analyze to run them"
		h.writeSuccess(w, response)
		return
	}
	runID, taskID, runErr := h.enqueueGuidedRun(ctx, targetID, captureID, modules, checks, []string{templateID}, false)
	if runErr != nil {
		response["modules_queued"] = 0
		response["note"] = "project created, but failed to queue automated tests: " + runErr.Error()
		h.writeSuccess(w, response)
		return
	}
	response["modules_queued"] = len(checks)
	response["run_id"] = runID
	response["task_id"] = taskID
	h.writeSuccess(w, response)
}
