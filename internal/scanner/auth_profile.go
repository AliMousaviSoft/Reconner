package scanner

import (
	"context"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/secret"
)

// Authentication-lifecycle state model (issue #45). A session is never judged
// healthy merely because a request returned 200 — these states are set from the
// explicit validation/refresh logic and drive fail-closed behaviour for every
// authenticated module.
const (
	SessHealthy         = "healthy"          // validated: the session reaches authenticated content
	SessExpired         = "expired"          // proven dead (redirect-to-login / lost marker)
	SessRefreshRequired = "refresh_required" // dead, a refresh strategy exists to try
	SessRefreshFailed   = "refresh_failed"   // a refresh was attempted and did not restore access
	SessBlocked         = "blocked"          // cannot proceed (no credentials / unrecoverable)
	SessRevoked         = "revoked"          // operator revoked the profile
	SessUnknown         = "unknown"          // not validatable (no endpoint) — proceed, unproven
)

// Authentication-lifecycle event names for the sanitized audit trail.
const (
	AuthEventValidated      = "validated"
	AuthEventExpired        = "expired"
	AuthEventRefreshAttempt = "refresh_attempt"
	AuthEventRefreshed      = "refreshed"
	AuthEventRefreshFailed  = "refresh_failed"
	AuthEventBlocked        = "blocked"
	AuthEventRevoked        = "revoked"
	AuthEventNoValidation   = "no_validation_endpoint"
)

// secretishDetail matches fragments that could carry a credential, so an audit
// detail string can never leak one even if a caller passes a raw header by
// mistake. Auth material is more sensitive than ordinary scan metadata (#45),
// so redaction is enforced here at the single write point, not left to callers.
var secretishDetail = regexp.MustCompile(`(?i)(cookie|authorization|bearer|token|session|csrf|x-[a-z-]*auth[a-z-]*)\s*[:=]\s*\S+`)

// sanitizeAuthDetail strips anything resembling a credential and bounds length.
func sanitizeAuthDetail(detail string) string {
	detail = secretishDetail.ReplaceAllString(detail, "[redacted]")
	detail = strings.TrimSpace(detail)
	if len(detail) > 300 {
		detail = detail[:300] + "…"
	}
	return detail
}

// RecordAuthEvent appends one sanitized row to the authentication-lifecycle audit
// trail. It is best-effort (an audit write must never fail a scan) and NEVER
// stores secret values — the detail is redacted at this single choke point.
func RecordAuthEvent(ctx context.Context, db *database.DB, targetID, identityID, label, event, state, detail string) {
	if db == nil || targetID == "" || event == "" {
		return
	}
	_, _ = db.ExecContext(ctx, `
		INSERT INTO auth_events (id, target_id, identity_id, identity_label, event, state, detail)
		VALUES (?,?,?,?,?,?,?)`,
		uuid.NewString(), targetID, identityID, label, event, state, sanitizeAuthDetail(detail))
}

// AuthGate is the reusable fail-closed check an authenticated-only module runs
// before testing: it validates the baseline identity's session and, if expired,
// attempts a refresh, so a module never silently scans a logged-out app behind a
// dead credential (issue #45).
//
// Returns:
//   - configured=false  → no identity is set; an unauthenticated scan is
//     legitimate, so ready=true and the module runs as normal.
//   - configured=true, ready=true  → the session is healthy (or indeterminate
//     because no validation endpoint is set — we cannot prove it dead, so we do
//     not block).
//   - configured=true, ready=false → a configured session is proven unusable
//     (expired and un-refreshable); an auth-only module should transition to an
//     explicit blocked state instead of running. `state` says which failure.
func AuthGate(ctx context.Context, db *database.DB, box *secret.Box, targetID string) (ready, configured bool, state string) {
	ids := LoadIdentities(ctx, db, targetID, box)
	if len(ids) == 0 {
		return true, false, ""
	}
	id, ok := baselineIdentity(ids)
	if !ok {
		return true, false, ""
	}
	if id.ValidationURL == "" && id.Origin == "" {
		return true, true, SessUnknown // cannot prove dead → don't block
	}
	switch ValidateSession(ctx, id) {
	case "authenticated":
		return true, true, SessHealthy
	case "unknown":
		return true, true, SessUnknown
	default: // expired — try to self-heal
		if st, refreshed := RefreshSession(ctx, db, box, targetID, id); refreshed {
			return true, true, st
		} else {
			RecordAuthEvent(ctx, db, targetID, id.ID, id.Label, AuthEventBlocked, SessBlocked,
				"authenticated module gated: session expired and could not be refreshed")
			return false, true, st
		}
	}
}

// SessStateForVerdict maps the ValidateSession verdict
// (authenticated|expired|unknown) onto the lifecycle state model.
func SessStateForVerdict(verdict string) string {
	switch verdict {
	case "authenticated":
		return SessHealthy
	case "expired":
		return SessExpired
	default:
		return SessUnknown
	}
}
