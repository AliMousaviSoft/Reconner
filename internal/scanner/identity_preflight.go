package scanner

import (
	"context"
	"fmt"

	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/secret"
)

// PreflightSessions validates every configured identity's session at the START of
// an authenticated scan and surfaces the result, so a dead login is caught before
// the whole request-heavy pipeline (SQLi/XSS/IDOR/authz/…) wastes itself replaying
// expired credentials against a logged-out app — one of the largest silent
// false-negative sources in authenticated scanning.
//
// Discipline that keeps it honest (no crying wolf):
//   - It ONLY raises the "session expired" alarm when expiry is PROVABLE, i.e.
//     ValidateSession returns "expired" for an identity that actually has a
//     validation endpoint. A legacy header-only identity with no validation
//     endpoint returns "unknown"; that becomes an informational note recommending
//     a validation URL, never an alarm.
//   - It NEVER blocks or fails the scan — the target may be partly public, and the
//     operator decides. It records status + last_verified_at so the UI can show
//     which identities are live.
//
// Returns the number of identities proven expired (0 when none or unauthenticated).
func PreflightSessions(ctx context.Context, s *HTTPScanner, targetID string, logFn LogFunc) int {
	ids := LoadIdentities(ctx, s.db, targetID, secret.New(s.cfg.SessionSecret))
	if len(ids) == 0 {
		return 0 // unauthenticated scan — nothing to validate, this is normal
	}

	expired := 0
	validatable := 0
	for _, id := range ids {
		if ctx.Err() != nil {
			break
		}
		// Without a validation endpoint (and no origin to fall back on) we cannot
		// prove liveness either way — note it, don't guess.
		if id.ValidationURL == "" && id.Origin == "" {
			logFn("info", "http_probe", fmt.Sprintf(
				"Identity %q: no validation endpoint configured — session liveness can't be verified; set a validation URL for reliable authenticated coverage.", id.Label))
			RecordAuthEvent(ctx, s.db, targetID, id.ID, id.Label, AuthEventNoValidation, SessUnknown,
				"no validation endpoint configured")
			continue
		}
		validatable++
		status := ValidateSession(ctx, id)
		// identities.status keeps the raw verdict (authenticated|expired|unknown)
		// for backward-compatible UI; auth_events carries the richer #45 state model.
		persistIdentityStatus(ctx, s.db, id.ID, status)
		switch status {
		case "authenticated":
			logFn("info", "http_probe", fmt.Sprintf("Identity %q: session is live.", id.Label))
			RecordAuthEvent(ctx, s.db, targetID, id.ID, id.Label, AuthEventValidated, SessHealthy,
				"session validated at scan start")
		case "expired":
			RecordAuthEvent(ctx, s.db, targetID, id.ID, id.Label, AuthEventExpired, SessExpired,
				"session expired, detected at scan-start preflight")
			// Self-heal: if a refresh strategy is configured, try to restore the
			// session now before declaring it dead — detect → refresh → resume.
			if state, ok := RefreshSession(ctx, s.db, secret.New(s.cfg.SessionSecret), targetID, id); ok {
				logFn("info", "http_probe", fmt.Sprintf(
					"Identity %q: session was expired but was REFRESHED successfully — authenticated coverage restored.", id.Label))
				persistIdentityStatus(ctx, s.db, id.ID, "authenticated")
				continue
			} else if state == SessRefreshRequired {
				expired++
				logFn("warn", "http_probe", fmt.Sprintf(
					"Identity %q: session EXPIRED and needs manual re-authentication (no automatic refresh) — re-import it; authenticated findings will be incomplete until then.", id.Label))
			} else {
				expired++
				logFn("warn", "http_probe", fmt.Sprintf(
					"Identity %q: session is EXPIRED and could not be refreshed — authenticated modules will scan the logged-out app and miss behind-login vulns. Re-capture this session before trusting the results.", id.Label))
			}
		default: // unknown
			logFn("info", "http_probe", fmt.Sprintf(
				"Identity %q: session status unknown (validation endpoint looks public or unreachable) — proceeding, but coverage behind login isn't guaranteed.", id.Label))
			RecordAuthEvent(ctx, s.db, targetID, id.ID, id.Label, AuthEventValidated, SessUnknown,
				"session status indeterminate (validation endpoint public or unreachable)")
		}
	}

	if expired > 0 {
		logFn("warn", "http_probe", fmt.Sprintf(
			"Authenticated-session preflight: %d of %d identity session(s) are expired. Findings behind authentication may be incomplete until the session(s) are refreshed.", expired, validatable))
	} else if validatable > 0 {
		logFn("info", "http_probe", fmt.Sprintf("Authenticated-session preflight: all %d validatable identity session(s) are live.", validatable))
	}
	return expired
}

// persistIdentityStatus records the verified status + timestamp so the target UI
// reflects which sessions are live. The legacy single-blob identity has the
// synthetic id "legacy" with no row to update — skip it silently.
func persistIdentityStatus(ctx context.Context, db *database.DB, identityID, status string) {
	if db == nil || identityID == "" || identityID == "legacy" {
		return
	}
	_, _ = db.ExecContext(ctx,
		`UPDATE identities SET status = ?, last_verified_at = CURRENT_TIMESTAMP WHERE id = ?`,
		status, identityID)
}
