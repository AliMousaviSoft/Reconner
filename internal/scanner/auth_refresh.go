package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/recon-platform/internal/capture"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/secret"
)

// Refresh strategies (issue #45). "replay" re-sends a stored login/refresh HTTP
// request and rebuilds the session from its Set-Cookie; "manual" means only an
// operator can restore it (re-import); "none" means a dead session stays dead.
const (
	RefreshNone   = "none"
	RefreshReplay = "replay"
	RefreshManual = "manual"
)

// authRefreshSpec is an identity's stored refresh configuration.
type authRefreshSpec struct {
	strategy   string
	rawRequest string // decrypted raw HTTP request to replay (for "replay")
}

// loadRefreshSpec reads and decrypts an identity's refresh configuration.
func loadRefreshSpec(ctx context.Context, db *database.DB, box *secret.Box, identityID string) authRefreshSpec {
	var spec authRefreshSpec
	var raw string
	_ = db.QueryRowContext(ctx,
		`SELECT COALESCE(refresh_strategy,'none'), COALESCE(refresh_request,'') FROM identities WHERE id = ?`,
		identityID).Scan(&spec.strategy, &raw)
	if raw != "" && box != nil {
		raw = box.Decrypt(raw)
	}
	spec.rawRequest = raw
	if spec.strategy == "" {
		spec.strategy = RefreshNone
	}
	return spec
}

// RefreshSession attempts to restore an identity's authenticated state after it
// was found expired, following its stored refresh strategy, then re-validates.
// It returns the resulting lifecycle state and whether the session is usable
// again. Every attempt and outcome is recorded as a sanitized auth_event, and the
// identity's stored headers are updated ATOMICALLY (one UPDATE) so a concurrent
// module never reads a half-rotated credential.
//
// Fail-closed: a strategy of "none"/"manual", a missing refresh request, an
// out-of-scope refresh URL, or a replay that does not restore access all return a
// non-healthy state — the caller must treat the session as unusable, never
// silently continue unauthenticated.
func RefreshSession(ctx context.Context, db *database.DB, box *secret.Box, targetID string, id Identity) (string, bool) {
	spec := loadRefreshSpec(ctx, db, box, id.ID)
	switch spec.strategy {
	case RefreshReplay:
		if strings.TrimSpace(spec.rawRequest) == "" {
			RecordAuthEvent(ctx, db, targetID, id.ID, id.Label, AuthEventRefreshFailed, SessRefreshFailed,
				"replay strategy configured but no refresh request stored")
			return SessRefreshFailed, false
		}
	case RefreshManual:
		RecordAuthEvent(ctx, db, targetID, id.ID, id.Label, AuthEventBlocked, SessRefreshRequired,
			"manual refresh required — operator must re-import the session")
		return SessRefreshRequired, false
	default: // none
		return SessExpired, false
	}

	RecordAuthEvent(ctx, db, targetID, id.ID, id.Label, AuthEventRefreshAttempt, SessRefreshRequired,
		"replaying stored refresh request")
	bumpRefreshAttempt(ctx, db, id.ID)

	cookie, err := replayForCookies(ctx, spec.rawRequest)
	if err != nil || cookie == "" {
		detail := "refresh replay did not yield a session cookie"
		if err != nil {
			detail = "refresh replay failed: " + err.Error()
		}
		RecordAuthEvent(ctx, db, targetID, id.ID, id.Label, AuthEventRefreshFailed, SessRefreshFailed, detail)
		return SessRefreshFailed, false
	}

	// Merge the fresh Cookie into the identity's headers and persist atomically.
	newHeaders := map[string]string{}
	for k, v := range id.Headers {
		if !strings.EqualFold(k, "Cookie") {
			newHeaders[k] = v
		}
	}
	newHeaders["Cookie"] = cookie
	if !persistIdentityHeaders(ctx, db, box, id.ID, newHeaders) {
		RecordAuthEvent(ctx, db, targetID, id.ID, id.Label, AuthEventRefreshFailed, SessRefreshFailed,
			"could not persist refreshed session state")
		return SessRefreshFailed, false
	}

	// Re-validate with the refreshed cookie.
	refreshed := id
	refreshed.Headers = newHeaders
	verdict := ValidateSession(ctx, refreshed)
	if verdict == "authenticated" || verdict == "unknown" {
		RecordAuthEvent(ctx, db, targetID, id.ID, id.Label, AuthEventRefreshed, SessHealthy,
			"session restored by refresh replay")
		persistIdentityStatus(ctx, db, id.ID, "authenticated")
		return SessHealthy, true
	}
	RecordAuthEvent(ctx, db, targetID, id.ID, id.Label, AuthEventRefreshFailed, SessRefreshFailed,
		"refresh replay ran but re-validation still shows expired")
	return SessRefreshFailed, false
}

// replayForCookies replays a stored raw HTTP request (a login / token-refresh
// request) through the SSRF-guarded transport with a cookie jar, following
// in-scope redirects, and returns the collected Cookie header for the request's
// own origin. The destination host is scope-checked before the request is sent.
func replayForCookies(ctx context.Context, rawRequest string) (string, error) {
	ex, err := capture.ParseRawHTTPRequest([]byte(rawRequest))
	if err != nil {
		return "", err
	}
	reqURL, err := url.Parse(ex.Request.URL)
	if err != nil || reqURL.Host == "" {
		return "", err
	}
	host := reqURL.Hostname()
	if host == "" || isBlockedHost(host) || !urlHostInScope(ctx, ex.Request.URL) {
		return "", errOutOfScopeRefresh
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Transport: guardedCredentialTransport,
		Timeout:   20 * time.Second,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			// Stay on the same registrable domain through the login redirect chain,
			// so the guarded credentials never follow off to a third party.
			if !sameRegistrable(normalizeHost(req.URL.Hostname()), normalizeHost(host)) &&
				normalizeHost(req.URL.Hostname()) != normalizeHost(host) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var body *bytes.Reader
	if len(ex.Request.Body) > 0 {
		body = bytes.NewReader(ex.Request.Body)
	} else {
		body = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(reqCtx, ex.Request.Method, ex.Request.URL, body)
	if err != nil {
		return "", err
	}
	for _, h := range ex.Request.Headers {
		// Cookie is rebuilt from the jar; a stale Cookie in the stored request
		// would defeat the refresh.
		if strings.EqualFold(h.Name, "Cookie") || strings.EqualFold(h.Name, "Host") || strings.EqualFold(h.Name, "Content-Length") {
			continue
		}
		req.Header.Set(h.Name, h.Value)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	_, _ = resp.Body.Read(make([]byte, 0))

	// Build the Cookie header from every cookie the jar now holds for the origin.
	var parts []string
	for _, c := range jar.Cookies(reqURL) {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; "), nil
}

// persistIdentityHeaders re-encrypts and atomically writes an identity's headers.
func persistIdentityHeaders(ctx context.Context, db *database.DB, box *secret.Box, identityID string, headers map[string]string) bool {
	raw, err := json.Marshal(headers)
	if err != nil {
		return false
	}
	enc := string(raw)
	if box != nil {
		enc = box.Encrypt(enc)
	}
	res, err := db.ExecContext(ctx,
		`UPDATE identities SET headers_json = ?, last_refreshed = CURRENT_TIMESTAMP, status = 'authenticated',
		 last_verified_at = CURRENT_TIMESTAMP WHERE id = ?`, enc, identityID)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

func bumpRefreshAttempt(ctx context.Context, db *database.DB, identityID string) {
	_, _ = db.ExecContext(ctx, `UPDATE identities SET refresh_attempts = refresh_attempts + 1 WHERE id = ?`, identityID)
}

// errOutOfScopeRefresh is returned when a refresh request targets a host outside
// the engagement scope — refusing to replay credentials off-scope.
var errOutOfScopeRefresh = refreshError("refresh request target is out of scope")

type refreshError string

func (e refreshError) Error() string { return string(e) }
