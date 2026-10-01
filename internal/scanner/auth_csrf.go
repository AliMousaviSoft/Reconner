package scanner

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/recon-platform/internal/database"
)

// CSRF token tracking (issue #45). A rotating anti-CSRF token goes stale within a
// session, so an authenticated state-changing test (CSRF/authz/ATO) that replays
// an old token is silently rejected — a false negative. An identity can declare
// WHERE its current token lives; FetchFreshCSRF fetches and extracts it just
// before such a request so the test carries a valid, current token.
//
// The descriptor is a non-secret locator (which page, which field) — the token
// VALUE is always fetched live, never stored.

// csrfSource enumerates where a fresh token is read from.
const (
	csrfSourceHTMLInput = "html_input" // <input name="<name>" value="<token>">
	csrfSourceHTMLMeta  = "html_meta"  // <meta name="<name>" content="<token>">
	csrfSourceJSON      = "json"       // JSON body, dotted path <name>
	csrfSourceCookie    = "cookie"     // a Set-Cookie value named <name> (double-submit)
)

// csrfSpec is an identity's stored CSRF locator (non-secret).
type csrfSpec struct {
	URL    string `json:"url"`    // page/endpoint that returns a fresh token
	Source string `json:"source"` // one of csrfSource*
	Name   string `json:"name"`   // input/meta name, JSON dotted path, or cookie name
	Header string `json:"header"` // header to carry the token (e.g. X-CSRF-Token); empty ⇒ send as the form field Name
}

// loadCSRFSpec reads an identity's CSRF descriptor (empty when none configured).
func loadCSRFSpec(ctx context.Context, db *database.DB, identityID string) (csrfSpec, bool) {
	var raw string
	_ = db.QueryRowContext(ctx, `SELECT COALESCE(csrf_config,'') FROM identities WHERE id = ?`, identityID).Scan(&raw)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return csrfSpec{}, false
	}
	var spec csrfSpec
	if json.Unmarshal([]byte(raw), &spec) != nil || spec.Source == "" || spec.Name == "" {
		return csrfSpec{}, false
	}
	return spec, true
}

// FetchFreshCSRF fetches the identity's CSRF-bearing page/endpoint AS that
// identity and extracts the current token. Returns the spec (so the caller knows
// whether to send it as a header or a form field), the token, and ok. The fetch
// uses the scope/SSRF-guarded identity client. ok=false whenever no descriptor is
// configured, the page is unreachable, or no token is present — the caller then
// proceeds without a manufactured token rather than a stale one.
func FetchFreshCSRF(ctx context.Context, db *database.DB, id Identity) (csrfSpec, string, bool) {
	spec, ok := loadCSRFSpec(ctx, db, id.ID)
	if !ok {
		return csrfSpec{}, "", false
	}
	if spec.URL == "" || isBlockedHost(hostOf(spec.URL)) || !urlHostInScope(ctx, spec.URL) {
		return spec, "", false
	}
	resp := fetchAs(ctx, spec.URL, &id)
	if resp.Err != nil || resp.Status >= 400 {
		return spec, "", false
	}
	token := extractCSRFToken(spec, resp.Body)
	return spec, token, token != ""
}

// extractCSRFToken pulls the token from a response body per the descriptor. Pure
// and precise — it anchors on the configured field name so it cannot pick up an
// unrelated value.
func extractCSRFToken(spec csrfSpec, body string) string {
	switch spec.Source {
	case csrfSourceHTMLInput:
		return extractHTMLInputValue(body, spec.Name)
	case csrfSourceHTMLMeta:
		return extractHTMLMetaContent(body, spec.Name)
	case csrfSourceJSON:
		return extractJSONStringPath(body, spec.Name)
	case csrfSourceCookie:
		// Double-submit cookie token: not in the body; handled by the identity's
		// own cookie jar, so nothing to extract from a body here.
		return ""
	}
	return ""
}

var (
	htmlAttrValue = `["']([^"']{8,512})["']`
)

// extractHTMLInputValue finds <input ... name="NAME" ... value="TOKEN"> in either
// attribute order. Requires the exact name to avoid grabbing a different field.
func extractHTMLInputValue(body, name string) string {
	qn := regexp.QuoteMeta(name)
	// name before value
	re1 := regexp.MustCompile(`(?is)<input\b[^>]*\bname=["']` + qn + `["'][^>]*\bvalue=` + htmlAttrValue)
	if m := re1.FindStringSubmatch(body); len(m) == 2 {
		return m[1]
	}
	// value before name
	re2 := regexp.MustCompile(`(?is)<input\b[^>]*\bvalue=` + htmlAttrValue + `[^>]*\bname=["']` + qn + `["']`)
	if m := re2.FindStringSubmatch(body); len(m) == 2 {
		return m[1]
	}
	return ""
}

// extractHTMLMetaContent finds <meta name="NAME" content="TOKEN"> in either order.
func extractHTMLMetaContent(body, name string) string {
	qn := regexp.QuoteMeta(name)
	re1 := regexp.MustCompile(`(?is)<meta\b[^>]*\bname=["']` + qn + `["'][^>]*\bcontent=` + htmlAttrValue)
	if m := re1.FindStringSubmatch(body); len(m) == 2 {
		return m[1]
	}
	re2 := regexp.MustCompile(`(?is)<meta\b[^>]*\bcontent=` + htmlAttrValue + `[^>]*\bname=["']` + qn + `["']`)
	if m := re2.FindStringSubmatch(body); len(m) == 2 {
		return m[1]
	}
	return ""
}

// extractJSONStringPath reads a dotted path (a.b.c) to a string value in a JSON body.
func extractJSONStringPath(body, path string) string {
	var root interface{}
	if json.Unmarshal([]byte(strings.TrimSpace(body)), &root) != nil {
		return ""
	}
	cur := root
	for _, seg := range strings.Split(path, ".") {
		obj, ok := cur.(map[string]interface{})
		if !ok {
			return ""
		}
		cur, ok = obj[seg]
		if !ok {
			return ""
		}
	}
	if s, ok := cur.(string); ok {
		return s
	}
	return ""
}
