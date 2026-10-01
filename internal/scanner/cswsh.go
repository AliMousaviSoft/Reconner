package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// Cross-Site WebSocket Hijacking (CSWSH): a WebSocket endpoint that authenticates
// purely via ambient cookies and does NOT validate the Origin of the handshake.
// An attacker page opened in the victim's browser can then open the authenticated
// socket (the browser attaches the victim's cookies automatically) and read its
// private messages — the WebSocket analogue of a credentialed CORS misconfig, and
// a class no HTTP-only CORS check can see.
//
// Confirmation is a three-handshake triad that proves BOTH preconditions, so a hit
// is a real, exploitable finding and never a false positive:
//
//  1. cookie + the site's OWN origin        → 101  (baseline: the socket works
//     authenticated)
//  2. cookie + a cross-site attacker origin → 101  (Origin is NOT validated)
//  3. NO cookie + attacker origin           → ≠101 (the socket is cookie-GATED, so
//     hijacking it actually yields private data)
//
// If (2) is rejected, Origin is validated → safe. If (3) succeeds, the socket is
// public → nothing private to steal → not reported. Only all-three fires a
// finding, and (2) is re-probed once to drop a transient accept.
//
// CSWSH requires AMBIENT credentials, so it only runs when the configured identity
// carries a Cookie (a Bearer-only identity is not browser-ambient and cannot be
// hijacked this way) — another deliberate false-positive gate.
func (s *CORSScanner) checkCSWSH(ctx context.Context, targetID string, logFn LogFunc) {
	cookie := identityCookie(loadAuthHeaders(ctx, s.db, targetID))
	if cookie == "" {
		return // no ambient cookie session → CSWSH is not applicable
	}
	endpoints := s.loadWebSocketEndpoints(ctx, targetID)
	if len(endpoints) == 0 {
		return
	}
	logFn("info", "cors", fmt.Sprintf("Testing %d WebSocket endpoint(s) for cross-site hijacking (CSWSH)...", len(endpoints)))

	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	var found atomic.Int64
	for _, ep := range endpoints {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(wsURL string) {
			defer wg.Done()
			defer func() { <-sem }()
			if ev, ok := cswshProbe(ctx, wsURL, cookie); ok {
				s.storeCSWSH(targetID, wsURL, ev)
				found.Add(1)
				logFn("warn", "cors", "Cross-Site WebSocket Hijacking confirmed: "+wsURL)
				if s.broadcast != nil {
					s.broadcast("new_vuln_finding", map[string]any{"target_id": targetID, "type": "cswsh", "url": wsURL, "parameter": "Origin"})
				}
			}
		}(ep)
	}
	wg.Wait()
	if n := found.Load(); n > 0 {
		logFn("warn", "cors", fmt.Sprintf("CSWSH check done. %d exploitable WebSocket endpoint(s).", n))
	}
}

// cswshProbe runs the three-handshake triad and returns evidence when CSWSH is
// proven. host scope is enforced before dialing; the dial itself goes through the
// SSRF-guarded dialer so an in-scope name that resolves to a private/loopback/
// metadata address can never be reached with the victim's cookie.
func cswshProbe(ctx context.Context, wsURL, cookie string) (string, bool) {
	u, err := url.Parse(wsURL)
	if err != nil || (u.Scheme != "ws" && u.Scheme != "wss") || u.Host == "" {
		return "", false
	}
	host := u.Hostname()
	if host == "" || isBlockedHost(host) || !urlHostInScope(ctx, wsURL) {
		return "", false
	}
	legitOrigin := "https://" + u.Host
	if u.Scheme == "ws" {
		legitOrigin = "http://" + u.Host
	}
	evilOrigin := "https://rcn-cswsh-" + randomCanary() + ".example"

	// (1) cookie + legit origin must succeed, else the socket isn't an
	//     authenticated endpoint we can reason about — bail without a finding.
	if code, ok := wsHandshake(ctx, wsURL, legitOrigin, cookie); !ok || code != 101 {
		return "", false
	}
	// (3) no cookie + attacker origin: if this succeeds the socket is public, so
	//     there's nothing private to hijack — not a vulnerability.
	if code, ok := wsHandshake(ctx, wsURL, evilOrigin, ""); ok && code == 101 {
		return "", false
	}
	// (2) cookie + attacker origin: acceptance means Origin is not validated.
	code, ok := wsHandshake(ctx, wsURL, evilOrigin, cookie)
	if !ok || code != 101 {
		return "", false // origin validated (or rejected) → safe
	}
	// Re-probe (2) once to drop a transient accept.
	if code2, ok2 := wsHandshake(ctx, wsURL, evilOrigin, cookie); !ok2 || code2 != 101 {
		return "", false
	}
	return fmt.Sprintf(
		"CSWSH confirmed: the WebSocket handshake succeeded (101) with the session cookie and a cross-site Origin (%s), while the SAME handshake WITHOUT the cookie was rejected — proving the socket is cookie-authenticated and does not validate Origin. An attacker page can open this socket in the victim's browser and read its private messages.",
		evilOrigin), true
}

// wsHandshake performs ONE WebSocket handshake with the given Origin and optional
// Cookie and returns the HTTP status (101 = accepted). It never reads frames —
// the handshake status alone answers the Origin/credential question — and any
// upgraded connection is closed immediately.
func wsHandshake(ctx context.Context, wsURL, origin, cookie string) (int, bool) {
	hctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	dialer := &websocket.Dialer{
		NetDialContext:   guardedDialContext,
		HandshakeTimeout: 8 * time.Second,
		// The platform validates destination/scope itself; this only governs the
		// TLS handshake to the (already in-scope) target and mirrors the rest of
		// the scanner's permissive-cert posture for coverage over broken-TLS hosts.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- scope-gated recon target, not a trust decision
	}
	header := map[string][]string{"Origin": {origin}}
	if cookie != "" {
		header["Cookie"] = []string{cookie}
	}
	conn, resp, err := dialer.DialContext(hctx, wsURL, header)
	if conn != nil {
		_ = conn.Close()
	}
	if resp != nil {
		// resp.Body is already closed by the dialer, but StatusCode is valid.
		return resp.StatusCode, true
	}
	if err != nil {
		return 0, false
	}
	return 0, false
}

// identityCookie extracts the Cookie header from an auth-header map, case-
// insensitively (CSWSH is only meaningful for cookie/ambient auth).
func identityCookie(auth map[string]string) string {
	for k, v := range auth {
		if strings.EqualFold(strings.TrimSpace(k), "Cookie") {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// loadWebSocketEndpoints returns in-scope ws:// / wss:// endpoints discovered in
// JavaScript (js_findings type='websocket'), de-duplicated.
func (s *CORSScanner) loadWebSocketEndpoints(ctx context.Context, targetID string) []string {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT value FROM js_findings WHERE target_id = ? AND type = 'websocket'`, targetID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	seen := map[string]bool{}
	var out []string
	for rows.Next() {
		var v string
		if rows.Scan(&v) != nil {
			continue
		}
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		if !strings.HasPrefix(v, "ws://") && !strings.HasPrefix(v, "wss://") {
			continue
		}
		if !urlHostInScope(ctx, v) {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func (s *CORSScanner) storeCSWSH(targetID, wsURL, evidence string) {
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: "cswsh", Severity: "high", URL: wsURL,
		Method: "GET", Parameter: "Origin", Location: "header",
		Payload:  "WebSocket handshake with cross-site Origin + session cookie",
		Evidence: evidence, Source: "cors", DetectionMethod: "cswsh-handshake-triad",
		Confidence: ConfMultiTool, Verdict: VerifyVerified,
	})
}
