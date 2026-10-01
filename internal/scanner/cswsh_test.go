package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

// wsUpgradeServer builds a gorilla-backed WebSocket server with configurable
// Origin and cookie policy, returning its ws:// URL.
func wsUpgradeServer(t *testing.T, checkOrigin bool, requireCookie bool) string {
	t.Helper()
	up := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			if !checkOrigin {
				return true // vulnerable: accepts ANY origin
			}
			return r.Header.Get("Origin") == "http://"+r.Host || r.Header.Get("Origin") == "https://"+r.Host
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requireCookie {
			c, err := r.Cookie("session")
			if err != nil || c.Value != "valid" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		conn.Close()
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http") // http://127.0.0.1:p -> ws://127.0.0.1:p
}

// Vulnerable: accepts any Origin AND is cookie-gated → CSWSH must be confirmed.
func TestCSWSHConfirmedOnVulnerableSocket(t *testing.T) {
	withLoopbackAllowed(t)
	wsURL := wsUpgradeServer(t, false /*no origin check*/, true /*cookie required*/)
	ev, ok := cswshProbe(context.Background(), wsURL, "session=valid")
	if !ok {
		t.Fatal("CSWSH must be confirmed on an origin-blind, cookie-gated socket")
	}
	if !strings.Contains(ev, "cross-site Origin") {
		t.Errorf("evidence should describe the cross-site handshake: %q", ev)
	}
}

// Safe: Origin is validated → cross-site handshake rejected → no finding.
func TestCSWSHNotFlaggedWhenOriginValidated(t *testing.T) {
	withLoopbackAllowed(t)
	wsURL := wsUpgradeServer(t, true /*origin checked*/, true /*cookie required*/)
	if _, ok := cswshProbe(context.Background(), wsURL, "session=valid"); ok {
		t.Fatal("an origin-validating socket must NOT be flagged")
	}
}

// Public: no cookie required → anonymous handshake also succeeds → nothing private
// to hijack → no finding (zero false positive).
func TestCSWSHNotFlaggedWhenSocketIsPublic(t *testing.T) {
	withLoopbackAllowed(t)
	wsURL := wsUpgradeServer(t, false /*no origin check*/, false /*no cookie*/)
	if _, ok := cswshProbe(context.Background(), wsURL, "session=valid"); ok {
		t.Fatal("a public (non-cookie-gated) socket must NOT be flagged as CSWSH")
	}
}

func TestIdentityCookieExtraction(t *testing.T) {
	if got := identityCookie(map[string]string{"cookie": "a=1"}); got != "a=1" {
		t.Errorf("case-insensitive cookie extraction failed: %q", got)
	}
	if got := identityCookie(map[string]string{"Authorization": "Bearer x"}); got != "" {
		t.Errorf("non-cookie auth must yield empty: %q", got)
	}
}
