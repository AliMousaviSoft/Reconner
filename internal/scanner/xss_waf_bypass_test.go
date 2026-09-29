package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestHTMLEntityAndUnicodeEscapeEncodingsRoundTrip(t *testing.T) {
	dec := htmlEntityEncodeDecimal("alert(1)")
	if strings.Contains(dec, "alert(") {
		t.Fatalf("decimal entity encoding must not contain the literal substring, got %q", dec)
	}
	if !strings.Contains(dec, "&#97;") || !strings.Contains(dec, "&#40;") {
		t.Fatalf("expected decimal entity references for 'a' and '(', got %q", dec)
	}

	hex := htmlEntityEncodeHex("alert(1)")
	if strings.Contains(hex, "alert(") {
		t.Fatalf("hex entity encoding must not contain the literal substring, got %q", hex)
	}
	if !strings.Contains(hex, "&#x61;") {
		t.Fatalf("expected a hex entity reference for 'a', got %q", hex)
	}

	esc := jsUnicodeEscapeLetters("alert(1)")
	if strings.Contains(esc, "alert(") {
		t.Fatalf("unicode-escaped form must not contain the literal substring, got %q", esc)
	}
	if !strings.Contains(esc, "\\u0061") || !strings.Contains(esc, "(1)") {
		t.Fatalf("expected letters escaped and punctuation preserved, got %q", esc)
	}
}

func TestXSSWAFTamperVariantsCoverThreeEncodings(t *testing.T) {
	p := htmlTextExecLadder()[0] // <svg onload=alert(document.domain)>
	variants := xssWAFTamperVariants(p)
	if len(variants) != 3 {
		t.Fatalf("expected 3 tamper variants, got %d", len(variants))
	}
	for _, v := range variants {
		if strings.Contains(v.Payload, xssAlert) {
			t.Fatalf("tamper variant must not contain the literal blocked substring: %q", v.Payload)
		}
		if v.Elem != p.Elem {
			t.Fatalf("tamper variant must preserve the element name for the survival check, got %q want %q", v.Elem, p.Elem)
		}
	}
}

func TestXSSWAFTamperVariantsSkipsPayloadsWithoutTheAlertCall(t *testing.T) {
	p := xssExecPayload{Payload: `<svg onload=confirm(document.domain)>`, Elem: "svg", Token: "confirm("}
	if v := xssWAFTamperVariants(p); v != nil {
		t.Fatalf("expected no tamper variants for a payload that doesn't contain xssAlert verbatim, got %v", v)
	}
}

// tryBrowserlessExecPayload is the browserless-fallback proof step wired into
// proveExecutingXSS. This proves the actual wiring end-to-end against a fake
// app that blocks the literal "alert(document.domain)" substring (a naive
// WAF's exact behavior) but lets an entity/unicode-escaped spelling through —
// the WAF-bypass upgrade is worthless if it isn't reachable from the real
// confirm path.
func TestTryBrowserlessExecPayloadFallsBackToWAFBypassWhenBlocked(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		if strings.Contains(q, "alert(document.domain)") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Access Denied - request blocked by the firewall"))
			return
		}
		_, _ = w.Write([]byte("<html><body>hi " + q + " bye</body></html>"))
	}))
	defer srv.Close()

	ip := insertionPoint{URL: srv.URL + "/?q=1", Param: "q", Method: "GET"}
	p := htmlTextExecLadder()[0] // <svg onload=alert(document.domain)>
	s := &DASTScanner{}

	payload, method, ok := s.tryBrowserlessExecPayload(context.Background(), ip, nil, "", p)
	if !ok {
		t.Fatal("expected the WAF-bypass tamper variant to survive after the plain payload was blocked")
	}
	if method != "differential-candidate-waf-bypass" {
		t.Fatalf("expected the waf-bypass proof method label, got %q", method)
	}
	if strings.Contains(payload, "alert(document.domain)") {
		t.Fatalf("expected the surviving payload to be an encoded variant, not the literal blocked string: %q", payload)
	}
}

// The plain payload path must still work unmodified when nothing is blocking
// it — the WAF-bypass retry must be additive, never required for the common
// (unfiltered) case.
func TestTryBrowserlessExecPayloadPlainPathStillWorksWhenUnblocked(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>hi " + r.URL.Query().Get("q") + " bye</body></html>"))
	}))
	defer srv.Close()

	ip := insertionPoint{URL: srv.URL + "/?q=1", Param: "q", Method: "GET"}
	p := htmlTextExecLadder()[0]
	s := &DASTScanner{}

	payload, method, ok := s.tryBrowserlessExecPayload(context.Background(), ip, nil, "", p)
	if !ok {
		t.Fatal("expected the plain payload to survive on an unfiltered app")
	}
	if method != "differential-candidate" {
		t.Fatalf("expected the plain proof method label, got %q", method)
	}
	if payload != p.Payload {
		t.Fatalf("expected the plain payload unchanged, got %q", payload)
	}
}

// proveExecutingXSS used to give up entirely (return "inconclusive") the
// instant a browser existed but its per-scan budget was exhausted — the
// deterministic browserless ladder below was reachable ONLY when no browser
// was ever found. On a large target (trivially >150 candidates needing
// browser escalation) that meant every candidate past the budget got zero
// further testing. This proves the fix: budget=0 still reaches, and can
// succeed through, the browserless ladder.
func TestProveExecutingXSSFallsThroughToLadderWhenBrowserBudgetExhausted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is Unix-only")
	}
	withLoopbackAllowed(t)

	// Force getXSSBrowser() to report a browser is available, without ever
	// actually launching chromedp (browserBudget.take() below fails first).
	xssBrowserMu.Lock()
	savedInst, savedTry := xssBrowserInst, xssBrowserLastTry
	xssBrowserInst, xssBrowserLastTry = nil, time.Time{}
	xssBrowserMu.Unlock()
	t.Cleanup(func() {
		xssBrowserMu.Lock()
		xssBrowserInst, xssBrowserLastTry = savedInst, savedTry
		xssBrowserMu.Unlock()
	})
	dir := t.TempDir()
	working := filepath.Join(dir, "working-chrome")
	if err := os.WriteFile(working, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RECONNER_CHROME", working)
	if getXSSBrowser() == nil {
		t.Fatal("test setup failed: expected getXSSBrowser to report the fake browser as available")
	}

	// Vulnerable, unfiltered app: the browserless ladder must find it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>hi " + r.URL.Query().Get("q") + " bye</body></html>"))
	}))
	defer srv.Close()

	ip := insertionPoint{URL: srv.URL + "/?q=1", Param: "q", Method: "GET"}
	a := ReflectionAnalysis{Context: CtxHTMLText, Reflected: true, Executable: true}
	s := &DASTScanner{}
	exhaustedBudget := newXSSBrowserBudget(0)

	payload, proof, confidence, executed := s.proveExecutingXSS(context.Background(), ip, a, []ReflectionAnalysis{a}, nil, "", exhaustedBudget)
	if payload == "" || proof == "inconclusive" {
		t.Fatalf("expected the exhausted-budget path to fall through to the browserless ladder and find the vulnerability, got payload=%q proof=%q", payload, proof)
	}
	if executed {
		t.Fatal("the browserless ladder must never claim real execution (executed=true) — only the live browser proof may")
	}
	if confidence != 85 {
		t.Fatalf("expected the browserless differential-candidate confidence tier (85), got %d", confidence)
	}
}
