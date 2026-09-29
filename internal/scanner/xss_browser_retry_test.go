package scanner

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// getXSSBrowser used to cache a FAILED chrome-detection attempt forever via
// sync.Once: one bad lookup (a container race, a transient exec failure)
// permanently disabled the browser-based XSS execution proof for the rest of
// the process's uptime, with no way to self-heal. This proves the fix: a
// failed attempt is retried after xssBrowserRetryCooldown instead of never.
func TestGetXSSBrowserRetriesAfterFailedAttempt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is Unix-only")
	}

	// Isolate this test from any other test's browser-detection state.
	xssBrowserMu.Lock()
	savedInst, savedTry := xssBrowserInst, xssBrowserLastTry
	xssBrowserInst, xssBrowserLastTry = nil, time.Time{}
	xssBrowserMu.Unlock()
	t.Cleanup(func() {
		xssBrowserMu.Lock()
		xssBrowserInst, xssBrowserLastTry = savedInst, savedTry
		xssBrowserMu.Unlock()
	})

	// findChromePath falls back to a real PATH/absolute-path search when
	// RECONNER_CHROME doesn't resolve — a host or CI runner (e.g. GitHub's
	// ubuntu-latest, which ships Chrome preinstalled) that happens to have a
	// real browser at one of those fallback locations would find it there
	// and make the "must fail" assertions below false regardless of the env
	// var. Neutralize both fallbacks for the duration of this test.
	savedLookPath, savedAbsPaths := chromeLookPath, chromeAbsolutePaths
	chromeLookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	chromeAbsolutePaths = nil
	t.Cleanup(func() { chromeLookPath, chromeAbsolutePaths = savedLookPath, savedAbsPaths })

	dir := t.TempDir()
	working := filepath.Join(dir, "working-chrome")
	if err := os.WriteFile(working, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// First attempt: point RECONNER_CHROME at a nonexistent binary. This must fail.
	t.Setenv("RECONNER_CHROME", filepath.Join(dir, "does-not-exist"))
	if b := getXSSBrowser(); b != nil {
		t.Fatal("expected getXSSBrowser to return nil for a nonexistent chrome binary")
	}

	// Immediately after, even pointing RECONNER_CHROME at a WORKING binary must
	// still return nil — the cooldown should suppress an immediate re-lookup so
	// a genuinely browser-less deployment isn't hammered on every insertion point.
	if err := os.Setenv("RECONNER_CHROME", working); err != nil {
		t.Fatal(err)
	}
	if b := getXSSBrowser(); b != nil {
		t.Fatal("expected getXSSBrowser to still return nil inside the retry cooldown")
	}

	// Once the cooldown has elapsed, the SAME process must retry and succeed —
	// this is the actual fix: the old sync.Once behavior would stay nil forever.
	xssBrowserMu.Lock()
	xssBrowserLastTry = time.Now().Add(-2 * xssBrowserRetryCooldown)
	xssBrowserMu.Unlock()
	b := getXSSBrowser()
	if b == nil {
		t.Fatal("expected getXSSBrowser to retry and succeed once the cooldown elapsed")
	}
	if b.chromePath != working {
		t.Fatalf("expected the retried lookup to pick up the now-working chrome path, got %q", b.chromePath)
	}
}
