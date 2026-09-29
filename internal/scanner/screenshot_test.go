package scanner

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
)

func TestXSSReproURLRebuildsQueryGET(t *testing.T) {
	ip := insertionPoint{URL: "https://example.test/search?q=1", Param: "q", Method: "GET", Location: "query"}
	got := xssReproURL(ip, `<svg onload=alert(1)>`)
	if got == ip.URL {
		t.Fatalf("expected the reproduction URL to carry the payload, got unchanged %q", got)
	}
	if !strings.Contains(got, "svg") {
		t.Fatalf("expected the payload to appear in the reproduction URL, got %q", got)
	}
}

func TestXSSReproURLFallsBackForNonQueryLocations(t *testing.T) {
	cases := []insertionPoint{
		{URL: "https://example.test/api", Param: "name", Method: "POST", Location: "body"},
		{URL: "https://example.test/api", Param: "name", Method: "POST", Location: "json"},
		{URL: "https://example.test/users/1", Param: "0", Method: "GET", Location: "path:1"},
	}
	for _, ip := range cases {
		if got := xssReproURL(ip, "<script>alert(1)</script>"); got != ip.URL {
			t.Errorf("expected fallback to the bare URL for location %q, got %q", ip.Location, got)
		}
	}
}

// captureAdminPanelScreenshot must skip launching a browser entirely when the
// panel already has a screenshot — a re-scan re-confirming the same panel
// should never repeatedly pay for a browser launch. This is verifiable
// without a real Chromium: RECONNER_NO_XSS_BROWSER-style unavailability would
// make captureScreenshot return "" anyway, but the "already has one" check
// happens BEFORE that, at the DB level, and would leave the existing
// screenshot untouched even if it were called (fire-and-forget goroutine
// writes only on a non-empty capture result).
func TestCaptureAdminPanelScreenshotSkipsWhenAlreadyPresent(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	url := "https://example.test/admin"
	panelID := uuid.NewString()
	if _, err := db.Exec(`INSERT INTO admin_panel_findings (id,target_id,url,status_code,group_key,screenshot_id) VALUES (?,?,?,?,?,?)`,
		panelID, tid, url, 200, "g1", "existing-shot-id"); err != nil {
		t.Fatal(err)
	}

	s := &DirScanner{db: db, cfg: &config.Config{}}
	s.captureAdminPanelScreenshot(tid, url)
	// No goroutine should have been spawned (screenshot already present), so
	// there is nothing async to wait for — the existing id must be untouched
	// immediately.
	var got string
	if err := db.QueryRow(`SELECT screenshot_id FROM admin_panel_findings WHERE id=?`, panelID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "existing-shot-id" {
		t.Fatalf("expected the existing screenshot_id to be left untouched, got %q", got)
	}
}

// captureScreenshot must fail closed (return "") rather than panic or block
// forever when Chromium is unavailable — the common case in a CI sandbox and
// the exact scenario this function's contract promises to degrade from.
func TestCaptureScreenshotReturnsEmptyWithoutBrowser(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	dir := t.TempDir()
	t.Setenv("RECONNER_CHROME", filepath.Join(dir, "does-not-exist"))
	cfg := &config.Config{ScreenshotsDir: filepath.Join(dir, "shots")}
	if got := captureScreenshot(context.Background(), db, cfg, tid, "https://example.test/"); got != "" {
		t.Fatalf("expected empty result without a working browser, got %q", got)
	}
}

func TestCaptureScreenshotReturnsEmptyWithoutConfig(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	if got := captureScreenshot(context.Background(), db, nil, tid, "https://example.test/"); got != "" {
		t.Fatalf("expected empty result with a nil config, got %q", got)
	}
	if got := captureScreenshot(context.Background(), db, &config.Config{}, tid, "https://example.test/"); got != "" {
		t.Fatalf("expected empty result with no ScreenshotsDir configured, got %q", got)
	}
}

// Live end-to-end capture, opt-in only (needs a real Chromium + explicit
// consent to launch one), mirroring the existing xss_browser_live_test.go
// pattern for the same reason: this actually writes a PNG to disk and hits
// the network.
func TestCaptureScreenshotLive(t *testing.T) {
	if os.Getenv("RECONNER_BROWSER_TEST") == "" || os.Getenv("RECONNER_CHROME") == "" {
		t.Skip("browser E2E disabled; set RECONNER_BROWSER_TEST=1 (and RECONNER_CHROME) to run")
	}
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is Unix-only")
	}
	db, tid := testDB(t)
	defer db.Close()
	dir := t.TempDir()
	cfg := &config.Config{ScreenshotsDir: dir}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	id := captureScreenshot(ctx, db, cfg, tid, "https://example.com/")
	if id == "" {
		t.Fatal("expected a screenshot id from a live capture")
	}
	var filePath string
	if err := db.QueryRow(`SELECT file_path FROM screenshots WHERE id=?`, id).Scan(&filePath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filePath); err != nil {
		t.Fatalf("expected the screenshot file to exist on disk: %v", err)
	}
}
