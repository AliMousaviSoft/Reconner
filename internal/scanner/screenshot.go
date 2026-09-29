package scanner

import (
	"bytes"
	"context"
	"image"
	_ "image/png" // register the PNG decoder so image.DecodeConfig can read chromedp's screenshot
	"os"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
)

// screenshotSem bounds how many headless Chromium instances captureScreenshot
// may run at once. Every caller (confirmed admin panels, confirmed XSS) fires
// capture as a best-effort background goroutine with no coordination between
// them, so on a target with many confirmations in flight at once — a scan of
// a large program that turns up dozens of admin panels across many hosts —
// nothing previously bounded how many simultaneous Chromium subprocesses
// could stack up, unlike every other browser-driven path in this codebase.
var screenshotSem = make(chan struct{}, 3)

// captureScreenshot renders rawURL in a short-lived headless Chromium and
// persists a PNG, inserting a row into the (pre-existing but previously never
// populated) screenshots table. Returns the screenshot's ID for embedding in
// a finding/panel row and serving via /screenshots/{id}, or "" on any
// failure — screenshot capture is always best-effort: a target with no
// working Chromium, a page that hangs, or a write failure must never break
// the scan or the finding it was attached to.
//
// Deliberately launches its OWN allocator/tab rather than reusing
// getXSSBrowser()'s shared, persistent tab: that tab's lease/navGate
// machinery is scoped to the XSS execution-proof sequence, and admin-panel
// screenshots happen on a completely independent code path (directory.go)
// that has no business coordinating with it. A one-shot browser per capture
// costs a few seconds of startup, which is acceptable — this only runs for a
// small number of high-value confirmations per scan (admin panels, verified
// XSS), never per-candidate.
func captureScreenshot(ctx context.Context, db *database.DB, cfg *config.Config, targetID, rawURL string) string {
	if db == nil || cfg == nil || cfg.ScreenshotsDir == "" || rawURL == "" {
		return ""
	}
	chromePath := findChromePath()
	if chromePath == "" {
		return ""
	}

	select {
	case screenshotSem <- struct{}{}:
		defer func() { <-screenshotSem }()
	case <-ctx.Done():
		return ""
	}

	capCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(chromePath),
		chromedp.Flag("headless", true),
		chromedp.Flag("no-sandbox", true), // scans run as root in the appliance, same as xss_browser.go
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("disable-background-networking", true),
		// Recon targets routinely present self-signed/expired/mismatched certs
		// on internal, staging or freshly-provisioned hosts — a screenshot is
		// visual evidence, not a certificate validator, so a cert error must
		// never be the reason a real finding gets no picture.
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.NoDefaultBrowserCheck,
		chromedp.ModifyCmdFunc(configureXSSBrowserProcess),
	)
	allocCtx, allocCancel := chromedp.NewExecAllocator(capCtx, opts...)
	defer allocCancel()
	tabCtx, tabCancel := chromedp.NewContext(allocCtx)
	defer tabCancel()

	var buf []byte
	err := chromedp.Run(tabCtx,
		chromedp.EmulateViewport(1366, 900),
		chromedp.Navigate(rawURL),
		chromedp.Sleep(1200*time.Millisecond), // let the page settle/render before capturing
		chromedp.CaptureScreenshot(&buf),
	)
	if err != nil || len(buf) == 0 {
		return ""
	}

	host := hostOfURL(rawURL)
	if host == "" {
		host = "target"
	}
	if err := os.MkdirAll(cfg.ScreenshotsDir, 0o750); err != nil {
		return ""
	}
	filePath := database.ScreenshotPath(cfg.ScreenshotsDir, host)
	if err := os.WriteFile(filePath, buf, 0o600); err != nil {
		return ""
	}

	width, height := 0, 0
	if imgCfg, _, err := image.DecodeConfig(bytes.NewReader(buf)); err == nil {
		width, height = imgCfg.Width, imgCfg.Height
	}

	id := uuid.New().String()
	if _, err := db.ExecContext(ctx, `INSERT INTO screenshots (id, target_id, url, file_path, width, height) VALUES (?, ?, ?, ?, ?, ?)`,
		id, targetID, rawURL, filePath, width, height); err != nil {
		return ""
	}
	return id
}
