package scanner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/pkg/logger"
)

// WordPressScanner is the dedicated WordPress offensive module family. Unlike the
// generic web detectors — which deliberately SKIP active injection on a detected
// stock WordPress host (see cms.go) because the core is a false-positive magnet —
// this scanner turns WordPress's own, well-documented surface into high-signal,
// individually-confirmed findings: version/plugin/theme/user enumeration, config
// and backup exposure, login/XML-RPC surface, misconfiguration, and known-CVE
// coverage.
//
// The cardinal rule is the DETECTION GATE: no WP module ever acts on a host until
// ensureDetected has CONFIRMED it is WordPress with an essentially WordPress-unique
// signal (the wp/v2 REST namespace or the wp-login.php credential form), recorded
// in the wp_sites table. A domain the operator entered that turns out NOT to be
// WordPress simply yields an empty site list, so every WP module no-ops on it —
// that is what keeps the whole family at zero false positives end to end.
type WordPressScanner struct {
	db        *database.DB
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewWordPressScanner(db *database.DB, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *WordPressScanner {
	return &WordPressScanner{db: db, cfg: cfg, logger: log, broadcast: broadcast}
}

// wpHTTPClient does not auto-follow redirects: the `/?author=1` → `/author/<name>/`
// 301 is itself a detection/enumeration signal we must read from the Location
// header, and following it would also risk leaving the base host. Per-request
// contexts carry the real timeout.
var wpHTTPClient = &http.Client{
	Transport: sharedHTTPTransport,
	Timeout:   15 * time.Second,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

const wpUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

// wpSite is one probed base URL and the verdict of the detection gate.
type wpSite struct {
	URL        string // scheme://host[:port], no trailing slash
	Host       string
	Version    string
	Confidence int
	Signals    []string
}

func (w wpSite) isWordPress() bool { return w.Confidence >= ConfEvidence }

// wpResp is a minimal fetched response (status + selected headers + bounded body).
type wpResp struct {
	status    int
	body      string
	location  string
	setCookie string
	linkHdr   string
	ctype     string
}

// wpGet performs one GET with the shared WP client and returns a bounded body.
// maxBody caps how much of the body we read (login pages are small; a JSON API
// root can be larger). Any transport error yields status 0.
func wpGet(ctx context.Context, rawURL string, maxBody int64) wpResp {
	rctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return wpResp{}
	}
	req.Header.Set("User-Agent", wpUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")
	resp, err := wpHTTPClient.Do(req)
	if err != nil {
		return wpResp{}
	}
	defer resp.Body.Close()
	if maxBody <= 0 {
		maxBody = 256 * 1024
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return wpResp{
		status:    resp.StatusCode,
		body:      string(body),
		location:  resp.Header.Get("Location"),
		setCookie: strings.Join(resp.Header.Values("Set-Cookie"), "; "),
		linkHdr:   strings.Join(resp.Header.Values("Link"), ", "),
		ctype:     resp.Header.Get("Content-Type"),
	}
}

// wpPost performs one POST with the shared WP client (for XML-RPC and login
// probes) and returns a bounded response.
func wpPost(ctx context.Context, rawURL, contentType, body string, maxBody int64) wpResp {
	rctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, rawURL, strings.NewReader(body))
	if err != nil {
		return wpResp{}
	}
	req.Header.Set("User-Agent", wpUserAgent)
	req.Header.Set("Content-Type", contentType)
	resp, err := wpHTTPClient.Do(req)
	if err != nil {
		return wpResp{}
	}
	defer resp.Body.Close()
	if maxBody <= 0 {
		maxBody = 128 * 1024
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return wpResp{
		status:    resp.StatusCode,
		body:      string(b),
		location:  resp.Header.Get("Location"),
		setCookie: strings.Join(resp.Header.Values("Set-Cookie"), "; "),
		linkHdr:   strings.Join(resp.Header.Values("Link"), ", "),
		ctype:     resp.Header.Get("Content-Type"),
	}
}

var (
	// meta generator: <meta name="generator" content="WordPress 6.4.2" />
	wpGeneratorRe = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s*([0-9][0-9.]*)?`)
	// enqueued core asset version: /wp-includes/js/wp-embed.min.js?ver=6.4.2
	wpAssetVerRe = regexp.MustCompile(`(?i)/wp-(?:includes|content)/[^"'?\s]+\?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	// readme.html version block: <br /> Version 6.4.2
	wpReadmeVerRe = regexp.MustCompile(`(?i)Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	// RSS/Atom feed generator: <generator>https://wordpress.org/?v=6.4.2</generator>
	wpFeedVerRe = regexp.MustCompile(`(?i)wordpress\.org/\?v=([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	// author-archive redirect target: /author/<slug>/
	wpAuthorPathRe = regexp.MustCompile(`(?i)/author/([A-Za-z0-9][A-Za-z0-9._-]{0,60})/?`)
)

// Run is the standalone WordPress DETECTION module (wp_detect). It force-refreshes
// the detection gate for the whole target and logs which hosts verified as
// WordPress. It is the mandatory first stage of the WP pipeline; every other WP
// module also calls ensureDetected so it is safe (and cheap — cached) to run them
// in any order.
func (s *WordPressScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	sites := s.detect(ctx, targetID, logFn, true)
	confirmed := 0
	for _, st := range sites {
		if st.isWordPress() {
			confirmed++
		}
	}
	logFn("warn", "wp_detect", wpSummary(len(sites), confirmed))
	if confirmed > 0 && s.broadcast != nil {
		s.broadcast("wp_detected", map[string]any{"target_id": targetID, "count": confirmed})
	}
	return ctx.Err()
}

func wpSummary(probed, confirmed int) string {
	return "WordPress detection gate done. " +
		itoa(confirmed) + " of " + itoa(probed) + " probed host(s) verified as WordPress."
}

// ensureDetected returns the CONFIRMED WordPress bases for a target, running the
// detection gate once if it has not run yet this scan. Every non-detection WP
// module starts here, so none of them can ever touch a non-WordPress host.
func (s *WordPressScanner) ensureDetected(ctx context.Context, targetID string, logFn LogFunc) []wpSite {
	if cached := s.loadConfirmedSites(ctx, targetID); len(cached) > 0 {
		return cached
	}
	// Only run a fresh detection pass if the gate has NEVER run for this target
	// (no rows at all). A target that was probed and found to have zero WordPress
	// hosts must not be re-probed by every module.
	if s.gateHasRun(ctx, targetID) {
		return nil
	}
	s.detect(ctx, targetID, logFn, false)
	return s.loadConfirmedSites(ctx, targetID)
}

func (s *WordPressScanner) gateHasRun(ctx context.Context, targetID string) bool {
	var n int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM wp_sites WHERE target_id=?`, targetID).Scan(&n)
	return n > 0
}

// detect probes every in-scope live host root, scores the WordPress signals, and
// upserts the verdict into wp_sites. force=true clears any prior verdicts first so
// the standalone wp_detect module always reflects the current state of the target.
func (s *WordPressScanner) detect(ctx context.Context, targetID string, logFn LogFunc, force bool) []wpSite {
	if force {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM wp_sites WHERE target_id=?`, targetID)
	}
	bases := s.loadHostBases(ctx, targetID)
	if len(bases) == 0 {
		return nil
	}
	logFn("info", "wp_detect", "Verifying WordPress across "+itoa(len(bases))+" live host(s) (deep multi-signal gate)...")

	sem := make(chan struct{}, 12)
	var wg sync.WaitGroup
	out := make([]wpSite, len(bases))
	for i, b := range bases {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, base string) {
			defer wg.Done()
			defer func() { <-sem }()
			out[i] = s.detectOne(ctx, base)
		}(i, b)
	}
	wg.Wait()

	for _, st := range out {
		if st.URL == "" {
			continue
		}
		s.storeSite(ctx, targetID, st)
		if st.isWordPress() {
			logFn("warn", "wp_detect", "WordPress confirmed: "+st.URL+
				wpVersionNote(st.Version)+" ["+strings.Join(st.Signals, ", ")+"]")
		}
	}
	return out
}

func wpVersionNote(v string) string {
	if v == "" {
		return ""
	}
	return " (v" + v + ")"
}

// detectOne runs the full signal battery against one base URL and returns a scored
// verdict. The two WordPress-UNIQUE signals (the wp/v2 REST namespace and the
// wp-login.php credential form) each independently clear the ConfEvidence bar, so
// a site is confirmed on either alone; the weaker corroborating signals only ever
// ADD to a verdict, never create one on their own without reaching the bar.
func (s *WordPressScanner) detectOne(ctx context.Context, base string) wpSite {
	site := wpSite{URL: base, Host: hostOf(base)}
	if ctx.Err() != nil {
		return site
	}

	add := func(points int, signal string) {
		site.Confidence += points
		site.Signals = append(site.Signals, signal)
	}
	setVer := func(v string) {
		if v != "" && site.Version == "" {
			site.Version = v
		}
	}

	// A catch-all/soft-404 baseline so an "everything is 200" host cannot turn a
	// bogus HTML page into a WordPress signal.
	bl := soft404Baseline(ctx, base)

	// (1) Homepage — meta generator, enqueued wp-* asset refs, REST link header.
	if home := wpGet(ctx, base+"/", 384*1024); home.status == 200 && !bl.matches(home.status, []byte(home.body), home.ctype) {
		if m := wpGeneratorRe.FindStringSubmatch(home.body); m != nil {
			add(60, "meta-generator")
			setVer(m[1])
		}
		if strings.Contains(home.body, "/wp-content/") || strings.Contains(home.body, "/wp-includes/") {
			add(40, "wp-asset-paths")
		}
		if m := wpAssetVerRe.FindStringSubmatch(home.body); m != nil {
			setVer(m[1])
		}
		if strings.Contains(strings.ToLower(home.linkHdr), "api.w.org") {
			add(55, "rest-link-header")
		}
	}

	// (2) REST API root — the wp/v2 namespace is essentially WordPress-unique.
	if rest := wpGet(ctx, base+"/wp-json/", 256*1024); rest.status == 200 &&
		strings.Contains(strings.ToLower(rest.ctype), "json") && wpRestNamespaceWP(rest.body) {
		add(90, "rest-wp-v2")
	}

	// (3) wp-login.php credential form — also WordPress-unique.
	if login := wpGet(ctx, base+"/wp-login.php", 128*1024); login.status == 200 && wpLoginForm(login.body) {
		add(90, "wp-login-form")
	} else if strings.Contains(strings.ToLower(login.setCookie), "wordpress_test_cookie") {
		add(70, "wp-test-cookie")
	}

	// (4) readme.html — present on many installs and definitive when it is.
	if rd := wpGet(ctx, base+"/readme.html", 128*1024); rd.status == 200 &&
		strings.Contains(rd.body, "WordPress") && strings.Contains(strings.ToLower(rd.body), "semantic personal publishing") {
		add(70, "readme")
		// The version sits right after the "Version" label in the masthead.
		if idx := strings.Index(rd.body, "Version"); idx >= 0 {
			if m := wpReadmeVerRe.FindStringSubmatch(rd.body[idx:]); m != nil {
				setVer(m[1])
			}
		}
	}

	// (5) Feed generator — corroborating version source.
	if site.Version == "" {
		if feed := wpGet(ctx, base+"/feed/", 128*1024); feed.status == 200 {
			if m := wpFeedVerRe.FindStringSubmatch(feed.body); m != nil {
				add(40, "feed-generator")
				setVer(m[1])
			}
		}
	}

	// (6) Author-archive redirect — /?author=1 → /author/<slug>/ (also used by the
	// user-enum module). Only counts when it is a genuine redirect to an author
	// path, not a catch-all 200.
	if a := wpGet(ctx, base+"/?author=1", 8*1024); (a.status == 301 || a.status == 302) &&
		wpAuthorPathRe.MatchString(a.location) {
		add(50, "author-redirect")
	}

	return site
}

// wpRestNamespaceWP reports whether a /wp-json/ body advertises the wp/v2
// namespace — the signal that is essentially unique to WordPress core.
func wpRestNamespaceWP(body string) bool {
	var root struct {
		Namespaces []string `json:"namespaces"`
	}
	if json.Unmarshal([]byte(body), &root) != nil {
		return false
	}
	for _, ns := range root.Namespaces {
		if ns == "wp/v2" {
			return true
		}
	}
	// Some hardened installs strip the namespace list but keep the routes map.
	return strings.Contains(body, `"/wp/v2"`) || strings.Contains(body, `\/wp\/v2`)
}

// wpLoginForm reports whether a body is the genuine wp-login.php form. It requires
// the two canonical field names TOGETHER plus a WordPress-specific marker, so a
// generic "log in" page cannot match.
func wpLoginForm(body string) bool {
	low := strings.ToLower(body)
	hasUser := strings.Contains(low, `name="log"`) || strings.Contains(low, "id=\"user_login\"")
	hasPass := strings.Contains(low, `name="pwd"`) || strings.Contains(low, "id=\"user_pass\"")
	marker := strings.Contains(low, "wordpress") || strings.Contains(low, "wp-submit") ||
		strings.Contains(low, "/wp-login.php") || strings.Contains(low, "wp-includes")
	return hasUser && hasPass && marker
}

// loadHostBases returns the distinct scheme://host[:port] roots of the target's
// live, in-scope HTTP services. The WP gate probes one root per host.
func (s *WordPressScanner) loadHostBases(ctx context.Context, targetID string) []string {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT url FROM http_services
		WHERE target_id = ? AND status_code BETWEEN 200 AND 403
		ORDER BY url`, targetID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	seen := map[string]bool{}
	var bases []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) != nil {
			continue
		}
		b := baseRoot(u)
		if b == "" || seen[b] {
			continue
		}
		seen[b] = true
		bases = append(bases, b)
	}
	return filterURLsByHostScope(ctx, bases)
}

// loadConfirmedSites returns the target's verified WordPress bases from the gate.
func (s *WordPressScanner) loadConfirmedSites(ctx context.Context, targetID string) []wpSite {
	rows, err := s.db.QueryContext(ctx, `
		SELECT url, host, version, confidence, signals FROM wp_sites
		WHERE target_id = ? AND is_wordpress = 1 ORDER BY url`, targetID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []wpSite
	for rows.Next() {
		var st wpSite
		var signals string
		if rows.Scan(&st.URL, &st.Host, &st.Version, &st.Confidence, &signals) != nil {
			continue
		}
		if signals != "" {
			st.Signals = strings.Split(signals, ", ")
		}
		out = append(out, st)
	}
	return filterWPSitesByHostScope(ctx, out)
}

// filterWPSitesByHostScope keeps only sites whose host is in the active host scope
// (per-asset prioritized scans scope each module to one host at a time).
func filterWPSitesByHostScope(ctx context.Context, sites []wpSite) []wpSite {
	urls := make([]string, 0, len(sites))
	for _, st := range sites {
		urls = append(urls, st.URL)
	}
	kept := filterURLsByHostScope(ctx, urls)
	keep := make(map[string]bool, len(kept))
	for _, u := range kept {
		keep[u] = true
	}
	out := make([]wpSite, 0, len(sites))
	for _, st := range sites {
		if keep[st.URL] {
			out = append(out, st)
		}
	}
	return out
}

func (s *WordPressScanner) storeSite(ctx context.Context, targetID string, st wpSite) {
	isWP := 0
	if st.isWordPress() {
		isWP = 1
	}
	_, _ = s.db.ExecContext(ctx, `
		INSERT INTO wp_sites (id, target_id, url, host, is_wordpress, version, confidence, signals, detected_at)
		VALUES (?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
		ON CONFLICT(target_id, url) DO UPDATE SET
			host=excluded.host, is_wordpress=excluded.is_wordpress, version=excluded.version,
			confidence=excluded.confidence, signals=excluded.signals, detected_at=CURRENT_TIMESTAMP`,
		uuid.New().String(), targetID, st.URL, st.Host, isWP, st.Version, st.Confidence,
		strings.Join(st.Signals, ", "))
}

// store records a WordPress finding through the canonical detector-observation
// pipeline (same path every other detector uses) so it dedupes, carries a POC
// (the Payload is the exact reproduction), and surfaces in the Findings UI. The
// reproduction for these GET-confirmed findings IS the URL that exposed them.
func (s *WordPressScanner) store(ctx context.Context, targetID, module, vulnType, severity, rawURL, evidence string) {
	confidence := ConfEvidence
	verdict := VerifyVerified
	if severity == "info" || strings.Contains(vulnType, "candidate") {
		confidence = ConfCandidateHi
		verdict = CandDetected
	}
	_, _ = RecordDetectorObservation(ctx, s.db, DetectorObservation{
		TargetID: targetID, Type: vulnType, Severity: severity, URL: rawURL, Method: "GET",
		Location: "response", Payload: rawURL, Evidence: evidence, Source: module,
		DetectionMethod: "wordpress:" + vulnType, Confidence: confidence, Verdict: verdict,
	})
}

// storeWithPayload is store() for findings whose reproduction is NOT a bare GET of
// the URL (e.g. an XML-RPC POST): payload carries the exact request to replay.
func (s *WordPressScanner) storeWithPayload(ctx context.Context, targetID, module, vulnType, severity, rawURL, method, payload, evidence string) {
	_, _ = RecordDetectorObservation(ctx, s.db, DetectorObservation{
		TargetID: targetID, Type: vulnType, Severity: severity, URL: rawURL, Method: method,
		Location: "response", Payload: payload, Evidence: evidence, Source: module,
		DetectionMethod: "wordpress:" + vulnType, Confidence: ConfEvidence, Verdict: VerifyVerified,
	})
}

func (s *WordPressScanner) notify(targetID, vulnType, u string) {
	if s.broadcast != nil {
		s.broadcast("new_vuln_finding", map[string]any{
			"target_id": targetID, "type": vulnType, "url": u,
		})
	}
}

// baseRoot reduces a URL to scheme://host[:port] with no trailing slash.
func baseRoot(rawURL string) string {
	u := strings.TrimSpace(rawURL)
	if u == "" {
		return ""
	}
	scheme := "https"
	if strings.HasPrefix(u, "http://") {
		scheme = "http"
		u = strings.TrimPrefix(u, "http://")
	} else if strings.HasPrefix(u, "https://") {
		u = strings.TrimPrefix(u, "https://")
	}
	if i := strings.IndexAny(u, "/?#"); i >= 0 {
		u = u[:i]
	}
	if u == "" {
		return ""
	}
	return scheme + "://" + u
}
