package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/pkg/logger"
)

// HeadlessCrawler renders pages in a REAL headless browser and harvests the attack
// surface a raw-HTTP crawler structurally cannot see: links the framework injects
// into the DOM after hydration (SPA client-side routing), form fields, and
// parameterized URLs that only exist once JavaScript runs. Everything it discovers
// is stored as parameters, so the XSS/DAST engines test the REAL rendered surface,
// not just the shipped HTML. It is deliberately bounded (page budget + depth) since
// each page is a full browser navigation.
type HeadlessCrawler struct {
	db     *database.DB
	cfg    *config.Config
	logger *logger.Logger
}

func NewHeadlessCrawler(db *database.DB, cfg *config.Config, log *logger.Logger) *HeadlessCrawler {
	return &HeadlessCrawler{db: db, cfg: cfg, logger: log}
}

// crawl bounds — every page is a real browser render, so they stay bounded, but
// they SCALE WITH THE SPEED PROFILE: a fast scan stays shallow for throughput, a
// slow scan crawls deep. The network-capture layer (see netCapture) multiplies
// coverage PER PAGE without needing more pages, so even the fast budget now sees
// the app's real XHR/fetch API surface.
const (
	headlessMaxPages = 120
	headlessMaxDepth = 3
	headlessSeedCap  = 40
	headlessNavWait  = 1100 * time.Millisecond
)

// headlessBudget returns (maxPages, maxDepth, seedCap) for the active speed
// profile. Normal is the const default above; fast trims for throughput; slow
// crawls far deeper (opt-in thoroughness).
func headlessBudget(ctx context.Context) (int, int, int) {
	switch webSpeedFromCtx(ctx) {
	case SpeedFast:
		return 60, 2, 20
	case SpeedSlow:
		return 300, 4, 80
	default:
		return headlessMaxPages, headlessMaxDepth, headlessSeedCap
	}
}

// capturedNetReq is one HTTP request the browser fired while rendering/interacting
// with a page — the real client→server traffic (XHR/fetch/navigation), which is
// the richest attack surface in a modern JS app and is invisible to a link/form
// scrape. Captured passively via the CDP Network domain.
type capturedNetReq struct {
	method, url, contentType, postData string
}

// netCapture accumulates the browser's in-scope requests across the whole crawl.
// The CDP event callback runs on chromedp's event goroutine, so every field is
// guarded by mu and the callback never blocks (it only parses + appends).
type netCapture struct {
	mu   sync.Mutex
	seen map[string]bool
	reqs []capturedNetReq
	cap  int
}

func newNetCapture(capacity int) *netCapture {
	return &netCapture{seen: make(map[string]bool), cap: capacity}
}

func (n *netCapture) add(r capturedNetReq) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.reqs) >= n.cap {
		return
	}
	// Dedup on method + URL + a coarse body shape so ?id=1 and ?id=2, or two POSTs
	// with different values to the same endpoint, collapse to one insertion point.
	key := strings.ToUpper(r.method) + " " + collapseURLValues(r.url) + " |" + bodyShapeKey(r.postData)
	if n.seen[key] {
		return
	}
	n.seen[key] = true
	n.reqs = append(n.reqs, r)
}

// netHeaderContentType reads Content-Type (case-insensitive) from a CDP
// network.Headers map (map[string]any whose values are usually strings).
func netHeaderContentType(h network.Headers) string {
	for k, v := range h {
		if strings.EqualFold(k, "content-type") {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

// netPostData returns the request body. CDP delivers it as PostDataEntries whose
// Bytes are base64-encoded; decode and concatenate. A body too large for the
// protocol is omitted (HasPostData true, entries empty) — acceptable, since our
// shape-based dedup only needs the field NAMES, not full values.
func netPostData(r *network.Request) string {
	if len(r.PostDataEntries) == 0 {
		return ""
	}
	var b strings.Builder
	for _, e := range r.PostDataEntries {
		if e == nil || e.Bytes == "" {
			continue
		}
		if dec, err := base64.StdEncoding.DecodeString(e.Bytes); err == nil {
			b.Write(dec)
		} else {
			b.WriteString(e.Bytes)
		}
	}
	return b.String()
}

func (n *netCapture) snapshot() []capturedNetReq {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]capturedNetReq, len(n.reqs))
	copy(out, n.reqs)
	return out
}

// collapseURLValues normalizes a URL to method-key identity: host+path + the SET
// of query NAMES (values dropped), so value-variants of the same endpoint dedup.
func collapseURLValues(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	var names []string
	for name := range u.Query() {
		names = append(names, strings.ToLower(name))
	}
	sortStrings(names)
	return strings.ToLower(u.Host) + u.Path + "?" + strings.Join(names, ",")
}

// bodyShapeKey reduces a request body to a stable shape signature (the set of
// JSON keys, or form field names) so bodies that differ only in values dedup.
func bodyShapeKey(body string) string {
	body = strings.TrimSpace(body)
	if body == "" {
		return ""
	}
	if leaves := jsonBodyLeaves(body); len(leaves) > 0 {
		names := make([]string, 0, len(leaves))
		for _, l := range leaves {
			names = append(names, l.path)
		}
		sortStrings(names)
		return "json:" + strings.Join(names, ",")
	}
	if vals, err := url.ParseQuery(body); err == nil && len(vals) > 0 {
		var names []string
		for name := range vals {
			names = append(names, name)
		}
		sortStrings(names)
		return "form:" + strings.Join(names, ",")
	}
	// Opaque body: length bucket keeps a few representatives without exploding.
	return fmt.Sprintf("raw:%d", len(body)/64)
}

type jsonLeaf struct {
	path string
	typ  string
}

// jsonBodyLeaves parses a JSON request body and returns its leaf fields as
// dotted paths with a JSON type, matching the dotted-path convention
// buildJSONFieldsTyped/insertion.go consume (which split names on "."). Arrays
// recurse into their first element under the SAME path (object-nesting
// semantics); an empty array/object is itself a leaf. Bounded to keep a huge API
// payload from exploding the insertion-point set.
func jsonBodyLeaves(body string) []jsonLeaf {
	var root interface{}
	if json.Unmarshal([]byte(strings.TrimSpace(body)), &root) != nil {
		return nil
	}
	var out []jsonLeaf
	var walk func(prefix string, v interface{})
	walk = func(prefix string, v interface{}) {
		if len(out) >= 60 {
			return
		}
		switch t := v.(type) {
		case map[string]interface{}:
			if len(t) == 0 {
				if prefix != "" {
					out = append(out, jsonLeaf{prefix, "object"})
				}
				return
			}
			for k, cv := range t {
				k = strings.TrimSpace(k)
				if k == "" || strings.ContainsAny(k, ".") {
					continue // a dotted key would corrupt the path convention
				}
				next := k
				if prefix != "" {
					next = prefix + "." + k
				}
				walk(next, cv)
			}
		case []interface{}:
			if len(t) == 0 {
				if prefix != "" {
					out = append(out, jsonLeaf{prefix, "array"})
				}
				return
			}
			walk(prefix, t[0])
		default:
			if prefix != "" {
				out = append(out, jsonLeaf{prefix, jsonScalarType(v)})
			}
		}
	}
	walk("", root)
	return out
}

func jsonScalarType(v interface{}) string {
	switch n := v.(type) {
	case bool:
		return "boolean"
	case float64:
		if n == float64(int64(n)) {
			return "integer"
		}
		return "number"
	case json.Number:
		if strings.ContainsAny(n.String(), ".eE") {
			return "number"
		}
		return "integer"
	default:
		return "string"
	}
}

// insertionPointsFromRequest turns one captured request into the insertion points
// the injection engines consume: query params, JSON-body leaves (location
// json:<type>), or form-body fields (location body). GET requests contribute only
// their query params; write requests contribute their body shape too. Returns nil
// for a request that carries no testable parameter (a bare endpoint hit).
func insertionPointsFromRequest(r capturedNetReq) []paramEntry {
	method := strings.ToUpper(strings.TrimSpace(r.method))
	if method == "" {
		method = http.MethodGet
	}
	u, err := url.Parse(r.url)
	if err != nil {
		return nil
	}
	var out []paramEntry
	// Query parameters — present on every method.
	for name, vals := range u.Query() {
		if name == "" || isJunkParam(name) {
			continue
		}
		val := ""
		if len(vals) > 0 {
			val = vals[0]
		}
		out = append(out, paramEntry{
			URL: r.url, Param: name, Value: val, Source: "headless-xhr",
			Method: method, ContentType: "", Location: "query",
		})
	}
	// Request body — only for state-carrying methods with an actual body.
	body := strings.TrimSpace(r.postData)
	if method != http.MethodGet && method != http.MethodHead && body != "" {
		endpoint := *u
		endpoint.RawQuery = ""
		endpoint.Fragment = ""
		ep := endpoint.String()
		ct := strings.ToLower(strings.TrimSpace(r.contentType))
		if leaves := jsonBodyLeaves(body); len(leaves) > 0 && (strings.Contains(ct, "json") || ct == "" || strings.HasPrefix(body, "{") || strings.HasPrefix(body, "[")) {
			for _, leaf := range leaves {
				out = append(out, paramEntry{
					URL: ep, Param: leaf.path, Value: jsonPlaceholder(leaf.typ),
					Source: "headless-xhr", Method: method,
					ContentType: "application/json", Location: "json:" + leaf.typ,
				})
			}
		} else if vals, perr := url.ParseQuery(body); perr == nil && len(vals) > 0 && !strings.Contains(ct, "json") {
			for name, v := range vals {
				if name == "" || isJunkParam(name) {
					continue
				}
				val := ""
				if len(v) > 0 {
					val = v[0]
				}
				formCT := ct
				if formCT == "" {
					formCT = "application/x-www-form-urlencoded"
				}
				out = append(out, paramEntry{
					URL: ep, Param: name, Value: val, Source: "headless-xhr",
					Method: method, ContentType: formCT, Location: "body",
				})
			}
		}
	}
	return out
}

func jsonPlaceholder(typ string) string {
	switch typ {
	case "integer", "number":
		return "1"
	case "boolean":
		return "true"
	case "object":
		return "{}"
	case "array":
		return "[]"
	default:
		return ""
	}
}

// formInfo is a discovered HTML form (rendered).
type formInfo struct {
	Action   string          `json:"action"`
	Method   string          `json:"method"`
	Encoding string          `json:"encoding"`
	Inputs   []formInputInfo `json:"inputs"`
}

type formInputInfo struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// pageSurface is what one rendered page yields.
type pageSurface struct {
	Links          []string   `json:"links"`
	Forms          []formInfo `json:"forms"`
	StateCount     int        `json:"stateCount"`
	TransitionURLs []string   `json:"transitionURLs"`
	States         []string   `json:"states"`
}

// extractJS runs in the page to collect rendered links + forms. It reads the LIVE
// DOM (post-hydration), so SPA-injected anchors and dynamically-built forms are
// captured — exactly what an HTTP crawl misses.
const extractJS = `(async() => {
  const links=new Set(), forms=new Map(), states=new Set(), transitionURLs=new Set();
  const roots=()=>{const out=[document];for(let i=0;i<out.length;i++){
    const r=out[i];for(const e of r.querySelectorAll?r.querySelectorAll('*'):[]){if(e.shadowRoot)out.push(e.shadowRoot)}
    if(r===document){for(const f of document.querySelectorAll('iframe')){try{if(f.contentDocument)out.push(f.contentDocument)}catch(_){}}}
  }return out};
  const snapshot=()=>{const rs=roots(), shape=[];for(const r of rs){
    for(const a of r.querySelectorAll?r.querySelectorAll('a[href],[role="link"][href]'):[]){try{if(a.href)links.add(a.href)}catch(_){}}
    for(const f of r.querySelectorAll?r.querySelectorAll('form'):[]){
      const item={action:f.action||location.href,method:(f.method||'get').toLowerCase(),encoding:(f.enctype||'').toLowerCase(),inputs:[...f.elements]
        .filter(e=>e.name&&!e.matches(':disabled')&&!['submit','button','reset','file'].includes(e.type)&&(!['checkbox','radio'].includes(e.type)||e.checked))
        .map(e=>({name:e.name,value:e.type==='file'?'':(e.value||'') }))};
      forms.set(JSON.stringify(item),item)
    }
    shape.push(...[...(r.querySelectorAll?r.querySelectorAll('a[href],form,input[name],button,[role="tab"],details'):[])].slice(0,250).map(e=>e.tagName+':'+(e.getAttribute('role')||'')+':'+(e.getAttribute('name')||'')+':'+(e.getAttribute('aria-controls')||'')))
  }
  states.add(location.href+'|'+shape.sort().join(','));transitionURLs.add(location.href)};
  snapshot();
  // Interact only with navigation-like, non-submitting controls. Generic buttons
  // are intentionally excluded because an arbitrary click may mutate server state.
  const safe=[...document.querySelectorAll('a[href^="#"],[role="tab"][aria-controls],details:not([open])>summary')].slice(0,12);
  for(const el of safe){try{el.click();await new Promise(r=>setTimeout(r,80));snapshot()}catch(_){}}
  return JSON.stringify({links:[...links].slice(0,750),forms:[...forms.values()].slice(0,100),stateCount:states.size,transitionURLs:[...transitionURLs].slice(0,50),states:[...states].slice(0,20)});
})()`

// Run drives the bounded headless crawl for a target.
func (c *HeadlessCrawler) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	chromePath := findChromePath()
	if chromePath == "" {
		logFn("info", "headless_crawl", "No headless Chromium available — rendered crawl blocked.")
		return BlockedPhase("Chromium is unavailable for rendered crawling")
	}

	domain := c.targetDomain(ctx, targetID)
	if domain == "" {
		return fmt.Errorf("headless crawl target domain is empty")
	}

	maxPages, maxDepth, seedCap := headlessBudget(ctx)

	seeds := c.seedURLs(ctx, targetID, seedCap)
	RecordCoverage(ctx, CoverageDiscovered, int64(len(seeds)))
	RecordCoverage(ctx, CoverageEligible, int64(len(seeds)))
	if len(seeds) == 0 {
		logFn("info", "headless_crawl", "No HTML hosts to render — skipping.")
		return nil
	}
	logFn("info", "headless_crawl", fmt.Sprintf("Rendering up to %d page(s) from %d seed(s) in a headless browser (SPA-aware surface discovery)...", maxPages, len(seeds)))

	// dedicated, isolated browser for the crawl (does not share the XSS confirmer's tab).
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(chromePath),
		chromedp.Flag("headless", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("blink-settings", "imagesEnabled=false"), // faster: skip images
		chromedp.NoDefaultBrowserCheck,
	)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, opts...)
	defer cancelAlloc()
	noop := func(string, ...interface{}) {}
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx, chromedp.WithErrorf(noop), chromedp.WithLogf(noop))
	defer cancelBrowser()
	if err := chromedp.Run(browserCtx); err != nil {
		logFn("info", "headless_crawl", "Headless browser failed to start — rendered crawl blocked.")
		return BlockedPhase("Chromium failed to start: " + err.Error())
	}
	headerActions, stopHeaders := scopedBrowserHeaderSession(browserCtx, browserCtx, ctx, seeds, nil)
	defer stopHeaders()
	if len(headerActions) > 0 {
		if err := chromedp.Run(browserCtx, headerActions...); err != nil {
			logFn("warn", "headless_crawl", "Could not configure scoped request identity; rendered crawl blocked.")
			return BlockedPhase("could not configure scoped browser request identity: " + err.Error())
		}
	}

	// Passive network capture: every XHR/fetch/navigation the app fires while we
	// render becomes an insertion point. This is the real API attack surface of a
	// modern JS app — the endpoints the client calls at runtime — which a link/form
	// scrape structurally cannot see. We only OBSERVE (CDP requestWillBeSent); we
	// never continue/modify requests here (the header session owns fetch), so this
	// adds no latency and cannot alter the page's own traffic. In-scope filtering
	// happens in the callback so out-of-scope third-party/analytics calls are dropped
	// before they ever reach the collector.
	collector := newNetCapture(maxPages * 16)
	chromedp.ListenTarget(browserCtx, func(ev any) {
		req, ok := ev.(*network.EventRequestWillBeSent)
		if !ok || req.Request == nil {
			return
		}
		switch req.Type {
		case network.ResourceTypeXHR, network.ResourceTypeFetch, network.ResourceTypeDocument:
		default:
			return // scripts, images, styles, fonts, media, ws — not request insertion points
		}
		ru, err := url.Parse(req.Request.URL)
		if err != nil {
			return
		}
		if !c.inScope(ru.Hostname(), domain) || !urlHostInScope(ctx, req.Request.URL) {
			return
		}
		collector.add(capturedNetReq{
			method:      req.Request.Method,
			url:         req.Request.URL,
			contentType: netHeaderContentType(req.Request.Headers),
			postData:    netPostData(req.Request),
		})
	})
	if err := chromedp.Run(browserCtx, network.Enable()); err != nil {
		logFn("warn", "headless_crawl", "Could not enable network capture; continuing with DOM-only crawl.")
	}

	type qi struct {
		url   string
		depth int
	}
	seen := map[string]bool{}
	var queue []qi
	for _, s := range seeds {
		if !seen[s] {
			seen[s] = true
			queue = append(queue, qi{s, 0})
		}
	}

	pages := 0
	var params []paramEntry
	pushParam := func(u, name, value, source, method, contentType, location string) {
		params = append(params, paramEntry{
			URL: u, Param: name, Value: value, Source: source,
			Method: method, ContentType: contentType, Location: location,
		})
	}

	for len(queue) > 0 && pages < maxPages {
		if ctx.Err() != nil {
			break
		}
		cur := queue[0]
		queue = queue[1:]
		pages++
		RecordCoverage(ctx, CoverageAttempted, 1)

		surf, ok := c.renderPage(browserCtx, cur.url)
		if !ok {
			RecordCoverage(ctx, CoverageError, 1)
			continue
		}
		if surf.StateCount > 1 {
			RecordCoverage(ctx, CoverageDiscovered, int64(surf.StateCount-1))
		}
		c.storeStates(ctx, targetID, cur.url, surf.States)
		if pages%10 == 0 {
			logFn("info", "headless_crawl", fmt.Sprintf("Rendered %d/%d page(s)...", pages, maxPages))
		}

		// links → in-scope, enqueue for deeper crawl, and harvest their query params.
		for _, l := range surf.Links {
			lu, err := url.Parse(l)
			if err != nil {
				continue
			}
			lu.Fragment = ""
			if !c.inScope(lu.Hostname(), domain) || !urlHostInScope(ctx, lu.String()) || !urlInEndpointScope(ctx, lu.String()) {
				continue
			}
			for name := range lu.Query() {
				if name != "" && !isJunkParam(name) {
					pushParam(lu.String(), name, lu.Query().Get(name), "headless", http.MethodGet, "", "query")
				}
			}
			norm := lu.String()
			if !seen[norm] && cur.depth < maxDepth && len(seen) < maxPages*4 {
				seen[norm] = true
				queue = append(queue, qi{norm, cur.depth + 1})
				RecordCoverage(ctx, CoverageEligible, 1)
			}
		}
		for _, transition := range surf.TransitionURLs {
			tu, err := url.Parse(transition)
			if err != nil || !c.inScope(tu.Hostname(), domain) || !urlHostInScope(ctx, tu.String()) || !urlInEndpointScope(ctx, tu.String()) {
				continue
			}
			tu.Fragment = ""
			norm := tu.String()
			if !seen[norm] && cur.depth < maxDepth && len(seen) < maxPages*4 {
				seen[norm] = true
				queue = append(queue, qi{norm, cur.depth + 1})
				RecordCoverage(ctx, CoverageEligible, 1)
			}
		}
		// forms → each named input is an insertion point (with the form's method).
		for _, f := range surf.Forms {
			fa, err := url.Parse(f.Action)
			if err != nil || !c.inScope(fa.Hostname(), domain) || !urlHostInScope(ctx, fa.String()) || !urlInEndpointScope(ctx, fa.String()) {
				continue
			}
			method := strings.ToUpper(strings.TrimSpace(f.Method))
			if method != http.MethodPost {
				method = http.MethodGet
			}
			contentType, location := "", "query"
			if method == http.MethodPost {
				contentType = strings.ToLower(strings.TrimSpace(f.Encoding))
				if contentType == "" {
					contentType = "application/x-www-form-urlencoded"
				}
				location = "body"
				if strings.Contains(contentType, "multipart/form-data") {
					location = "multipart"
				}
			}
			for _, in := range f.Inputs {
				// Preserve every successful form control, including CSRF/action
				// plumbing: downstream injectors need those values as required
				// siblings even when the field itself is not a useful candidate.
				if in.Name != "" {
					pushParam(fa.String(), in.Name, in.Value, "headless-form", method, contentType, location)
				}
			}
		}
	}

	// Fold in the runtime API surface: every in-scope XHR/fetch/navigation the app
	// fired while we rendered becomes an insertion point (query params, JSON-body
	// leaves, form fields). This is the leap over a DOM-only crawl — the endpoints a
	// SPA calls at runtime are invisible to a link/form scrape but are the richest
	// attack surface of a modern app.
	captured := collector.snapshot()
	xhrPoints := 0
	for _, r := range captured {
		pts := insertionPointsFromRequest(r)
		params = append(params, pts...)
		xhrPoints += len(pts)
	}

	stored := c.storeParams(ctx, targetID, params)
	RecordCoverage(ctx, CoverageDiscovered, int64(stored))
	logFn("warn", "headless_crawl", fmt.Sprintf("Headless crawl done. Rendered %d page(s); captured %d runtime request(s) → %d XHR/API insertion point(s); harvested %d parameter insertion point(s) total from the live DOM + runtime traffic.", pages, len(captured), xhrPoints, stored))
	return nil
}

func (c *HeadlessCrawler) storeStates(ctx context.Context, targetID, pageURL string, states []string) {
	parent := ""
	for sequence, state := range states {
		if strings.TrimSpace(state) == "" {
			continue
		}
		fingerprint := fmt.Sprintf("%x", sha256.Sum256([]byte(state)))
		_, _ = c.db.ExecContext(ctx, `INSERT INTO browser_states
			(id,target_id,url,fingerprint,parent_fingerprint,sequence,source)
			VALUES(?,?,?,?,?,?,'headless')
			ON CONFLICT(target_id,fingerprint) DO UPDATE SET
				url=excluded.url,parent_fingerprint=excluded.parent_fingerprint,sequence=excluded.sequence`,
			uuid.NewString(), targetID, pageURL, fingerprint, parent, sequence)
		parent = fingerprint
	}
}

// renderPage navigates to url, waits for hydration, and extracts links + forms.
func (c *HeadlessCrawler) renderPage(parent context.Context, pageURL string) (pageSurface, bool) {
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	var raw string
	err := chromedp.Run(ctx,
		chromedp.Navigate(pageURL),
		chromedp.Sleep(headlessNavWait),
		chromedp.Evaluate(extractJS, &raw),
	)
	if err != nil || raw == "" {
		return pageSurface{}, false
	}
	var surf pageSurface
	if json.Unmarshal([]byte(raw), &surf) != nil {
		return pageSurface{}, false
	}
	return surf, true
}

// seedURLs returns the HTML hosts to start the render crawl from (probe sources).
func (c *HeadlessCrawler) seedURLs(ctx context.Context, targetID string, seedCap int) []string {
	rows, err := c.db.QueryContext(ctx, `
		SELECT url FROM http_services
		WHERE target_id = ? AND COALESCE(source,'probe') IN ('probe','seed')
		ORDER BY LENGTH(url) ASC LIMIT ?`, targetID, seedCap)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) == nil && strings.HasPrefix(u, "http") {
			out = append(out, u)
		}
	}
	return out
}

func (c *HeadlessCrawler) targetDomain(ctx context.Context, targetID string) string {
	var d string
	_ = c.db.QueryRowContext(ctx, "SELECT domain FROM targets WHERE id = ?", targetID).Scan(&d)
	return strings.ToLower(strings.TrimSpace(d))
}

// inScope keeps the crawl on the target's registrable domain (or a subdomain).
func (c *HeadlessCrawler) inScope(host, domain string) bool {
	host = normalizeHost(host)
	if host == "" || isBlockedHost(host) {
		return false
	}
	d := normalizeHost(domain)
	return host == d || strings.HasSuffix(host, "."+d) || sameRegistrable(host, d)
}

// storeParams inserts the harvested insertion points (batched, ON CONFLICT no-op).
func (c *HeadlessCrawler) storeParams(ctx context.Context, targetID string, params []paramEntry) int {
	if len(params) == 0 {
		return 0
	}
	stored := 0
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return 0
	}
	for _, p := range params {
		// Single-endpoint mode: only keep insertion points under the seed URL.
		if !urlInEndpointScope(ctx, p.URL) {
			continue
		}
		method := strings.ToUpper(strings.TrimSpace(p.Method))
		contentType := strings.TrimSpace(p.ContentType)
		location := strings.ToLower(strings.TrimSpace(p.Location))
		if method == "" {
			method = http.MethodGet
			if strings.Contains(p.Source, "form") {
				method = http.MethodPost
			}
		}
		if location == "" {
			location = "query"
			if method != http.MethodGet {
				location = "body"
			}
		}
		if method != http.MethodGet && contentType == "" {
			contentType = "application/x-www-form-urlencoded"
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO parameters (id,target_id,url,parameter,value,source,method,content_type,location)
			VALUES (?,?,?,?,?,?,?,?,?)
			ON CONFLICT(target_id,url,parameter,method,location,content_type) DO UPDATE SET
				value=CASE WHEN excluded.value<>'' THEN excluded.value ELSE parameters.value END,
				source=CASE WHEN parameters.source='' THEN excluded.source ELSE parameters.source END`,
			uuid.New().String(), targetID, p.URL, p.Param, p.Value, p.Source, method, contentType, location); err == nil {
			stored++
		}
	}
	if tx.Commit() != nil {
		return 0
	}
	return stored
}
