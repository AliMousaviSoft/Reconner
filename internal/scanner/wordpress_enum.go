package scanner

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// wordpress_enum.go — core version + plugin + theme enumeration (module wp_enum).
//
// Every item reported is CONFIRMED, never inferred:
//   - the core VERSION is read from an authoritative WordPress source (meta
//     generator, readme.html, the RSS feed generator, or an enqueued core asset's
//     ?ver=), recorded on the site during the detection gate;
//   - a PLUGIN is confirmed either because the live site itself references the
//     plugin's asset (/wp-content/plugins/<slug>/…) or because its readme.txt is
//     served with the WordPress-readme "Stable tag:" marker;
//   - a THEME is confirmed by its style.css header (Theme Name / Version).
//
// So wp_enum surfaces inventory a human could verify with a single GET — the raw
// material the known-CVE module (wp_vulns) later correlates against advisories.

// wpTopPluginSlugs is the curated, most-installed-first plugin slug list probed
// actively (readme.txt). Kept to high-traffic plugins so the active pass is a
// bounded, fast ~N requests per site; operators extend it via the wp_plugins
// corpus. Passive discovery (asset references on the live pages) finds the rest.
var wpTopPluginSlugs = []string{
	"akismet", "jetpack", "woocommerce", "contact-form-7", "wordpress-seo",
	"elementor", "elementor-pro", "classic-editor", "wpforms-lite", "all-in-one-seo-pack",
	"really-simple-ssl", "wordfence", "updraftplus", "google-site-kit", "wp-mail-smtp",
	"mailchimp-for-wp", "redirection", "w3-total-cache", "wp-super-cache", "litespeed-cache",
	"autoptimize", "wp-rocket", "seo-by-rank-math", "advanced-custom-fields", "tablepress",
	"wpbakery-page-builder", "js_composer", "revslider", "nextgen-gallery", "ninja-forms",
	"gravityforms", "wordpress-importer", "duplicate-post", "duplicator", "backwpup",
	"wpvivid-backuprestore", "all-in-one-wp-migration", "sucuri-scanner", "better-wp-security",
	"ithemes-security-pro", "limit-login-attempts-reloaded", "wps-hide-login", "two-factor",
	"loco-translate", "sitepress-multilingual-cms", "polylang", "cookie-law-info", "forminator",
	"essential-addons-for-elementor-lite", "elementskit-lite", "happy-elementor-addons",
	"wp-file-manager", "wp-super-cache", "smush", "ewww-image-optimizer", "regenerate-thumbnails",
	"buddypress", "bbpress", "learnpress", "tutor", "memberpress", "paid-memberships-pro",
	"easy-digital-downloads", "woocommerce-gateway-stripe", "woocommerce-pdf-invoices-packing-slips",
	"wpml-string-translation", "mailpoet", "the-events-calendar", "wp-statistics", "wordpress-popular-posts",
}

// wpTopThemeSlugs is the common-theme slug list probed actively (style.css). As
// with plugins, passive discovery from asset references finds the real theme most
// of the time; this list catches a theme the home page did not reference.
var wpTopThemeSlugs = []string{
	"twentytwentyfour", "twentytwentythree", "twentytwentytwo", "twentytwentyone",
	"twentytwenty", "twentynineteen", "twentyseventeen", "astra", "hello-elementor",
	"oceanwp", "generatepress", "kadence", "neve", "storefront", "divi", "betheme",
	"flatsome", "avada", "the7", "enfold", "salient", "x", "bridge", "jupiter",
}

var (
	wpPluginRefRe = regexp.MustCompile(`(?i)/wp-content/plugins/([a-z0-9][a-z0-9._-]{0,62})/`)
	wpThemeRefRe  = regexp.MustCompile(`(?i)/wp-content/themes/([a-z0-9][a-z0-9._-]{0,62})/`)
	// "Stable tag: 1.2.3" inside a plugin/theme readme.txt.
	wpStableTagRe = regexp.MustCompile(`(?im)^\s*Stable tag:\s*([0-9][0-9A-Za-z.\-]*)`)
	// style.css header fields.
	wpStyleNameRe = regexp.MustCompile(`(?im)^\s*Theme Name:\s*(.+)$`)
	wpStyleVerRe  = regexp.MustCompile(`(?im)^\s*Version:\s*([0-9][0-9A-Za-z.\-]*)`)
	// ?ver= on a specific plugin/theme asset.
	wpSlugVerRe = regexp.MustCompile(`(?i)\?ver=([0-9][0-9A-Za-z.\-]*)`)
)

// RunEnumeration implements wp_enum.
func (s *WordPressScanner) RunEnumeration(ctx context.Context, targetID string, logFn LogFunc) error {
	sites := s.ensureDetected(ctx, targetID, logFn)
	if len(sites) == 0 {
		logFn("info", "wp_enum", "No confirmed WordPress host for this target; nothing to enumerate.")
		return ctx.Err()
	}
	pluginSlugs := wpTopPluginSlugs
	themeSlugs := wpTopThemeSlugs
	if s.cfg != nil {
		pluginSlugs = LoadCorpus(s.cfg.WordlistsDir, "wp_plugins", wpTopPluginSlugs)
		themeSlugs = LoadCorpus(s.cfg.WordlistsDir, "wp_themes", wpTopThemeSlugs)
	}

	var versions, plugins, themes int64
	for _, site := range sites {
		if ctx.Err() != nil {
			break
		}
		logFn("info", "wp_enum", "Enumerating "+site.URL+" (core/plugins/themes)...")

		// ── Core version ──
		if site.Version != "" {
			s.store(ctx, targetID, "wp_enum", "wordpress_version", "info", site.URL+"/",
				"WordPress core version "+site.Version+" disclosed (signals: "+strings.Join(site.Signals, ", ")+"). Map it against core advisories; hide the generator/readme to reduce fingerprinting.")
			atomic.AddInt64(&versions, 1)
		}

		// ── Passive plugin/theme discovery from the live pages ──
		refPlugins := map[string]string{} // slug -> version (from ?ver=)
		refThemes := map[string]string{}
		for _, page := range s.enumPages(ctx, site.URL) {
			s.collectRefs(page, wpPluginRefRe, refPlugins)
			s.collectRefs(page, wpThemeRefRe, refThemes)
		}

		// ── Active, confirmed plugin probing (readme.txt) ──
		activePlugins := s.probePluginReadmes(ctx, site.URL, pluginSlugs)
		for slug, ver := range activePlugins {
			refPlugins[slug] = firstNonEmpty(ver, refPlugins[slug])
		}
		for _, slug := range wpSortedKeys(refPlugins) {
			ver := refPlugins[slug]
			ev := "WordPress plugin '" + slug + "' present"
			if ver != "" {
				ev += " (version " + ver + ")"
			}
			ev += " — confirmed from its own asset/readme. Cross-check '" + slug + "' " + verForAdvisory(ver) + " against plugin advisories (WPScan/CVE)."
			s.store(ctx, targetID, "wp_enum", "wordpress_plugin", "info", site.URL+"/wp-content/plugins/"+slug+"/", ev)
			atomic.AddInt64(&plugins, 1)
		}

		// ── Active, confirmed theme probing (style.css) ──
		activeThemes := s.probeThemeStyles(ctx, site.URL, mergeSlugs(themeSlugs, wpSortedKeys(refThemes)))
		for slug, ver := range activeThemes {
			refThemes[slug] = firstNonEmpty(ver, refThemes[slug])
		}
		for _, slug := range wpSortedKeys(refThemes) {
			ver := refThemes[slug]
			ev := "WordPress theme '" + slug + "' present"
			if ver != "" {
				ev += " (version " + ver + ")"
			}
			ev += " — confirmed from its asset/style.css."
			s.store(ctx, targetID, "wp_enum", "wordpress_theme", "info", site.URL+"/wp-content/themes/"+slug+"/", ev)
			atomic.AddInt64(&themes, 1)
		}
	}
	logFn("warn", "wp_enum", "WordPress enumeration done. versions="+itoa(int(versions))+
		" plugins="+itoa(int(plugins))+" themes="+itoa(int(themes))+".")
	return ctx.Err()
}

// enumPages fetches a small set of pages likely to reference the active plugins
// and theme: the home page and the REST root (which lists active plugin routes on
// some installs). Bounded so enumeration stays fast.
func (s *WordPressScanner) enumPages(ctx context.Context, base string) []string {
	var out []string
	if h := wpGet(ctx, base+"/", 512*1024); h.status == 200 {
		out = append(out, h.body)
	}
	if f := wpGet(ctx, base+"/feed/", 128*1024); f.status == 200 {
		out = append(out, f.body)
	}
	return out
}

func (s *WordPressScanner) collectRefs(body string, re *regexp.Regexp, into map[string]string) {
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		slug := strings.ToLower(m[1])
		if slug == "" || !validWPSlug(slug) {
			continue
		}
		if _, ok := into[slug]; !ok {
			into[slug] = ""
		}
		// Pull a ?ver= attached to an asset under this slug's directory so the
		// reported version is the one the site actually loads.
		if vm := wpSlugVerForSlug(body, slug); vm != "" {
			into[slug] = vm
		}
	}
}

// wpSlugVerForSlug finds a ?ver= value attached to an asset under the given slug's
// plugin/theme directory, so a reported version is the one the site actually loads.
func wpSlugVerForSlug(body, slug string) string {
	low := strings.ToLower(body)
	marker := "/" + slug + "/"
	start := 0
	for {
		i := strings.Index(low[start:], marker)
		if i < 0 {
			return ""
		}
		seg := body[start+i:]
		end := len(seg)
		if j := strings.IndexAny(seg, "\"'<> \t\n"); j >= 0 {
			end = j
		}
		if m := wpSlugVerRe.FindStringSubmatch(seg[:end]); m != nil {
			return m[1]
		}
		start += i + len(marker)
		if start >= len(low) {
			return ""
		}
	}
}

// probePluginReadmes actively confirms plugins from a slug list by fetching
// /wp-content/plugins/<slug>/readme.txt and requiring the WordPress-readme
// "Stable tag:" marker (zero-FP: a soft-404 HTML page never carries it). Returns
// slug -> version.
func (s *WordPressScanner) probePluginReadmes(ctx context.Context, base string, slugs []string) map[string]string {
	return s.probeReadmeCorpus(ctx, base, "plugins", slugs)
}

func (s *WordPressScanner) probeThemeStyles(ctx context.Context, base string, slugs []string) map[string]string {
	bl := soft404Baseline(ctx, base)
	out := map[string]string{}
	var mu sync.Mutex
	sem := make(chan struct{}, 12)
	var wg sync.WaitGroup
	for _, slug := range slugs {
		if ctx.Err() != nil {
			break
		}
		if !validWPSlug(slug) {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(slug string) {
			defer wg.Done()
			defer func() { <-sem }()
			r := wpGet(ctx, base+"/wp-content/themes/"+slug+"/style.css", 64*1024)
			if r.status != 200 || bl.matches(r.status, []byte(r.body), r.ctype) {
				return
			}
			// A real theme style.css has the Theme Name header; HTML pages don't.
			if !wpStyleNameRe.MatchString(r.body) {
				return
			}
			ver := ""
			if m := wpStyleVerRe.FindStringSubmatch(r.body); m != nil {
				ver = m[1]
			}
			mu.Lock()
			out[slug] = ver
			mu.Unlock()
		}(slug)
	}
	wg.Wait()
	return out
}

func (s *WordPressScanner) probeReadmeCorpus(ctx context.Context, base, kind string, slugs []string) map[string]string {
	bl := soft404Baseline(ctx, base)
	out := map[string]string{}
	var mu sync.Mutex
	sem := make(chan struct{}, 12)
	var wg sync.WaitGroup
	for _, slug := range slugs {
		if ctx.Err() != nil {
			break
		}
		if !validWPSlug(slug) {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(slug string) {
			defer wg.Done()
			defer func() { <-sem }()
			r := wpGet(ctx, base+"/wp-content/"+kind+"/"+slug+"/readme.txt", 64*1024)
			if r.status != 200 || bl.matches(r.status, []byte(r.body), r.ctype) {
				return
			}
			// readme.txt is confirmed by the WordPress "Stable tag:" marker.
			if !wpStableTagRe.MatchString(r.body) {
				return
			}
			ver := ""
			if m := wpStableTagRe.FindStringSubmatch(r.body); m != nil {
				ver = m[1]
			}
			mu.Lock()
			out[slug] = ver
			mu.Unlock()
		}(slug)
	}
	wg.Wait()
	return out
}

// validWPSlug rejects path segments that are not real plugin/theme slugs (avoids
// turning a stray /wp-content/plugins/ or an encoded fragment into a "plugin").
func validWPSlug(slug string) bool {
	if len(slug) < 2 || len(slug) > 64 {
		return false
	}
	switch slug {
	case "index", "css", "js", "images", "img", "assets", "fonts", "cache", "uploads":
		return false
	}
	for _, r := range slug {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func verForAdvisory(v string) string {
	if v == "" {
		return "(version unknown)"
	}
	return "v" + v
}

func wpSortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mergeSlugs(a []string, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
