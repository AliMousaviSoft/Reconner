package scanner

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

// wordpress_exposure.go — wp-config and sensitive-file exposure (module wp_config).
//
// Zero false positives by construction: a path returning 200 is NEVER a finding on
// its own. A wp-config variant is reported ONLY when its body actually carries the
// raw configuration source (DB credentials or the AUTH/SECRET salts, or a Vim swap
// of it); debug.log ONLY when the body is a genuine PHP error log; a directory
// index ONLY when the response is a real autoindex listing. Each is a catastrophic,
// directly-verifiable leak, and the reproduction is the exact URL.

// wpConfigLeakPaths are the wp-config backup / editor-swap variants a careless
// edit or deploy leaves world-readable. The live wp-config.php itself is probed
// too (a mis-handled .php that serves its source is game over).
var wpConfigLeakPaths = []string{
	"/wp-config.php", "/wp-config.php.bak", "/wp-config.php.bak2", "/wp-config.php~",
	"/wp-config.php.save", "/wp-config.php.swp", "/wp-config.php.swo", "/wp-config.php.orig",
	"/wp-config.php.old", "/wp-config.php.txt", "/wp-config.php.dist.bak", "/wp-config.php.1",
	"/wp-config.php_bak", "/wp-config.php.inc", "/wp-config.php.tmp", "/wp-config.php.backup",
	"/wp-config.bak", "/wp-config.old", "/wp-config.txt", "/wp-config.inc",
	"/.wp-config.php.swp", "/wp-config.php.disabled", "/wp-config-backup.txt",
	"/wp-config.php.original", "/wp-config.save",
}

var (
	// A PHP error log line: "[18-Jan-2026 01:30:22 UTC] PHP Warning: ..."
	wpDebugLogRe = regexp.MustCompile(`(?i)\[\d{2}-[A-Za-z]{3}-\d{4}[^\]]*\]\s*PHP\s+(Notice|Warning|Fatal error|Deprecated|Parse error|Error)`)
	// Apache/nginx autoindex listing.
	wpAutoindexRe = regexp.MustCompile(`(?i)<title>\s*Index of\s*/|<h1>\s*Index of\s*/`)
)

// RunConfigExposure implements wp_config.
func (s *WordPressScanner) RunConfigExposure(ctx context.Context, targetID string, logFn LogFunc) error {
	sites := s.ensureDetected(ctx, targetID, logFn)
	if len(sites) == 0 {
		logFn("info", "wp_config", "No confirmed WordPress host for this target; nothing to check.")
		return ctx.Err()
	}
	paths := wpConfigLeakPaths
	if s.cfg != nil {
		paths = LoadCorpus(s.cfg.WordlistsDir, "wp_config_paths", wpConfigLeakPaths)
	}

	var found atomic.Int64
	for _, site := range sites {
		if ctx.Err() != nil {
			break
		}
		logFn("info", "wp_config", "Checking wp-config / sensitive-file exposure on "+site.URL+"...")
		bl := soft404Baseline(ctx, site.URL)

		// ── wp-config source / backups ──
		sem := make(chan struct{}, 12)
		var wg sync.WaitGroup
		for _, p := range paths {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(p string) {
				defer wg.Done()
				defer func() { <-sem }()
				u := site.URL + p
				r := wpGet(ctx, u, 256*1024)
				if r.status != 200 || bl.matches(r.status, []byte(r.body), r.ctype) {
					return
				}
				if kind := wpConfigLeakKind(r.body); kind != "" {
					s.store(ctx, targetID, "wp_config", "wordpress_config_exposure", "critical", u,
						"Exposed WordPress configuration ("+kind+") at "+p+" — leaks the database credentials and/or the AUTH/SECRET salts, enabling full database access and session/cookie forgery. Rotate the DB password and all salts immediately and remove the file.")
					s.notify(targetID, "wordpress_config_exposure", u)
					found.Add(1)
				}
			}(p)
		}
		wg.Wait()

		// ── wp-content/debug.log ──
		if dl := wpGet(ctx, site.URL+"/wp-content/debug.log", 128*1024); dl.status == 200 &&
			!bl.matches(dl.status, []byte(dl.body), dl.ctype) && wpDebugLogRe.MatchString(dl.body) {
			s.store(ctx, targetID, "wp_config", "wordpress_debug_log", "medium", site.URL+"/wp-content/debug.log",
				"WordPress debug.log is world-readable — leaks server paths, plugin internals and sometimes credentials/tokens from error traces. Set WP_DEBUG_LOG off (or move it out of the webroot) and delete the file.")
			s.notify(targetID, "wordpress_debug_log", site.URL+"/wp-content/debug.log")
			found.Add(1)
		}

		// ── directory listing on sensitive WordPress dirs ──
		for _, d := range []string{"/wp-content/uploads/", "/wp-content/", "/wp-includes/"} {
			if ctx.Err() != nil {
				break
			}
			if li := wpGet(ctx, site.URL+d, 96*1024); li.status == 200 && wpAutoindexRe.MatchString(li.body) {
				sev := "low"
				if d == "/wp-content/uploads/" {
					sev = "medium" // uploads commonly holds member data / stray backups
				}
				s.store(ctx, targetID, "wp_config", "wordpress_directory_listing", sev, site.URL+d,
					"Directory listing is enabled on "+d+" — the file/folder index is browsable, mapping uploads, plugins and any stray backups left there. Disable autoindex (Options -Indexes).")
				found.Add(1)
			}
		}
	}
	logFn("warn", "wp_config", "WordPress config/exposure check done. "+itoa(int(found.Load()))+" exposure(s).")
	return ctx.Err()
}

// wpConfigLeakKind reports what a served wp-config-like body actually leaks, or ""
// if the body is not raw configuration source. It requires the real credential or
// salt definitions so a 200 HTML/empty page can never be a finding.
func wpConfigLeakKind(body string) string {
	// Vim swap of wp-config carries the full source — magic "b0VIM".
	if strings.HasPrefix(body, "b0VIM") {
		return "Vim swap of wp-config.php"
	}
	hasDBPass := strings.Contains(body, "DB_PASSWORD")
	hasDefine := strings.Contains(body, "define(") || strings.Contains(body, "define (")
	if hasDBPass && hasDefine {
		return "database credentials"
	}
	if strings.Contains(body, "DB_NAME") && strings.Contains(body, "DB_USER") && hasDBPass {
		return "database credentials"
	}
	if strings.Contains(body, "AUTH_KEY") && strings.Contains(body, "SECURE_AUTH_KEY") &&
		strings.Contains(body, "LOGGED_IN_KEY") {
		return "authentication salts/keys"
	}
	return ""
}
