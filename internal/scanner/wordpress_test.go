package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/pkg/logger"
)

// fakeWordPress is an httptest handler that answers the exact endpoints the
// detection gate and enumerators rely on, so the whole WP pipeline can be
// exercised end to end without a real WordPress install.
func fakeWordPress() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Author-archive redirect: /?author=1 -> /author/admin/
		if r.URL.RawQuery == "author=1" {
			http.Redirect(w, r, "/author/admin/", http.StatusMovedPermanently)
			return
		}
		// Real WordPress 404s unknown paths — essential so the soft-404 baseline
		// stays inactive and the home page is read as genuine content.
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Link", `<https://ex.test/wp-json/>; rel="https://api.w.org/"`)
		_, _ = w.Write([]byte(`<!doctype html><html><head>
<meta name="generator" content="WordPress 6.4.2" />
<link rel="stylesheet" href="/wp-content/plugins/woocommerce/assets/css/woocommerce.css?ver=8.5.1" />
<script src="/wp-includes/js/wp-embed.min.js?ver=6.4.2"></script>
<link rel="stylesheet" href="/wp-content/themes/astra/style.css?ver=4.5.0" />
</head><body>hello</body></html>`))
	})
	mux.HandleFunc("/wp-json/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"Ex","namespaces":["oembed/1.0","wp/v2","wp-site-health/v1"]}`))
	})
	mux.HandleFunc("/wp-login.php", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Set-Cookie", "wordpress_test_cookie=WP+Cookie+check")
		_, _ = w.Write([]byte(`<form name="loginform" action="/wp-login.php">
<input name="log" id="user_login"><input name="pwd" id="user_pass" type="password">
<input type="submit" id="wp-submit"></form>`))
	})
	mux.HandleFunc("/wp-json/wp/v2/users", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":1,"name":"Site Admin","slug":"admin"},{"id":2,"name":"Editor","slug":"editor"}]`))
	})
	mux.HandleFunc("/wp-content/plugins/woocommerce/readme.txt", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("=== WooCommerce ===\nContributors: automattic\nStable tag: 8.5.1\n"))
	})
	mux.HandleFunc("/wp-content/themes/astra/style.css", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		_, _ = w.Write([]byte("/*\nTheme Name: Astra\nVersion: 4.5.0\n*/\n"))
	})
	// Exposed wp-config backup leaking the DB credentials.
	mux.HandleFunc("/wp-config.php.bak", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("<?php\ndefine('DB_NAME', 'wp');\ndefine('DB_USER', 'root');\ndefine('DB_PASSWORD', 's3cr3t');\n"))
	})
	// World-readable debug.log.
	mux.HandleFunc("/wp-content/debug.log", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("[18-Jan-2026 01:30:22 UTC] PHP Warning: include(): failed opening '/var/www/x.php'\n"))
	})
	// UpdraftPlus backup directory with autoindex listing + a downloadable gz dump.
	mux.HandleFunc("/wp-content/updraft/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><title>Index of /wp-content/updraft</title></head><body>
<h1>Index of /wp-content/updraft</h1><a href="../">Parent Directory</a>
<a href="backup_2026-db.gz">backup_2026-db.gz</a></body></html>`))
	})
	mux.HandleFunc("/wp-content/updraft/backup_2026-db.gz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02})
	})
	return mux
}

func newWPTestScanner(t *testing.T) (*WordPressScanner, *database.DB, string) {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "wp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	tid := uuid.NewString()
	if _, err := db.Exec(`INSERT INTO targets (id, domain) VALUES (?, 'ex.test')`, tid); err != nil {
		t.Fatal(err)
	}
	s := NewWordPressScanner(db, &config.Config{}, logger.New("error"), nil)
	return s, db, tid
}

func addHTTPService(t *testing.T, db *database.DB, tid, u string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,source) VALUES (?,?,?,200,'probe')`,
		uuid.NewString(), tid, u); err != nil {
		t.Fatal(err)
	}
}

func noLog(string, string, string) {}

func TestWordPressDetectionGateConfirms(t *testing.T) {
	srv := httptest.NewServer(fakeWordPress())
	defer srv.Close()
	s, db, tid := newWPTestScanner(t)
	addHTTPService(t, db, tid, srv.URL+"/")

	sites := s.ensureDetected(context.Background(), tid, noLog)
	if len(sites) != 1 {
		t.Fatalf("expected 1 confirmed WordPress site, got %d", len(sites))
	}
	if !sites[0].isWordPress() {
		t.Fatalf("site should be confirmed WordPress: %+v", sites[0])
	}
	if sites[0].Version != "6.4.2" {
		t.Errorf("expected core version 6.4.2, got %q", sites[0].Version)
	}
	// The REST namespace and the login form should BOTH have fired.
	var isWP, conf int
	if err := db.QueryRow(`SELECT is_wordpress, confidence FROM wp_sites WHERE target_id=?`, tid).Scan(&isWP, &conf); err != nil {
		t.Fatal(err)
	}
	if isWP != 1 || conf < ConfEvidence {
		t.Fatalf("wp_sites must record a confirmed verdict: is_wp=%d conf=%d", isWP, conf)
	}
}

func TestWordPressGateRejectsNonWordPress(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body>just a site, no cms</body></html>`))
	}))
	defer plain.Close()
	s, db, tid := newWPTestScanner(t)
	addHTTPService(t, db, tid, plain.URL+"/")

	sites := s.ensureDetected(context.Background(), tid, noLog)
	if len(sites) != 0 {
		t.Fatalf("a non-WordPress host must NOT enter the WP pipeline, got %d sites", len(sites))
	}
}

func TestWordPressEnumerationConfirmsPluginTheme(t *testing.T) {
	srv := httptest.NewServer(fakeWordPress())
	defer srv.Close()
	s, db, tid := newWPTestScanner(t)
	addHTTPService(t, db, tid, srv.URL+"/")

	if err := s.RunEnumeration(context.Background(), tid, noLog); err != nil {
		t.Fatal(err)
	}
	// WooCommerce must be confirmed (home-page asset ref + readme.txt Stable tag).
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='wordpress_plugin' AND url LIKE '%woocommerce%'`, tid).Scan(&n)
	if n == 0 {
		t.Error("woocommerce plugin was not enumerated")
	}
	// Astra theme must be confirmed via style.css.
	db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='wordpress_theme' AND url LIKE '%astra%'`, tid).Scan(&n)
	if n == 0 {
		t.Error("astra theme was not enumerated")
	}
	// Core version finding.
	db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='wordpress_version'`, tid).Scan(&n)
	if n == 0 {
		t.Error("core version was not reported")
	}
}

func TestWordPressUserEnumeration(t *testing.T) {
	srv := httptest.NewServer(fakeWordPress())
	defer srv.Close()
	s, db, tid := newWPTestScanner(t)
	addHTTPService(t, db, tid, srv.URL+"/")

	if err := s.RunUsers(context.Background(), tid, noLog); err != nil {
		t.Fatal(err)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='wordpress_user_enumeration'`, tid).Scan(&n)
	if n == 0 {
		t.Fatal("user enumeration produced no finding")
	}
	users := s.enumerateUsernames(context.Background(), baseRoot(srv.URL))
	if len(users) < 2 {
		t.Errorf("expected >=2 usernames (admin, editor), got %v", users)
	}
}

func TestWordPressConfigExposure(t *testing.T) {
	srv := httptest.NewServer(fakeWordPress())
	defer srv.Close()
	s, db, tid := newWPTestScanner(t)
	addHTTPService(t, db, tid, srv.URL+"/")

	if err := s.RunConfigExposure(context.Background(), tid, noLog); err != nil {
		t.Fatal(err)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='wordpress_config_exposure' AND severity='critical'`, tid).Scan(&n)
	if n == 0 {
		t.Error("exposed wp-config.php.bak with DB creds was not reported as critical")
	}
	db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='wordpress_debug_log'`, tid).Scan(&n)
	if n == 0 {
		t.Error("exposed debug.log was not reported")
	}
}

func TestWordPressConfigNoFalsePositive(t *testing.T) {
	// A site that 200s an HTML page for a wp-config backup path (SPA catch-all) must
	// NOT be reported — the body carries no real config source.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body>app shell, mentions DB_PASSWORD in docs</body></html>`))
	}))
	defer srv.Close()
	s, db, tid := newWPTestScanner(t)
	addHTTPService(t, db, tid, srv.URL+"/")
	// Force a confirmed site row so the module runs even though detection would fail.
	s.storeSite(context.Background(), tid, wpSite{URL: baseRoot(srv.URL), Host: hostOf(srv.URL), Confidence: ConfEvidence, Signals: []string{"test"}})

	if err := s.RunConfigExposure(context.Background(), tid, noLog); err != nil {
		t.Fatal(err)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='wordpress_config_exposure'`, tid).Scan(&n)
	if n != 0 {
		t.Errorf("HTML page mentioning DB_PASSWORD must not be a config leak (got %d)", n)
	}
}

func TestWordPressBackupFinder(t *testing.T) {
	srv := httptest.NewServer(fakeWordPress())
	defer srv.Close()
	s, db, tid := newWPTestScanner(t)
	addHTTPService(t, db, tid, srv.URL+"/")

	if err := s.RunBackups(context.Background(), tid, noLog); err != nil {
		t.Fatal(err)
	}
	var dir, arch int
	db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='wordpress_backup_directory'`, tid).Scan(&dir)
	db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='wordpress_backup_exposure' AND severity='critical'`, tid).Scan(&arch)
	if dir == 0 {
		t.Error("browsable UpdraftPlus backup directory was not reported")
	}
	if arch == 0 {
		t.Error("magic-confirmed downloadable gz backup was not reported as critical")
	}
}

func TestWPBackupConfirmHelpers(t *testing.T) {
	// gzip magic confirms.
	if confirmWPBackupFile("/x/backup.gz", "\x1f\x8bxxxx") == "" {
		t.Error("gzip backup not confirmed")
	}
	// HTML served at a backup path is never a backup.
	if confirmWPBackupFile("/x/backup.zip", "<!doctype html><html></html>") != "" {
		t.Error("HTML page falsely confirmed as backup")
	}
	// Duplicator installer markers.
	if wpInstallerKind("<title>Duplicator</title> dup-installer STEP 1 OF 4") == "" {
		t.Error("duplicator installer not recognized")
	}
	if wpInstallerKind("a page that merely mentions duplicator plugin") != "" {
		t.Error("mere mention of duplicator falsely flagged as installer")
	}
}

func TestWPDetectionHelpers(t *testing.T) {
	if !wpRestNamespaceWP(`{"namespaces":["wp/v2"]}`) {
		t.Error("wp/v2 namespace not recognized")
	}
	if wpRestNamespaceWP(`{"namespaces":["foo/v1"]}`) {
		t.Error("non-WP namespace falsely recognized")
	}
	if !wpLoginForm(`<form><input name="log"><input name="pwd"><input id="wp-submit"></form>`) {
		t.Error("genuine wp-login form not recognized")
	}
	if wpLoginForm(`<form><input name="email"><input name="password"></form>`) {
		t.Error("generic login form falsely recognized as wp-login")
	}
	if got := baseRoot("https://a.ex.test:8443/blog/x?y=1"); got != "https://a.ex.test:8443" {
		t.Errorf("baseRoot = %q", got)
	}
	if got := baseRoot("http://plain.test"); got != "http://plain.test" {
		t.Errorf("baseRoot default = %q", got)
	}
	if !validWPSlug("woocommerce") || validWPSlug("css") || validWPSlug("a") {
		t.Error("validWPSlug gate wrong")
	}
	if v := wpSlugVerForSlug(`x /wp-content/plugins/woo/foo.js?ver=1.2.3" y`, "woo"); v != "1.2.3" {
		t.Errorf("wpSlugVerForSlug = %q", v)
	}
}
