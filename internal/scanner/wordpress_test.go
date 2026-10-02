package scanner

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"regexp"
	"strings"
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
	// XML-RPC: listMethods advertises the dangerous methods; wp.getUsersBlogs
	// accepts admin/admin (a weak credential) and faults otherwise.
	mux.HandleFunc("/xmlrpc.php", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body := string(b)
		w.Header().Set("Content-Type", "text/xml")
		switch {
		case strings.Contains(body, "system.listMethods"):
			_, _ = w.Write([]byte(`<?xml version="1.0"?><methodResponse><params><param><value><array><data>
<value><string>system.multicall</string></value>
<value><string>pingback.ping</string></value>
<value><string>wp.getUsersBlogs</string></value>
</data></array></value></param></params></methodResponse>`))
		case strings.Contains(body, "system.multicall"):
			// Amplifiable host: each batched sub-call is executed and returns its OWN
			// fault (three faults in one response) — the per-element execution the
			// multicall proof requires. Must precede the wp.getUsersBlogs case.
			fault := `<value><struct><member><name>faultCode</name><value><int>403</int></value></member>` +
				`<member><name>faultString</name><value><string>Incorrect username or password.</string></value></member></struct></value>`
			_, _ = w.Write([]byte(`<?xml version="1.0"?><methodResponse><params><param><value><array><data>` +
				fault + fault + fault +
				`</data></array></value></param></params></methodResponse>`))
		case strings.Contains(body, "pingback.ping"):
			// Simulate the SSRF: synchronously fetch the SOURCE URI the caller asked us
			// to "verify" (our OOB callback) before answering, so the proof is recorded
			// by the time the pingback POST returns.
			if m := regexp.MustCompile(`<string>(https?://[^<]+)</string>`).FindStringSubmatch(body); m != nil {
				if resp, err := http.Get(m[1]); err == nil {
					_ = resp.Body.Close()
				}
			}
			_, _ = w.Write([]byte(`<?xml version="1.0"?><methodResponse><params><param><value><string>pong</string></value></param></params></methodResponse>`))
		case strings.Contains(body, "wp.getUsersBlogs"):
			// Accept any username==password (a weak credential) — mirrors the audit's
			// first guess (pw = username) so the success path is confirmed quickly.
			sm := regexp.MustCompile(`<string>([^<]*)</string>`).FindAllStringSubmatch(body, -1)
			if len(sm) >= 2 && sm[0][1] != "" && sm[0][1] == sm[1][1] {
				_, _ = w.Write([]byte(`<?xml version="1.0"?><methodResponse><params><param><value><array><data>
<value><struct><member><name>isAdmin</name><value><boolean>1</boolean></value></member>
<member><name>blogName</name><value><string>Ex</string></value></member></struct></value>
</data></array></value></param></params></methodResponse>`))
				return
			}
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`<?xml version="1.0"?><methodResponse><fault><value><struct>
<member><name>faultCode</name><value><int>403</int></value></member>
<member><name>faultString</name><value><string>Incorrect username or password.</string></value></member>
</struct></value></fault></methodResponse>`))
		default:
			_, _ = w.Write([]byte(`<?xml version="1.0"?><methodResponse><params></params></methodResponse>`))
		}
	})
	// Installer left in the "not installed" state → reinstall takeover.
	mux.HandleFunc("/wp-admin/install.php", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><h1>Welcome</h1>
<form><input name="weblog_title"><input name="admin_email"><input name="admin_password"></form>
famous five-minute WordPress installation</body></html>`))
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

func TestWordPressEndpointsXMLRPC(t *testing.T) {
	srv := httptest.NewServer(fakeWordPress())
	defer srv.Close()
	s, db, tid := newWPTestScanner(t)
	addHTTPService(t, db, tid, srv.URL+"/")

	if err := s.RunEndpoints(context.Background(), tid, noLog); err != nil {
		t.Fatal(err)
	}
	// Honest availability, the login panel, and the PROVEN multicall amplification
	// (the fake host executes each batched sub-call) must all be reported. Pingback
	// is proof-gated on an OOB callback and is covered by its own test below.
	for _, typ := range []string{"wordpress_xmlrpc_enabled", "wordpress_xmlrpc_multicall", "wordpress_login_panel"} {
		var n int
		db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type=?`, tid, typ).Scan(&n)
		if n == 0 {
			t.Errorf("endpoint finding %q missing", typ)
		}
	}
	// With no OOB callback configured, pingback.ping is advertised but UNPROVEN —
	// it must NOT be reported (zero false positives).
	var pb int
	db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='wordpress_xmlrpc_pingback'`, tid).Scan(&pb)
	if pb != 0 {
		t.Error("pingback must not be reported without a caught OOB callback (advertisement alone is not proof)")
	}
}

// TestWordPressPingbackSSRFProof confirms pingback is reported ONLY on a real
// out-of-band callback, and that the server's egress Source IP is captured. The
// callback endpoint mimics the production OAST handler (RecordOOBHit): it records
// the hit on the probe and raises the confirmed finding.
func TestWordPressPingbackSSRFProof(t *testing.T) {
	srv := httptest.NewServer(fakeWordPress())
	defer srv.Close()
	s, db, tid := newWPTestScanner(t)
	addHTTPService(t, db, tid, srv.URL+"/")

	const egressIP = "203.0.113.42"
	callback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := path.Base(r.URL.Path)
		ev := "Out-of-band wordpress_xmlrpc_pingback confirmed: the target server called back via /oob/" + token +
			". Injected via " + srv.URL + "/xmlrpc.php (sink: xmlrpc:pingback.ping). Source IP: " + egressIP + " | method: GET | UA: WordPress/pingback"
		_, _ = db.Exec(`UPDATE oob_probes SET hit_count=hit_count+1, evidence=? WHERE token=?`, ev, token)
		_, _ = RecordDetectorObservation(context.Background(), db, DetectorObservation{
			TargetID: tid, Type: "wordpress_xmlrpc_pingback", Subtype: "wordpress_pingback", Severity: "critical",
			URL: srv.URL + "/xmlrpc.php", Method: "CALLBACK", Location: "xmlrpc:pingback.ping",
			Evidence: ev, Source: "oast-callback", Confidence: 100, Verdict: VerifyVerified,
		})
		_, _ = w.Write([]byte("ok"))
	}))
	defer callback.Close()
	s.cfg.BlindXSSCallbackURL = callback.URL

	if err := s.RunEndpoints(context.Background(), tid, noLog); err != nil {
		t.Fatal(err)
	}

	var pb int
	db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='wordpress_xmlrpc_pingback'`, tid).Scan(&pb)
	if pb == 0 {
		t.Fatal("a caught pingback OOB callback must raise the wordpress_xmlrpc_pingback finding")
	}
	// The egress Source IP must have been recorded on the probe evidence.
	var ev string
	db.QueryRow(`SELECT COALESCE(evidence,'') FROM oob_probes WHERE kind='wordpress_pingback' AND target_id=?`, tid).Scan(&ev)
	if parseOOBSourceIP(ev) != egressIP {
		t.Errorf("egress source IP not captured from pingback callback: evidence=%q parsed=%q", ev, parseOOBSourceIP(ev))
	}
}

// TestWordPressMulticallBlockedNotReported confirms a host that blocks multicall
// auth-amplification (single fault, not per-element) is NOT reported.
func TestWordPressMulticallBlockedNotReported(t *testing.T) {
	mux := http.NewServeMux()
	// Minimal WP surface the detection gate needs.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Link", `<https://ex.test/wp-json/>; rel="https://api.w.org/"`)
		_, _ = w.Write([]byte(`<!doctype html><html><head><meta name="generator" content="WordPress 6.4.2" /></head><body>hi</body></html>`))
	})
	mux.HandleFunc("/wp-json/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"Ex","namespaces":["oembed/1.0","wp/v2"]}`))
	})
	mux.HandleFunc("/wp-login.php", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Set-Cookie", "wordpress_test_cookie=WP+Cookie+check")
		_, _ = w.Write([]byte(`<form name="loginform" action="/wp-login.php"><input name="log" id="user_login"><input name="pwd" id="user_pass" type="password"><input type="submit" id="wp-submit"></form>`))
	})
	mux.HandleFunc("/xmlrpc.php", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/xml")
		switch {
		case strings.Contains(string(b), "system.listMethods"):
			_, _ = w.Write([]byte(`<?xml version="1.0"?><methodResponse><params><param><value><array><data><value><string>system.multicall</string></value></data></array></value></param></params></methodResponse>`))
		default:
			// Hardened: a single top-level fault, NOT per-element execution.
			_, _ = w.Write([]byte(`<?xml version="1.0"?><methodResponse><fault><value><struct><member><name>faultCode</name><value><int>405</int></value></member><member><name>faultString</name><value><string>XML-RPC services are disabled.</string></value></member></struct></value></fault></methodResponse>`))
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	s, db, tid := newWPTestScanner(t)
	addHTTPService(t, db, tid, srv.URL+"/")

	if err := s.RunEndpoints(context.Background(), tid, noLog); err != nil {
		t.Fatal(err)
	}
	var mc int
	db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='wordpress_xmlrpc_multicall'`, tid).Scan(&mc)
	if mc != 0 {
		t.Error("multicall must not be reported when the host blocks batched auth-amplification (single fault)")
	}
}

func TestParseOOBSourceIP(t *testing.T) {
	ev := "Out-of-band blind_ssrf confirmed: the target server called back via /oob/x. Injected via http://h/y (sink: s). Source IP: 198.51.100.7 | method: GET | UA: curl"
	if got := parseOOBSourceIP(ev); got != "198.51.100.7" {
		t.Errorf("parseOOBSourceIP = %q want 198.51.100.7", got)
	}
	if got := parseOOBSourceIP("no marker here"); got != "unknown" {
		t.Errorf("parseOOBSourceIP(no marker) = %q want unknown", got)
	}
}

func TestWordPressMisconfigInstall(t *testing.T) {
	srv := httptest.NewServer(fakeWordPress())
	defer srv.Close()
	s, db, tid := newWPTestScanner(t)
	addHTTPService(t, db, tid, srv.URL+"/")

	if err := s.RunMisconfig(context.Background(), tid, noLog); err != nil {
		t.Fatal(err)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='wordpress_install_exposed' AND severity='critical'`, tid).Scan(&n)
	if n == 0 {
		t.Error("reinstallable site (install.php wizard) was not flagged critical")
	}
}

func TestWordPressCredAuditGate(t *testing.T) {
	srv := httptest.NewServer(fakeWordPress())
	defer srv.Close()

	// (1) Unauthorized: must do NO active testing → no credential finding.
	s1, db1, tid1 := newWPTestScanner(t)
	addHTTPService(t, db1, tid1, srv.URL+"/")
	if err := s1.RunCredAudit(context.Background(), tid1, noLog); err != nil {
		t.Fatal(err)
	}
	var n int
	db1.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='wordpress_weak_credentials'`, tid1).Scan(&n)
	if n != 0 {
		t.Fatal("credential audit must not run active testing without authorization")
	}

	// (2) Authorized: admin/admin is accepted by the fake → one critical finding.
	db2, err := database.New(filepath.Join(t.TempDir(), "wp2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	if err := database.RunMigrations(db2); err != nil {
		t.Fatal(err)
	}
	tid2 := uuid.NewString()
	if _, err := db2.Exec(`INSERT INTO targets (id, domain) VALUES (?, 'ex.test')`, tid2); err != nil {
		t.Fatal(err)
	}
	addHTTPService(t, db2, tid2, srv.URL+"/")
	s2 := NewWordPressScanner(db2, &config.Config{EnableWPCredentialAudit: true}, logger.New("error"), nil)
	if err := s2.RunCredAudit(context.Background(), tid2, noLog); err != nil {
		t.Fatal(err)
	}
	db2.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='wordpress_weak_credentials' AND severity='critical'`, tid2).Scan(&n)
	if n == 0 {
		t.Error("authorized credential audit did not confirm the weak admin/admin credential")
	}
}

func TestWPCredContextAuthorization(t *testing.T) {
	srv := httptest.NewServer(fakeWordPress())
	defer srv.Close()
	s, db, tid := newWPTestScanner(t) // default config: EnableWPCredentialAudit=false
	addHTTPService(t, db, tid, srv.URL+"/")

	// Per-scan authorization via context (what the WP Scanner tick sends) must
	// enable the audit even though the server-wide config switch is off.
	ctx := WithWPCredAuthorized(context.Background(), true)
	if err := s.RunCredAudit(ctx, tid, noLog); err != nil {
		t.Fatal(err)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='wordpress_weak_credentials'`, tid).Scan(&n)
	if n == 0 {
		t.Error("per-scan context authorization did not enable the credential audit")
	}
}

func TestWPCredHelpers(t *testing.T) {
	if maskSecret("password") != "p*******" {
		t.Errorf("maskSecret = %q", maskSecret("password"))
	}
	if !strings.Contains(xmlrpcGetUsersBlogs("a&b", "c<d"), "a&amp;b") {
		t.Error("xmlEscape not applied in getUsersBlogs request")
	}
	if !xmlrpcHasMulticall("...system.multicall...") || xmlrpcHasMulticall("nope") {
		t.Error("xmlrpcHasMulticall wrong")
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
