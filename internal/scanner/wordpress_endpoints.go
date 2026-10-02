package scanner

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

// wordpress_endpoints.go — login/admin surface, XML-RPC and REST (module
// wp_endpoints). The high-signal XML-RPC findings here are the two capabilities
// that turn an anonymous endpoint into a real attack primitive — but neither is
// ever reported from the system.listMethods advertisement alone:
//
//   - wordpress_xmlrpc_pingback (SSRF/DDoS reflector) is reported ONLY when the
//     target server actually performs the out-of-band fetch we induce via
//     pingback.ping — i.e. an attributed OAST callback is caught, recording the
//     server's egress Source IP and promoting a confirmed finding. No callback,
//     no finding.
//   - wordpress_xmlrpc_multicall (brute-force amplifier) is reported ONLY when a
//     single batched system.multicall is observed executing each sub-call
//     (per-element faults), proving the amplification actually works on THIS host
//     rather than being blocked by 4.4+ hardening / a security plugin.
//
// listMethods only decides whether a proof attempt is worth making. This keeps
// both findings at zero false positives: they describe a demonstrated primitive,
// not an advertised method name.

const xmlrpcListMethods = `<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>`

// RunEndpoints implements wp_endpoints.
func (s *WordPressScanner) RunEndpoints(ctx context.Context, targetID string, logFn LogFunc) error {
	sites := s.ensureDetected(ctx, targetID, logFn)
	if len(sites) == 0 {
		logFn("info", "wp_endpoints", "No confirmed WordPress host for this target; nothing to check.")
		return ctx.Err()
	}
	for _, site := range sites {
		if ctx.Err() != nil {
			break
		}
		logFn("info", "wp_endpoints", "Mapping login / XML-RPC / REST surface on "+site.URL+"...")

		// ── Login panel ──
		if lp := wpGet(ctx, site.URL+"/wp-login.php", 96*1024); lp.status == 200 && wpLoginForm(lp.body) {
			s.store(ctx, targetID, "wp_endpoints", "wordpress_login_panel", "info", site.URL+"/wp-login.php",
				"WordPress admin login panel is reachable. Consider IP-allowlisting /wp-login.php and /wp-admin, and renaming the login path, to shrink the credential-attack surface.")
		}

		// ── XML-RPC capabilities (proof-gated) ──
		s.auditXMLRPC(ctx, targetID, site.URL, logFn)

		// ── REST API root ──
		if rest := wpGet(ctx, site.URL+"/wp-json/", 96*1024); rest.status == 200 &&
			strings.Contains(strings.ToLower(rest.ctype), "json") && wpRestNamespaceWP(rest.body) {
			s.store(ctx, targetID, "wp_endpoints", "wordpress_rest_api", "info", site.URL+"/wp-json/",
				"WordPress REST API is public. Review exposed routes (users, media, settings) and restrict any that leak data.")
		}

		// ── admin-ajax (unauthenticated AJAX surface) ──
		if aj := wpGet(ctx, site.URL+"/wp-admin/admin-ajax.php", 8*1024); aj.status == 200 || aj.status == 400 {
			s.store(ctx, targetID, "wp_endpoints", "wordpress_admin_ajax", "info", site.URL+"/wp-admin/admin-ajax.php",
				"wp-admin/admin-ajax.php is reachable — the unauthenticated AJAX entry point many plugin vulnerabilities are reached through. Enumerate plugin 'action' handlers reachable here.")
		}
	}
	logFn("warn", "wp_endpoints", "WordPress endpoint mapping done.")
	return ctx.Err()
}

// auditXMLRPC confirms xmlrpc.php is live (honest low-severity availability) and
// then ATTEMPTS to prove its two dangerous capabilities. The pingback and
// multicall findings are raised only by their proof routines — never from the
// listMethods advertisement — so a hardened host that merely lists the methods
// produces no high-signal finding.
func (s *WordPressScanner) auditXMLRPC(ctx context.Context, targetID, base string, logFn LogFunc) {
	u := base + "/xmlrpc.php"
	r := wpPost(ctx, u, "text/xml", xmlrpcListMethods, 128*1024)
	if r.status != 200 || !strings.Contains(r.body, "<methodResponse") {
		// A GET / non-XML response to xmlrpc.php means it is unavailable or not
		// speaking the protocol — nothing actionable.
		return
	}
	body := r.body
	s.store(ctx, targetID, "wp_endpoints", "wordpress_xmlrpc_enabled", "low", u,
		"XML-RPC is enabled (POC: POST system.listMethods to /xmlrpc.php). If unused, disable it — it concentrates several attack primitives behind one anonymous endpoint.")

	// The advertisement only gates whether a proof attempt is worthwhile.
	if strings.Contains(body, "pingback.ping") {
		s.provePingback(ctx, targetID, u, base, logFn)
	}
	if strings.Contains(body, "system.multicall") {
		s.proveMulticall(ctx, targetID, u, base, logFn)
	}
}

// provePingback obtains a REAL out-of-band proof of the XML-RPC pingback SSRF
// reflector. It plants an OOB probe and asks the target, via pingback.ping, to
// fetch our callback URL as the pingback "source". If the TARGET SERVER actually
// calls back, the public OAST handler (RecordOOBHit) records the server's egress
// Source IP and promotes a confirmed finding (wordpress_xmlrpc_pingback) — this
// routine only fires the request and waits for that proof. If no OOB callback
// endpoint is configured, or no callback arrives within the budget, NOTHING is
// reported: advertising pingback.ping is not, by itself, a vulnerability.
func (s *WordPressScanner) provePingback(ctx context.Context, targetID, xmlrpcURL, base string, logFn LogFunc) {
	oob, ok := newOOBCapability(s.cfg)
	if !ok {
		logFn("info", "wp_endpoints", "xmlrpc.php advertises pingback.ping on "+base+", but no OOB callback endpoint is configured — the SSRF cannot be proven, so it is not reported.")
		return
	}
	token := registerOOBProbe(s.db, targetID, xmlrpcURL, "pingback", "wordpress_pingback", "xmlrpc:pingback.ping")
	cb := oob.callbackURL(token)

	// WordPress fetches the pingback SOURCE only after it accepts the TARGET as a
	// local, pingback-enabled post, so aim at a real post URL (discovered via REST)
	// and fall back to the site root. Any of these inducing a fetch of our callback
	// proves the SSRF; the same token backs all of them so a hit on any one counts.
	targets := dedupeStrings([]string{s.wpFirstPostURL(ctx, base), base})
	fired := 0
	for _, tgt := range targets {
		if ctx.Err() != nil || tgt == "" {
			continue
		}
		_ = wpPost(ctx, xmlrpcURL, "text/xml", xmlrpcPingback(cb, tgt), 64*1024)
		fired++
	}
	if fired == 0 {
		return
	}

	logFn("info", "wp_endpoints", "pingback.ping fired on "+base+" with an out-of-band source URL; waiting for the target's server-side fetch (SSRF proof)...")
	if ip := s.pollOOBHit(ctx, token, 25*time.Second); ip != "" {
		logFn("warn", "wp_endpoints", "XML-RPC pingback SSRF PROVEN on "+base+" — the server fetched our callback from egress IP "+ip+"; a confirmed finding was recorded.")
	} else {
		logFn("info", "wp_endpoints", "No pingback callback was caught on "+base+" within the window; pingback.ping is advertised but the SSRF was not proven — not reported.")
	}
}

// proveMulticall proves the system.multicall amplification primitive the way it is
// actually abused: it batches several wp.getUsersBlogs calls (with throwaway bogus
// credentials) into ONE request and confirms the server executed EACH sub-call —
// returning a per-call fault for every element instead of a single top-level
// block. That per-element execution is exactly what lets an attacker batch
// hundreds/thousands of login guesses into one request and bypass per-request
// login throttling. A host that blocks multicall auth-amplification (WordPress
// 4.4+ hardening, a security plugin) answers with a single/again-throttled
// response and is NOT reported. Three fixed bogus guesses in one request are a
// capability probe, far below any lockout threshold — not a credential attack.
func (s *WordPressScanner) proveMulticall(ctx context.Context, targetID, xmlrpcURL, base string, logFn LogFunc) {
	probe := xmlrpcMulticallProbe()
	r := wpPost(ctx, xmlrpcURL, "text/xml", probe, 128*1024)
	if r.status != 200 || !strings.Contains(r.body, "<methodResponse") {
		return
	}
	// Each batched wp.getUsersBlogs with bad creds yields its own <fault>; two or
	// more faults prove every sub-call in the batch was executed in one request.
	if strings.Count(r.body, "faultCode") < 2 {
		logFn("info", "wp_endpoints", "system.multicall is advertised on "+base+" but batched auth-amplification is blocked (single/throttled response) — not reported.")
		return
	}
	s.storeWithPayload(ctx, targetID, "wp_endpoints", "wordpress_xmlrpc_multicall", "medium", xmlrpcURL, "POST",
		"POST "+xmlrpcURL+"  (text/xml)\n"+probe,
		"XML-RPC system.multicall amplification PROVEN: one request batching multiple wp.getUsersBlogs calls was executed per-element (the server returned a separate fault for each sub-call). This lets an attacker batch hundreds/thousands of login guesses into ONE request and bypass per-request login throttling. Disable XML-RPC or block system.multicall.")
	s.notify(targetID, "wordpress_xmlrpc_multicall", xmlrpcURL)
	logFn("warn", "wp_endpoints", "XML-RPC system.multicall amplification PROVEN on "+base+" (per-element batch execution confirmed).")
}

// pollOOBHit waits up to `budget` for an attributed out-of-band callback on
// `token` and returns the server's egress Source IP parsed from the recorded
// evidence ("" when no callback arrived). The confirmed finding itself is raised
// by the OAST callback handler (RecordOOBHit); this only waits for, and reads,
// that proof.
func (s *WordPressScanner) pollOOBHit(ctx context.Context, token string, budget time.Duration) string {
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ""
		}
		var hits int
		var evidence string
		_ = s.db.QueryRowContext(ctx,
			`SELECT hit_count, COALESCE(evidence,'') FROM oob_probes WHERE token=?`, token).
			Scan(&hits, &evidence)
		if hits > 0 {
			return parseOOBSourceIP(evidence)
		}
		select {
		case <-ctx.Done():
			return ""
		case <-time.After(1 * time.Second):
		}
	}
	return ""
}

// parseOOBSourceIP extracts the egress Source IP from a RecordOOBHit evidence
// string ("... Source IP: <ip> | method: ..."). Returns "unknown" when the marker
// is absent (a hit was still caught — we just couldn't read the IP) so the caller
// still treats the callback as proof.
func parseOOBSourceIP(evidence string) string {
	const marker = "Source IP: "
	i := strings.Index(evidence, marker)
	if i < 0 {
		return "unknown"
	}
	rest := evidence[i+len(marker):]
	if j := strings.Index(rest, " |"); j >= 0 {
		rest = rest[:j]
	}
	if rest = strings.TrimSpace(rest); rest != "" {
		return rest
	}
	return "unknown"
}

// wpFirstPostURL returns the canonical link of the most recent published post via
// the REST API, used as a valid pingback TARGET so the server will proceed to
// fetch the pingback source (our OOB callback). Returns "" if REST is unavailable
// or exposes no posts; the caller falls back to the site root.
func (s *WordPressScanner) wpFirstPostURL(ctx context.Context, base string) string {
	r := wpGet(ctx, base+"/wp-json/wp/v2/posts?per_page=1&_fields=link", 32*1024)
	if r.status != 200 || !strings.Contains(strings.ToLower(r.ctype), "json") {
		return ""
	}
	var posts []struct {
		Link string `json:"link"`
	}
	if err := json.Unmarshal([]byte(r.body), &posts); err != nil || len(posts) == 0 {
		return ""
	}
	return strings.TrimSpace(posts[0].Link)
}

// xmlrpcPingback builds a pingback.ping call whose SOURCE is our OOB callback URL
// and whose TARGET is a post on the site under test.
func xmlrpcPingback(source, target string) string {
	return `<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params>` +
		`<param><value><string>` + xmlEscape(source) + `</string></value></param>` +
		`<param><value><string>` + xmlEscape(target) + `</string></value></param>` +
		`</params></methodCall>`
}

// xmlrpcMulticallProbe batches three wp.getUsersBlogs calls with clearly bogus,
// throwaway credentials into one system.multicall. It is a capability probe, not a
// credential attack: three fixed bad guesses in a single request stay far below any
// lockout threshold, yet are enough to prove per-element batch execution.
func xmlrpcMulticallProbe() string {
	call := func(u, p string) string {
		return `<value><struct>` +
			`<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>` +
			`<member><name>params</name><value><array><data>` +
			`<value><string>` + xmlEscape(u) + `</string></value>` +
			`<value><string>` + xmlEscape(p) + `</string></value>` +
			`</data></array></value></member>` +
			`</struct></value>`
	}
	return `<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data>` +
		call("rcn_probe_u1", "rcn_probe_p1") +
		call("rcn_probe_u2", "rcn_probe_p2") +
		call("rcn_probe_u3", "rcn_probe_p3") +
		`</data></array></value></param></params></methodCall>`
}

// xmlrpcHasMulticall reports whether a system.listMethods response advertises the
// amplification method (shared with the credential-audit module).
func xmlrpcHasMulticall(listMethodsBody string) bool {
	return strings.Contains(listMethodsBody, "system.multicall")
}
