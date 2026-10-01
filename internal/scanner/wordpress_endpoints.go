package scanner

import (
	"context"
	"strings"
)

// wordpress_endpoints.go — login/admin surface, XML-RPC and REST (module
// wp_endpoints). The high-signal findings here are the XML-RPC capabilities that
// turn an anonymous endpoint into an attack primitive: system.multicall amplifies
// a password-guessing campaign (thousands of guesses per request) and pingback.ping
// is an SSRF/DDoS reflector. Both are confirmed from the server's own
// system.listMethods response — definitive, zero-FP.

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

		// ── XML-RPC capabilities ──
		s.auditXMLRPC(ctx, targetID, site.URL)

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

// auditXMLRPC confirms xmlrpc.php is live and reports its dangerous capabilities
// from the server's own system.listMethods response.
func (s *WordPressScanner) auditXMLRPC(ctx context.Context, targetID, base string) {
	u := base + "/xmlrpc.php"
	r := wpPost(ctx, u, "text/xml", xmlrpcListMethods, 128*1024)
	if r.status != 200 || !strings.Contains(r.body, "<methodResponse") {
		// A GET to xmlrpc.php returning the "POST requests only" notice still confirms
		// it exists but is not actionable without the method list.
		return
	}
	body := r.body
	s.store(ctx, targetID, "wp_endpoints", "wordpress_xmlrpc_enabled", "low", u,
		"XML-RPC is enabled (POC: POST system.listMethods to /xmlrpc.php). If unused, disable it — it concentrates several attack primitives behind one anonymous endpoint.")

	if strings.Contains(body, "pingback.ping") {
		s.storeWithPayload(ctx, targetID, "wp_endpoints", "wordpress_xmlrpc_pingback", "medium", u, "POST",
			"POST "+u+"  (XML body) <methodCall><methodName>pingback.ping</methodName>...</methodCall>",
			"XML-RPC pingback.ping is available — a server-side request forgery / DDoS reflector: the server will fetch an attacker-chosen URL (internal-port scanning, SSRF) and can be used to reflect traffic at a third party. Disable pingbacks / XML-RPC.")
		s.notify(targetID, "wordpress_xmlrpc_pingback", u)
	}
	if strings.Contains(body, "system.multicall") {
		s.storeWithPayload(ctx, targetID, "wp_endpoints", "wordpress_xmlrpc_multicall", "medium", u, "POST",
			"POST "+u+"  (XML body) <methodCall><methodName>system.multicall</methodName>... many wp.getUsersBlogs calls ...</methodCall>",
			"XML-RPC system.multicall is available — it amplifies credential brute-forcing (hundreds/thousands of wp.getUsersBlogs login attempts batched into ONE request, bypassing per-request login throttling). Disable XML-RPC or block system.multicall.")
		s.notify(targetID, "wordpress_xmlrpc_multicall", u)
	}
}

// xmlrpcHasMulticall reports whether a system.listMethods response advertises the
// amplification method (shared with the credential-audit module).
func xmlrpcHasMulticall(listMethodsBody string) bool {
	return strings.Contains(listMethodsBody, "system.multicall")
}
