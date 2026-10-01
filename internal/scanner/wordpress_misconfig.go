package scanner

import (
	"context"
	"regexp"
	"strings"
)

// wordpress_misconfig.go — high-impact misconfiguration audit (module
// wp_misconfig). Each check is content-confirmed and only the genuinely dangerous
// states are reported: a reinstallable site (install.php / setup-config.php serving
// their setup wizard) is a full takeover; WP_DEBUG display left on in production
// leaks server paths and internals; open registration widens the attack surface.

var (
	// WP_DEBUG display: an inline PHP error that references a WordPress path.
	wpDebugDisplayRe = regexp.MustCompile(`(?is)<b>\s*(Notice|Warning|Deprecated|Fatal error|Parse error)\s*</b>.{0,200}?(/wp-includes/|/wp-content/|/wp-admin/)`)
)

// RunMisconfig implements wp_misconfig.
func (s *WordPressScanner) RunMisconfig(ctx context.Context, targetID string, logFn LogFunc) error {
	sites := s.ensureDetected(ctx, targetID, logFn)
	if len(sites) == 0 {
		logFn("info", "wp_misconfig", "No confirmed WordPress host for this target; nothing to check.")
		return ctx.Err()
	}
	found := 0
	for _, site := range sites {
		if ctx.Err() != nil {
			break
		}
		logFn("info", "wp_misconfig", "Auditing WordPress misconfiguration on "+site.URL+"...")
		bl := soft404Baseline(ctx, site.URL)

		// ── Reinstallable site: /wp-admin/install.php ──
		if r := wpGet(ctx, site.URL+"/wp-admin/install.php", 96*1024); r.status == 200 &&
			!bl.matches(r.status, []byte(r.body), r.ctype) && wpInstallSetupForm(r.body) {
			s.store(ctx, targetID, "wp_misconfig", "wordpress_install_exposed", "critical", site.URL+"/wp-admin/install.php",
				"WordPress installer is live and the site is NOT yet installed — anyone can complete setup with their own admin account and database, taking over the site. Finish installation or block /wp-admin/install.php immediately.")
			s.notify(targetID, "wordpress_install_exposed", site.URL+"/wp-admin/install.php")
			found++
		}

		// ── DB reconfiguration: /wp-admin/setup-config.php ──
		if r := wpGet(ctx, site.URL+"/wp-admin/setup-config.php", 96*1024); r.status == 200 &&
			!bl.matches(r.status, []byte(r.body), r.ctype) && wpSetupConfigForm(r.body) {
			s.store(ctx, targetID, "wp_misconfig", "wordpress_setup_config_exposed", "critical", site.URL+"/wp-admin/setup-config.php",
				"WordPress database-setup wizard (setup-config.php) is reachable and accepting input — an attacker can point the install at their own database and seize the site. Block it immediately.")
			s.notify(targetID, "wordpress_setup_config_exposed", site.URL+"/wp-admin/setup-config.php")
			found++
		}

		// ── Open user registration ──
		if r := wpGet(ctx, site.URL+"/wp-login.php?action=register", 96*1024); r.status == 200 &&
			wpRegistrationOpen(r.body) {
			s.store(ctx, targetID, "wp_misconfig", "wordpress_open_registration", "low", site.URL+"/wp-login.php?action=register",
				"Open user registration is enabled — anyone can create an account. Confirm this is intended; combined with a privilege-escalation plugin bug it is a common foothold. Review the default new-user role.")
			found++
		}

		// ── WP_DEBUG display left on in production ──
		if r := wpGet(ctx, site.URL+"/", 256*1024); r.status == 200 && wpDebugDisplayRe.MatchString(r.body) {
			s.store(ctx, targetID, "wp_misconfig", "wordpress_debug_display", "medium", site.URL+"/",
				"WP_DEBUG display is enabled in production — PHP notices/warnings are rendered inline, leaking absolute server paths, plugin/theme internals and query details. Set WP_DEBUG (or WP_DEBUG_DISPLAY) to false.")
			found++
		}
	}
	logFn("warn", "wp_misconfig", "WordPress misconfiguration audit done. "+itoa(found)+" finding(s).")
	return ctx.Err()
}

// wpInstallSetupForm reports whether a body is the install WIZARD (site not yet
// installed), as opposed to the "already installed" notice a live site returns.
func wpInstallSetupForm(body string) bool {
	low := strings.ToLower(body)
	if strings.Contains(low, "already installed") {
		return false
	}
	// The step-1 install form collects the site title + admin credentials.
	hasForm := strings.Contains(low, "weblog_title") ||
		(strings.Contains(low, "admin_email") && strings.Contains(low, "admin_password"))
	welcome := strings.Contains(low, "five-minute") || strings.Contains(low, "information needed") ||
		strings.Contains(low, "welcome")
	return hasForm && welcome
}

// wpSetupConfigForm reports whether a body is the DB-configuration wizard.
func wpSetupConfigForm(body string) bool {
	low := strings.ToLower(body)
	if strings.Contains(low, "already installed") {
		return false
	}
	fields := strings.Contains(low, "dbname") && strings.Contains(low, "uname") && strings.Contains(low, "dbhost")
	context := strings.Contains(low, "database") && (strings.Contains(low, "before getting started") ||
		strings.Contains(low, "connection information") || strings.Contains(low, "setup-config"))
	return fields && context
}

// wpRegistrationOpen reports whether the registration form is actually available.
func wpRegistrationOpen(body string) bool {
	low := strings.ToLower(body)
	if strings.Contains(low, "registration") && (strings.Contains(low, "not allowed") ||
		strings.Contains(low, "disabled") || strings.Contains(low, "currently not")) {
		return false
	}
	return strings.Contains(low, "registerform") &&
		strings.Contains(low, "user_login") && strings.Contains(low, "user_email")
}
