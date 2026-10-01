package scanner

import (
	"context"
	"strings"
	"time"
)

// wordpress_credaudit.go — OPT-IN WordPress weak-credential audit (module
// wp_credaudit).
//
// This is dual-use, so it is deliberately boxed in:
//   - It never runs active password testing unless the operator has set the
//     explicit authorization switch cfg.EnableWPCredentialAudit (default OFF). With
//     it off, the module does nothing active (the brute-force SURFACE is already
//     reported by wp_endpoints). So even a "select every module" scan can never
//     spray passwords unattended.
//   - When authorized, it stays conservative: ENUMERATED usernames only (never a
//     username wordlist), a tiny curated weak-password list, strictly serial with a
//     delay (no lockout storm), a hard attempt cap, and it stops on the first hit
//     per user.
//   - A hit is confirmed ONLY by a definitive auth-success signal — XML-RPC
//     wp.getUsersBlogs returning the blog list (no <fault>) — so there are no false
//     positives, and XML-RPC guessing does not trip login-lockout plugins the way
//     wp-login.php form posts do.

// wpWeakPasswords is the tiny, highest-signal default list. Operators extend it via
// the wp_passwords corpus. Username-equals-password is also tried per user.
var wpWeakPasswords = []string{
	"admin", "password", "Password1", "password123", "123456", "12345678",
	"admin123", "welcome", "letmein", "changeme", "P@ssw0rd", "qwerty",
	"root", "wordpress", "secret",
}

const (
	wpCredMaxUsers    = 5
	wpCredMaxAttempts = 50
	wpCredDelay       = 250 * time.Millisecond
)

// RunCredAudit implements wp_credaudit.
func (s *WordPressScanner) RunCredAudit(ctx context.Context, targetID string, logFn LogFunc) error {
	sites := s.ensureDetected(ctx, targetID, logFn)
	if len(sites) == 0 {
		logFn("info", "wp_credaudit", "No confirmed WordPress host for this target; nothing to check.")
		return ctx.Err()
	}
	authorized := s.cfg != nil && s.cfg.EnableWPCredentialAudit
	if !authorized {
		logFn("warn", "wp_credaudit", "Active credential testing is NOT authorized (set enable_wp_credential_audit=true to allow it). Skipping password attempts; the XML-RPC brute-force surface is reported by wp_endpoints.")
		return ctx.Err()
	}

	passwords := wpWeakPasswords
	if s.cfg != nil {
		passwords = LoadCorpus(s.cfg.WordlistsDir, "wp_passwords", wpWeakPasswords)
	}

	hits := 0
	for _, site := range sites {
		if ctx.Err() != nil {
			break
		}
		// XML-RPC must be available and expose wp.getUsersBlogs, or we have no safe,
		// lockout-free confirmation channel — skip rather than hammer wp-login.php.
		lm := wpPost(ctx, site.URL+"/xmlrpc.php", "text/xml", xmlrpcListMethods, 128*1024)
		if lm.status != 200 || !strings.Contains(lm.body, "wp.getUsersBlogs") {
			logFn("info", "wp_credaudit", "XML-RPC wp.getUsersBlogs unavailable on "+site.URL+"; skipping (no lockout-free confirmation channel).")
			continue
		}

		users := s.enumerateUsernames(ctx, site.URL)
		if len(users) == 0 {
			users = []string{"admin"} // the one near-universal default worth a few guesses
		}
		if len(users) > wpCredMaxUsers {
			users = users[:wpCredMaxUsers]
		}
		logFn("info", "wp_credaudit", "Authorized credential audit on "+site.URL+" over "+itoa(len(users))+" enumerated user(s) (rate-limited, XML-RPC-confirmed)...")

		attempts := 0
	userLoop:
		for _, user := range users {
			// Build this user's candidate list: the curated weak list + username itself.
			for _, pw := range append([]string{user}, passwords...) {
				if ctx.Err() != nil || attempts >= wpCredMaxAttempts {
					break userLoop
				}
				attempts++
				if s.xmlrpcLoginSucceeds(ctx, site.URL, user, pw) {
					poc := "POST " + site.URL + "/xmlrpc.php  (text/xml)\n" + xmlrpcGetUsersBlogs(user, pw)
					s.storeWithPayload(ctx, targetID, "wp_credaudit", "wordpress_weak_credentials", "critical",
						site.URL+"/xmlrpc.php", "POST", poc,
						"Valid WordPress credentials confirmed via XML-RPC for user '"+user+"' (password "+maskSecret(pw)+"). This grants dashboard access — typically full site compromise. Reset the password and enforce strong-password + 2FA policy. See the finding payload for the exact replay.")
					s.notify(targetID, "wordpress_weak_credentials", site.URL+"/xmlrpc.php")
					hits++
					continue userLoop // stop on first hit for this user
				}
				time.Sleep(wpCredDelay)
			}
		}
	}
	logFn("warn", "wp_credaudit", "WordPress credential audit done. "+itoa(hits)+" valid credential(s) found.")
	return ctx.Err()
}

// xmlrpcLoginSucceeds submits wp.getUsersBlogs and reports a confirmed login: a
// methodResponse carrying the blog list (isAdmin/blogName) and NO <fault>. A failed
// login returns a <fault> (403), so this cannot false-positive.
func (s *WordPressScanner) xmlrpcLoginSucceeds(ctx context.Context, base, user, pass string) bool {
	r := wpPost(ctx, base+"/xmlrpc.php", "text/xml", xmlrpcGetUsersBlogs(user, pass), 64*1024)
	if r.status != 200 || !strings.Contains(r.body, "<methodResponse") {
		return false
	}
	if strings.Contains(r.body, "<fault") {
		return false
	}
	return strings.Contains(r.body, "isAdmin") || strings.Contains(r.body, "blogName") ||
		strings.Contains(r.body, "blogid")
}

func xmlrpcGetUsersBlogs(user, pass string) string {
	return `<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params>` +
		`<param><value><string>` + xmlEscape(user) + `</string></value></param>` +
		`<param><value><string>` + xmlEscape(pass) + `</string></value></param>` +
		`</params></methodCall>`
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}

// maskSecret shows only the first character of a credential for the (redacted)
// evidence line; the real value lives in the finding payload for reproduction.
func maskSecret(s string) string {
	switch {
	case s == "":
		return "(empty)"
	case len(s) <= 2:
		return "*"
	default:
		return s[:1] + strings.Repeat("*", len(s)-1)
	}
}
