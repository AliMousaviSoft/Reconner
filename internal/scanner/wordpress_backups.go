package scanner

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

// wordpress_backups.go — public / plugin-generated backup discovery (module
// wp_backups). WordPress backup plugins routinely write full-site and database
// archives to predictable, world-readable directories, and migration/installer
// plugins leave their restore scripts in the webroot — a database archive hands an
// attacker every credential and password hash on the site, and a live Duplicator
// installer is a direct site/DB takeover.
//
// Zero false positives: a backup archive is reported ONLY after its bytes are
// magic-confirmed (ZIP/GZIP/TAR/SQL/7z/… via checkMagicBytes, or the .wpress
// binary header); a backup DIRECTORY is reported ONLY on a genuine autoindex
// listing; an installer ONLY when the page carries the plugin's own wizard markers.

// wpBackupDirListings are directories WordPress backup plugins write archives to.
// If any is browsable (autoindex), that itself leaks the backup inventory, and any
// archive listed is then fetched and magic-confirmed.
var wpBackupDirListings = []struct{ path, plugin string }{
	{"/wp-content/updraft/", "UpdraftPlus"},
	{"/wp-content/ai1wm-backups/", "All-in-One WP Migration"},
	{"/wp-content/wpvividbackups/", "WPvivid"},
	{"/wp-content/backups-dup-lite/", "Duplicator"},
	{"/wp-content/backups-dup-pro/", "Duplicator Pro"},
	{"/wp-content/backup-db/", "WP-DB-Backup"},
	{"/wp-content/backups/", "generic"},
	{"/wp-content/uploads/backupbuddy_backups/", "BackupBuddy"},
	{"/wp-content/uploads/backup-guard/", "Backup Guard"},
	{"/wp-content/uploads/snapshots/", "Snapshot / Snapshot Pro"},
	{"/wp-content/uploads/wp-clone/", "WP Clone"},
	{"/wp-content/uploads/backupwordpress/", "BackUpWordPress"},
	{"/wp-content/uploads/aryo-backup/", "WP Time Capsule"},
	{"/wp-snapshots/", "Snapshot"},
}

// wpBackupProbePaths are fixed single-file probes — migration/installer leftovers
// whose mere presence is a critical finding (restore scripts allow DB overwrite /
// RCE), plus a few webroot archive names some plugins use verbatim.
var wpBackupProbePaths = []string{
	"/installer.php", "/installer-backup.php", "/dup-installer/main.installer.php",
	"/installer-20230101.php", "/wp-content/plugins/duplicator/installer.php",
	"/wordpress.zip", "/wp-content.zip", "/backup.zip", "/site-backup.zip",
	"/database.sql", "/db.sql", "/wp-content/uploads/db.sql",
}

var wpHrefRe = regexp.MustCompile(`(?i)href=["']([^"'?#]+)["']`)

// wpListedBackupExtRe matches a filename in a directory listing that looks like a
// backup archive or dump (the magic-byte check below is the actual confirmation).
var wpListedBackupExtRe = regexp.MustCompile(`(?i)\.(zip|rar|7z|gz|tgz|bz2|xz|zst|sql|tar|bak|wpress|dump)(\.(gz|zip|bz2|xz|zst))?$`)

// RunBackups implements wp_backups.
func (s *WordPressScanner) RunBackups(ctx context.Context, targetID string, logFn LogFunc) error {
	sites := s.ensureDetected(ctx, targetID, logFn)
	if len(sites) == 0 {
		logFn("info", "wp_backups", "No confirmed WordPress host for this target; nothing to check.")
		return ctx.Err()
	}
	probePaths := wpBackupProbePaths
	if s.cfg != nil {
		probePaths = LoadCorpus(s.cfg.WordlistsDir, "wp_backup_paths", wpBackupProbePaths)
	}

	var found atomic.Int64
	for _, site := range sites {
		if ctx.Err() != nil {
			break
		}
		logFn("info", "wp_backups", "Hunting public/plugin backups on "+site.URL+"...")
		bl := soft404Baseline(ctx, site.URL)

		// ── Plugin backup directories ──
		for _, d := range wpBackupDirListings {
			if ctx.Err() != nil {
				break
			}
			r := wpGet(ctx, site.URL+d.path, 128*1024)
			if r.status != 200 || bl.matches(r.status, []byte(r.body), r.ctype) {
				continue
			}
			if !wpAutoindexRe.MatchString(r.body) {
				continue
			}
			s.store(ctx, targetID, "wp_backups", "wordpress_backup_directory", "high", site.URL+d.path,
				d.plugin+" backup directory is browsable at "+d.path+" — the backup inventory is exposed. Disable autoindex and move backups out of the webroot.")
			s.notify(targetID, "wordpress_backup_directory", site.URL+d.path)
			found.Add(1)
			// Fetch and magic-confirm the first listed archive → the real prize.
			if n := s.confirmListedBackup(ctx, targetID, site.URL, d.path, d.plugin, r.body); n {
				found.Add(1)
			}
		}

		// ── Fixed installer / archive probes ──
		sem := make(chan struct{}, 10)
		var wg sync.WaitGroup
		for _, p := range probePaths {
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
				// Installer/restore script leftover.
				if strings.HasSuffix(p, ".php") {
					if label := wpInstallerKind(r.body); label != "" {
						s.store(ctx, targetID, "wp_backups", "wordpress_installer_exposed", "critical", u,
							label+" restore/installer script is live at "+p+" — it can rebuild the site over an attacker-supplied database (full site/DB takeover, frequently RCE). Delete it immediately.")
						s.notify(targetID, "wordpress_installer_exposed", u)
						found.Add(1)
					}
					return
				}
				// Archive/dump leftover.
				if label := confirmWPBackupFile(p, r.body); label != "" {
					s.store(ctx, targetID, "wp_backups", "wordpress_backup_exposure", "critical", u,
						"Downloadable WordPress backup ("+label+") at "+p+" — a site/database archive exposes every credential and password hash. Remove it and rotate secrets.")
					s.notify(targetID, "wordpress_backup_exposure", u)
					found.Add(1)
				}
			}(p)
		}
		wg.Wait()
	}
	logFn("warn", "wp_backups", "WordPress backup hunt done. "+itoa(int(found.Load()))+" exposure(s).")
	return ctx.Err()
}

// confirmListedBackup pulls the first backup-looking file out of an autoindex body,
// fetches it, and magic-confirms it before reporting a downloadable archive. Only
// the first confirmed archive is reported (one bounded extra request per directory).
func (s *WordPressScanner) confirmListedBackup(ctx context.Context, targetID, siteBase, dir, plugin, listing string) bool {
	for _, m := range wpHrefRe.FindAllStringSubmatch(listing, -1) {
		name := strings.TrimSpace(m[1])
		if name == "" || strings.HasPrefix(name, "?") || strings.EqualFold(name, "../") {
			continue // sort links / parent directory
		}
		if !wpListedBackupExtRe.MatchString(name) {
			continue
		}
		full := listedFileURL(siteBase, dir, name)
		if full == "" {
			continue
		}
		r := wpGet(ctx, full, 256*1024)
		if r.status != 200 {
			continue
		}
		if label := confirmWPBackupFile(full, r.body); label != "" {
			s.store(ctx, targetID, "wp_backups", "wordpress_backup_exposure", "critical", full,
				"Downloadable "+plugin+" backup ("+label+") at "+full+" — a site/database archive exposes every credential and password hash. Remove it, disable the directory listing, and rotate secrets.")
			s.notify(targetID, "wordpress_backup_exposure", full)
			return true
		}
	}
	return false
}

// listedFileURL resolves an autoindex href against the site base and directory.
// Absolute-path hrefs are kept on the same host; relative names hang off dir.
func listedFileURL(siteBase, dir, name string) string {
	switch {
	case strings.HasPrefix(name, "http://"), strings.HasPrefix(name, "https://"):
		if hostOf(name) != hostOf(siteBase) {
			return "" // never follow a listing link to another host
		}
		return name
	case strings.HasPrefix(name, "/"):
		return siteBase + name
	default:
		return strings.TrimRight(siteBase, "/") + strings.TrimRight(dir, "/") + "/" + strings.TrimPrefix(name, "./")
	}
}

// confirmWPBackupFile confirms a served file really is a backup archive/dump. It
// magic-confirms common archive/dump formats, and recognizes the All-in-One WP
// Migration .wpress container (a custom, uncompressed format with no leading magic)
// by extension + a non-HTML binary body.
func confirmWPBackupFile(pathOrURL, body string) string {
	if label := checkMagicBytes([]byte(body)); label != "" {
		return label
	}
	low := strings.ToLower(pathOrURL)
	if strings.HasSuffix(low, ".wpress") && len(body) > 16 && !looksLikeHTML([]byte(body)) {
		return "All-in-One WP Migration .wpress archive"
	}
	return ""
}

// wpInstallerKind recognizes a live migration/installer restore script by its own
// wizard markers (not just a passing mention of the plugin name).
func wpInstallerKind(body string) string {
	low := strings.ToLower(body)
	hasInstaller := strings.Contains(low, "installer")
	switch {
	case strings.Contains(low, "duplicator") && (strings.Contains(low, "dup-installer") ||
		strings.Contains(low, "step 1 of") || strings.Contains(low, "archive setup") ||
		strings.Contains(low, "database restore")):
		return "Duplicator"
	case strings.Contains(low, "all-in-one wp migration") && hasInstaller:
		return "All-in-One WP Migration"
	case hasInstaller && strings.Contains(low, "wp-config") && strings.Contains(low, "database") &&
		(strings.Contains(low, "restore") || strings.Contains(low, "deploy")):
		return "WordPress migration"
	}
	return ""
}
