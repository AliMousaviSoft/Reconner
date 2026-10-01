# Reconner v4.3.0

A capability release that adds a **dedicated, modular WordPress scanner** — a
whole pipeline for WordPress targets, held to the same zero-false-positive bar as
the rest of Reconner: every finding is confirmed by a signal a human could
reproduce with a single request, and every finding carries a replayable PoC.

## WP Scanner — its own section

WordPress is heavy enough to earn its own place: a new **WP Scanner** entry in the
left nav (route `/wp-scanner`), separate from the generic web scanner.

- **Create a project from one or many domains** (space/comma/newline separated).
- **Verification first, always.** A mandatory deep **detection gate** crawls each
  domain and confirms WordPress only by an essentially WordPress-unique signal
  (the `wp/v2` REST namespace or the genuine `wp-login.php` credential form),
  corroborated by the generator, asset refs, the `api.w.org` link header and the
  `?author=1` redirect — with a soft-404 guard so a catch-all host can't fool it.
  **Only confirmed hosts enter the pipeline**, which is what keeps the whole
  family at zero false positives. The page shows exactly which domains verified
  (with their version + evidence).
- **Modular & individually selectable**, exactly like the web scanner's module
  picker.

## WordPress modules (all zero-FP, all with PoCs)

- **`wp_detect`** — the detection gate (always on); records version + signals.
- **`wp_enum`** — core version + plugins (`/wp-content/plugins/*` asset refs +
  `readme.txt` `Stable tag:`) + themes (`style.css` header). Every item confirmed.
- **`wp_users`** — usernames WordPress itself returns (REST users route,
  author-archive redirect, oembed) — never inferred from a login error.
- **`wp_config`** — wp-config backups / editor-swaps / source disclosure and
  `debug.log`, reported only when the body carries the real config source
  (DB creds / salts) or a genuine PHP error log; directory listings on sensitive
  dirs.
- **`wp_backups`** — the exposure operators care about most: public/plugin backup
  archives (UpdraftPlus, All-in-One WP Migration, Duplicator, BackupBuddy,
  WPvivid, BackWPup, Snapshot, …) and leftover installers, **magic-byte
  confirmed** (incl. the `.wpress` container) before anything is reported critical.
- **`wp_endpoints`** — login panel, REST root, admin-ajax, and XML-RPC
  capabilities read from the server's own `system.listMethods`:
  `system.multicall` (brute-force amplification) and `pingback.ping` (SSRF/DDoS).
- **`wp_misconfig`** — reinstallable site (`install.php` / `setup-config.php`
  wizard → critical), open registration, `WP_DEBUG` display in production — each
  content-confirmed.
- **`wp_vulns`** — the WordPress-tagged nuclei corpus against confirmed hosts
  only: the embedded FP-safe pack **plus** the official projectdiscovery
  templates, under the medium+ floor and runtime noise/reflection guards.
- **`wp_credaudit`** — **opt-in** weak-credential audit. No active password
  testing unless `enable_wp_credential_audit=true` is set (default off), so even
  a select-all scan can't spray. When authorized: enumerated usernames only, a
  tiny curated weak-password list, rate-limited and capped, confirmed only by a
  definitive XML-RPC `wp.getUsersBlogs` success. The working credential lands in
  the finding payload; logs/events are redacted.

## FP-safe WordPress CVE pack

Six new curated WordPress nuclei templates, all enforced false-positive-safe by
the build-breaking verifier (status gate + multi-word-AND / regex / binary
signature), all medium+: XML-RPC multicall amplification, Duplicator installer
exposure, wp-config source disclosure, UpdraftPlus / All-in-One WP Migration
backup-directory listings, and WooCommerce log-directory listing. The official
`wordpress`-tagged corpus covers the long tail of plugin/core CVEs alongside.

## Custom WordPress wordlists

New embedded, overridable corpora: `wp_plugins`, `wp_themes`, `wp_config_paths`,
`wp_backup_paths`, `wp_passwords` — drop a `reconner-custom-<id>.txt` in the
wordlists directory to extend any of them.

See `docs/WORDPRESS_SCANNER.md` for the full design and the zero-FP confirmation
rules per class.

---
Full diff: v4.2.0...v4.3.0
