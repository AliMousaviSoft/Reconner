# WordPress Scanner

Reconner ships a dedicated, modular WordPress offensive pipeline — the **WP
Scanner** (left nav → *WP Scanner*, route `/wp-scanner`). WordPress is heavy
enough (its own fingerprint gate, enumerators, backup/config exposure, CVE
coverage) to warrant its own project list and module picker, separate from the
generic web scanner.

The whole family is held to the project motto: **0 false positives, 0 false
negatives, fast and reliable**. Every finding is confirmed by a signal a human
could reproduce with a single request, and every finding carries a replayable
PoC (the exact URL, or the exact request body for XML-RPC/credential findings).

## The detection gate is mandatory

Nothing in the WordPress pipeline ever acts on a host until the **detection
gate** (`wp_detect`) has CONFIRMED it is WordPress and recorded the verdict in
the `wp_sites` table. A host is confirmed only by an essentially
WordPress-unique signal:

- the **`wp/v2` REST namespace** at `/wp-json/`, or
- the genuine **`wp-login.php` credential form** (the `log` + `pwd` fields plus a
  WordPress marker),

corroborated by weaker signals (meta generator, enqueued `/wp-content/` &
`/wp-includes/` asset refs, the `api.w.org` REST link header, the
`/?author=1 → /author/<slug>/` redirect, `readme.html`, the feed generator). A
soft-404 baseline guards every HTML signal so a catch-all "200 for everything"
host can never be mistaken for WordPress.

A domain the operator enters that turns out NOT to be WordPress simply yields an
empty confirmed-site list, so every other WP module no-ops on it. **That is what
keeps the whole family at zero false positives end to end.**

Create a project with **one or many domains** on the WP Scanner page; the gate
crawls each and the page shows exactly which entered the WordPress pipeline
(their confirmed version + the evidence signals).

## Modules (individually selectable, like the web scanner)

| Module | What it confirms | Severity |
| --- | --- | --- |
| `wp_detect` | The detection gate (always on). Records version + signals in `wp_sites`. | — |
| `wp_enum` | Core version (authoritative sources) + plugins (asset refs + `readme.txt` `Stable tag:`) + themes (`style.css` header). | info |
| `wp_users` | Usernames WordPress itself returns (REST users route, author-archive redirect, oembed). | low–medium |
| `wp_config` | wp-config backups/swaps/source and `debug.log` — reported only when the body carries the real config source / PHP error log; directory listings on sensitive dirs. | medium–critical |
| `wp_backups` | Public/plugin backup archives (UpdraftPlus, All-in-One WP Migration, Duplicator, BackupBuddy, WPvivid, BackWPup, Snapshot, …) and installers — magic-byte confirmed. | high–critical |
| `wp_endpoints` | Login panel, REST root, admin-ajax, and XML-RPC capabilities (`system.multicall` amplification, `pingback.ping` SSRF/DDoS) read from the server's own `system.listMethods`. | info–medium |
| `wp_misconfig` | Reinstallable site (`install.php` / `setup-config.php` wizard), open registration, `WP_DEBUG` display — each content-confirmed. | low–critical |
| `wp_vulns` | WordPress-tagged nuclei corpus (embedded FP-safe pack + official templates) against confirmed hosts only. | medium+ |
| `wp_credaudit` | **Opt-in** weak-credential audit (see below). | critical |

Each module self-gates on the detection result (calls `ensureDetected`, which is
cached), so they are safe to run in any order and independently.

## Zero-false-positive confirmation, per class

- **Enumeration** (`wp_enum`, `wp_users`): the item is one the site returned —
  an asset the page references, a `readme.txt`/`style.css` it serves, a username
  the REST route / author redirect / oembed discloses. Never a guess.
- **Config / backup exposure** (`wp_config`, `wp_backups`): a 200 is never a
  finding. wp-config is reported only when the body carries `DB_PASSWORD` +
  `define(` (or the AUTH/SECRET salts, or a `b0VIM` swap); a backup archive only
  after its bytes are magic-confirmed (ZIP/GZIP/TAR/SQL/7z/…​ or the `.wpress`
  header); a directory listing only on a genuine autoindex.
- **Endpoints / misconfig**: XML-RPC capabilities are read from the server's own
  method list; a reinstallable site is confirmed by the setup wizard markers (and
  excluded when the page says "already installed").
- **CVE coverage** (`wp_vulns`): the embedded pack is FP-safe **by construction**
  — a build-breaking test (`nuclei_pack_test.go`) requires every template to be
  medium+ with a status gate plus a strong/multi-word-AND signature; the official
  corpus runs under the same medium+ floor and runtime noise/reflection guards.

## Opt-in weak-credential audit (`wp_credaudit`)

Credential testing is dual-use, so it is boxed in:

- It performs **no active password testing** unless the operator sets the
  explicit authorization switch `enable_wp_credential_audit: true`
  (env `RECON_ENABLE_WP_CREDENTIAL_AUDIT=true`). Default **off**. With it off,
  selecting the module runs a non-intrusive surface check only — so even a
  "select every module" scan can never spray passwords unattended.
- When authorized it stays conservative: **enumerated usernames only** (never a
  username wordlist), a tiny curated weak-password list (`wp_passwords` corpus),
  strictly serial with a delay and a hard attempt cap, stopping on the first hit
  per user.
- A hit is confirmed **only** by a definitive auth-success signal — XML-RPC
  `wp.getUsersBlogs` returning the blog list (no `<fault>`) — which also avoids
  tripping login-lockout plugins the way `wp-login.php` form posts do.
- The working credential lands in the finding **payload** (the PoC); logs and
  events are redacted (the password is masked).

Use it only against targets you are explicitly authorized to test.

## Custom wordlists

All WordPress wordlists are embedded defaults that an operator can override or
extend by dropping a `reconner-custom-<id>.txt` file in the wordlists directory:

| Corpus id | Used by |
| --- | --- |
| `wp_plugins` | plugin slugs probed by `wp_enum` |
| `wp_themes` | theme slugs probed by `wp_enum` |
| `wp_config_paths` | wp-config variants probed by `wp_config` |
| `wp_backup_paths` | installer/archive paths probed by `wp_backups` |
| `wp_passwords` | weak passwords for the opt-in `wp_credaudit` |

## API

- `GET /targets/{id}/wp-sites` — the detection-gate verdicts (which host roots
  were confirmed WordPress, with version + confidence + evidence signals).
- Findings surface through the normal findings pipeline (type prefix
  `wordpress_*`), each with a reproduction PoC.
