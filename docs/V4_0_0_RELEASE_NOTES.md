# Reconner v4.0.0

## Prioritized, asset-first scanning (now the default)
- New asset-priority scoring engine (`ComputeAssetPriority`) ranks every known host using signals already captured for free — tech fingerprint, WAF/CMS detection, admin-panel findings, parameter density, vhost-discovery, and subdomain-name heuristics (`admin`/`api`/`staging`/`auth`/`payment` score up, `cdn`/`static`/`mail` score down). The main/apex domain always sorts first.
- Wildcard-catch-all and byte-identical-content hosts are collapsed into one representative for full-pipeline testing — the single biggest time-saver on a 1000+-subdomain target.
- Every request-heavy module (SQLi, XSS, SSRF, LFI, SSTI, CSTI, command injection, XXE, NoSQLi, file upload, IDOR, race, CSRF, CORS, cache poisoning, smuggling, open redirect, authz, dir/backup discovery, exposure, Nuclei, OAST) now runs its complete group against the highest-priority asset before moving to the next, instead of one module sweeping the whole target before the next module starts. Low-score tail assets on large targets get a lighter module tier instead of the full pipeline.
- Live per-asset progress (current asset / assets done / assets total) on the target page and via the task API.
- Shipped opt-in first, then promoted to the default — the old module-by-module sweep remains available as `classic_order`.

## SQLi and XSS: root-caused and fixed, not just tuned
- Found the real reason SQLi scans were slow to the point of finding nothing on real, WAF/rate-limited targets: `quickProbe`'s ~75-180 requests per candidate routinely tripped the shared adaptive per-host throttle into its ceiling. Added throttle-severity gating (skip the expensive ladder once a host is already saturated) and hard per-candidate deadlines.
- Found and fixed a real XSS coverage-loss bug: once the per-run browser budget was spent, candidates got zero further testing instead of falling through to the deterministic browserless ladder.
- Fixed a latent "XSS silently stops working forever" bug — a single failed Chrome-detection attempt was cached permanently via `sync.Once`; replaced with a 60s retry cooldown.
- Added a WAF-bypass request-encoding layer for XSS (HTML numeric character references, JS Unicode escapes) — XSS previously had zero request-level evasion, unlike SQLi's tamper variants.

## Root-caused a shared false-negative affecting nearly every detector
- `looksLikeWAFBlock`/`looksLikeBlockPage` — the shared gate almost every differential detector (SQLi, XSS, SSRF, LFI, XXE, SSTI, CSTI, IDOR, NoSQLi, cache poisoning) calls before trusting a response — treated the bare phrase "access denied" and any bare HTTP 406 as an automatic WAF block. Both are extremely common on ordinary, non-WAF application responses (auth failures, content negotiation) and were silently discarding real signal. Fixed to require the same vendor-specific signature every other block match already does.

## Subdomain takeover: two concrete false-positive fixes
- Wildcard/catch-all DNS zones were never detected — every subdomain under a wildcard CNAME (real or made up) was reported as its own "dangling subdomain" finding. Now detected and assessed once per zone.
- Two fingerprints (Cargo, Unbounce) were keyed on the target's own generic default error text (a plain "404 Not Found"), which could flag any ordinary live 404. Generic signatures now require a second confirming signal (NXDOMAIN or subzy) before being trusted.

## Backup/secret-file discovery: branded wordlist + wider reach
- New brand-aware candidate generation (`generateBrandedBackupCandidates`) — the highest-yield real-world pattern (a backup named after the site itself, e.g. `acmecorp_backup.zip`) was previously not modeled at all.
- Fixed a real bug in domain-name extraction that silently turned URL-shaped domains into the literal word "https", corrupting every domain-derived backup candidate.
- Added CMS automated-backup-plugin storage paths (WordPress, Joomla, Drupal, Magento, cPanel) that a generic wordlist can never guess.

## Findings UI: collapse by root cause, not by URL
- A host-wide issue (e.g. Host Header Injection re-confirmed on every URL of a host) previously repeated an identical-looking row per URL. The vulns/candidates tab now groups by (type, host, parameter) into one collapsed row with a "×N" badge and an expandable list of affected URLs.

## Screenshot proof for admin panels and verified PoCs
- The `screenshots` table, serve endpoint, and config already existed but had no production code path that ever populated them. Wired up real chromedp-based capture for confirmed admin panels and confirmed XSS with live browser execution proof, with thumbnails now shown in both tabs.

## Nuclei: low/info templates removed outright, no opt-in
- The medium+-only default from v3.8.0 was still escapable via a config flag that let low/info templates run again, with a narrow path for a low/info-classified hit to still reach `vuln_findings`. That opt-in is now removed entirely — there is no configured or coded path left that ever runs an info/low nuclei template.

---
Full diff: v3.8.0...v4.0.0
