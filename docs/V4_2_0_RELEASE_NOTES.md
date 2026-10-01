# Reconner v4.2.0

A capability release focused on **finding more real bugs** — new attack-surface
discovery, new vulnerability classes, a self-hosted OOB (Collaborator-class)
channel, and a durable authenticated-session lifecycle — all held to the same
zero-false-positive bar: every new detector is confirmed by callback, differential
+ revert, or breakout proof, never by a bare heuristic.

## Browser-driven crawl: the real runtime API surface
- The headless crawler now passively captures every in-scope **XHR / fetch /
  navigation** the app fires via the CDP Network domain and turns each into an
  insertion point (query params, JSON-body leaves, form fields). A modern SPA's
  attack surface is the endpoints its client calls at runtime — invisible to a
  link/form scrape, now harvested like Burp's browser-driven crawl / Acunetix
  DeepScan. Crawl depth also scales with the speed profile.

## Self-hosted OOB: DNS interaction channel (Collaborator-class)
- The built-in OAST server gained a **DNS channel**: an authoritative listener for
  a delegated zone (`oob_dns_zone`) catches blind callbacks from targets that can
  resolve DNS but not open an outbound HTTP/LDAP connection — blind SSRF, blind
  SQLi DNS-exfil (UNC/`LOAD_FILE`, Oracle `UTL_INADDR`), DNS-only RCE, blind XXE.
  The token rides in `<token>.<zone>`; a hit is definitive proof.

## New vulnerability classes (all OOB- or differential-confirmed)
- **Server-side prototype pollution (non-reflective)** — confirmed via behavioural
  gadgets (`json spaces` indentation, `status` override) with double-value +
  revert control.
- **CSWSH (Cross-Site WebSocket Hijacking)** — a three-handshake triad proves the
  socket is cookie-authenticated AND accepts a cross-site Origin.
- **Blind insecure deserialization** — Node `node-serialize`, Python `pickle`,
  Java SnakeYAML payloads whose only effect is an OOB callback.
- **HTTP request smuggling** — added the canonical Transfer-Encoding obfuscation
  variants (space-before-colon, tab, vertical-tab, dual header, obs-fold) to the
  time-based CL.TE/TE.CL probes.

## Authentication Profiles & session lifecycle (issue #45)
Authenticated scanning is now a durable, verification-aware prerequisite rather
than a static header:
- **session-health preflight** validates every identity at scan start (never
  treats `200` as authenticated);
- **refresh / re-authentication** — `replay` a stored login to rebuild the session
  from `Set-Cookie`, `manual`, or `none`; the preflight self-heals (detect →
  refresh → resume);
- **CSRF token tracking** — fetch a live token (input/meta/json/cookie) before a
  state-changing request so it isn't rejected as stale;
- **fail-closed gate** — a configured-but-dead session blocks the dependent module
  explicitly instead of silently scanning the logged-out app;
- **sanitized audit trail** + dashboard controls (Validate / Refresh / Revoke /
  Delete) and a timeline; secrets encrypted at rest, redacted from logs/events,
  and excluded from exported bundles. See `docs/AUTHENTICATION_PROFILES.md`.

## Reliability: a failed httpx no longer collapses the scan
- When httpx is missing, errors (e.g. a flag the installed build rejects → exit
  status 2), or stores zero live services, the scan now falls back to the native
  Go prober instead of silently finding nothing downstream. Tool stderr is also
  surfaced in the error so the real reason is visible.

## Recall boosts (more finds, still zero false positives)
- **Backup finder** now searches archives **under common backup directories**
  (`/backup/acme.zip`, `/db/db_2025.sql.gz`, `/dumps/database.sql`) — the most
  common real layout, which the root-only generators missed — with the site's own
  name first; every hit is still magic-byte/SQL-signature confirmed. Extensions
  widened (`.tgz/.war/.tar.bz2/.dump`).
- **Reflected XSS now tests request headers** (Referer, X-Forwarded-Host,
  User-Agent, X-Forwarded-For, Origin, X-Original-URL, …) — a whole source class,
  run through the identical context-aware breakout confirmation, so no new
  false-positive path.
- **Nuclei curated pack 13 → 35 templates**, all medium+ and enforced
  false-positive-safe by a build-breaking verifier test (status gate + specific
  multi-signature matchers, no lone keyword). Highlights: Spring Cloud Gateway
  actuator, private-key/`.vscode/sftp.json`/`web.config` credential exposure,
  Elasticsearch/Kibana/Docker-registry/Prometheus, Jenkins script console,
  Tomcat manager, PHPUnit `eval-stdin` RCE (CVE-2017-9841, confirmed by a computed
  marker), WordPress REST user enumeration, and more. The official
  projectdiscovery corpus still runs at medium+ alongside.

---
Full diff: v4.1.0...v4.2.0
