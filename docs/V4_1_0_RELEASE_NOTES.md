# Reconner v4.1.0

A stability, detection-coverage, and performance release. No accuracy or
detection power was traded away for speed — every change below either preserves
the exact detection contract or strengthens it.

## Scan speed: classic module-by-module order is the default again
- The v4.0.0 asset-first (per-asset) order walked scored hosts ONE AT A TIME.
  On a large target (e.g. 80+ full-pipeline hosts) that serialisation lost the
  cross-host concurrency the classic sweep has — each module normally
  parallelises across every host at once — so a scan could spend hours before
  the injection modules even finished. The classic module-by-module sweep is
  the default again; asset-first ordering is preserved as an opt-in
  (`prioritized` token / ScanModal toggle) for anyone who wants the top host's
  findings to surface first and accepts the slower wall-clock.

## Front-loaded recon/analysis time sinks removed
- **DOM-XSS browser verification is now speed-profile aware.** It used a fixed
  30-minute base budget (cap 2h) regardless of scan speed, so even an explicit
  "fast" scan could burn 40+ minutes of serial Chromium proofing before
  injection started. Budgets are now fast = 10m cap, normal = 25m cap, slow =
  the old 2h envelope. Pages are already ordered by lead score (reflected
  params first), so a smaller budget trims the low-yield tail, not likely
  findings; slow mode is byte-for-byte the old depth.
- **OpenAPI/Swagger and GraphQL spec harvesting run concurrently across
  origins.** Both were fully serial `origins × candidate-paths` loops of
  8s-timeout probes (~16 minutes combined on an 88-origin target, both usually
  finding nothing). A bounded 16-worker pool gives identical coverage at a
  fraction of the wall-clock.
- **Adaptive DNS resolution uses fast public resolvers + higher concurrency.**
  Resolving ~30k permutation candidates through the system resolver at 50
  threads took ~15 minutes (~33/s). It now resolves against the bundled public
  resolvers in parallel (thread floor 150); same candidate set, same
  wildcard-aware admission gate, orders of magnitude faster.
- **api_data_exposure endpoint concurrency raised 6 → 10** for a large API
  surface, kept moderate deliberately (these probes aren't per-host throttled).

## SSRF: much wider, still zero-false-positive
Every new signature is still gated by the existing baseline + two-control +
double-confirm differential, so an app that legitimately returns a field is
never flagged.
- New confirmations: cloud OAuth **token** responses (GCP service-account,
  Azure managed-identity, any IMDS token route — a confirmed hit is a live
  cloud credential), Kubernetes API/kubelet `*List` responses,
  OpenStack/CloudStack `meta_data.json`, and `file://` local-file disclosure
  (`/etc/passwd`).
- New payloads: GCP + Azure token endpoints, GCP full recursive dump, AWS IAM
  role credential document, `file:///etc/passwd`, and additional metadata-IP
  encodings (fully-expanded IPv4-mapped IPv6, `nip.io` DNS alias).
- **False-negative fix:** Azure's required `Metadata: true` header was only set
  on `/metadata/instance`, so the `/metadata/identity/oauth2/token` probe — the
  most valuable Azure route — was silently rejected and could never confirm.

## SQLi: double-quote-paren context gap closed
- The boolean-pair, error-suffix, and time-based ladders all covered the
  single-quote-paren string context but not its double-quote analogue, and the
  error ladder lacked bare parenthesis-closing boundaries. A parameter
  injectable only inside a double-quoted, parenthesised predicate (or one/two
  parentheses) produced no signal on any path — a silent false negative. Added
  `") AND ("1"="1`, error boundaries `)` / `))` / `'))`, and a
  `") AND SLEEP()` time vector, all still gated by the same reproduce /
  extraction / linear-sleep proofs.

## XSS: modern execution vectors + a real DOM sink fix
- Browserless ladder (DOM-survival-gated, so additions can't create FPs):
  `onpageshow`, `<animateTransform onbegin>`, `<object>`/`<embed>` `onerror`,
  constructor-chain and `globalThis` string-concat call obfuscation.
- Browser proof set: MathML namespace-confusion mXSS (only a real browser
  performs the namespace switch, so it's inert to the static parser and never a
  false positive there).
- **Real DOM-XSS false-negative fix:** the `innerHTML`/`outerHTML` sink patterns
  matched only assignment (`=`), silently missing the extremely common append
  form (`+= tainted`). Broadened to `+=` with a guard that rejects the
  comparison forms (`==` / `===`) so no false positives are introduced.

## Web-behavior: broader 403-bypass and CRLF
- 403/401 bypass (each still proven by two stable 200 controls + a materially
  different body): more IP-spoofing headers (Client-IP, X-Cluster-Client-IP,
  CF-Connecting-IP, X-ProxyUser-Ip) and path-normalization bypasses
  (Tomcat/Spring `/..;/`, leading `//` and `/./`, trailing `/%2e`).
- CRLF/response-header injection (still confirmed by dual-random-header
  response replay): bare-CR (`%0d`) and IIS/.NET `%u000d%u000a` encodings.

## Deep audit: real correctness/coverage bugs fixed
- `fp_rules.go` — panic on a bare `"*"` suppression pattern (`[1:0]` slice)
  turned into a match, not a crash.
- `waf.go` — the Wallarm WAF fingerprint was dead code (exact-key lookup vs a
  name-prefix selector); it could never identify a Wallarm-fronted host.
- `idor.go` — IDOR silently scanned nothing on a single-identity (legacy
  auth_headers) target; the single-account differential heuristic fallback was
  restored (candidate-only, so no new false positives).
- `nosqli.go` — the finding Payload field was hardcoded to `[$ne]` for every
  technique, mislabelling the `$regex` and error-based PoCs.
- `admin_panels.go` — `classifyStoredServicePanels` ignored the per-asset host
  scope, recording admin-panel findings for the whole target during a
  scoped scan and re-scanning all services once per asset.

---
Full diff: v4.0.0...v4.1.0
