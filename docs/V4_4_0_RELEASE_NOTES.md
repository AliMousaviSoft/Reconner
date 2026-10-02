# Reconner v4.4.0

Builds on the v4.3.0 WordPress scanner with an authorized WordPress brute-force,
a WordPress option inside the normal project scan, a DOM-XSS fix, and a reworked
report.

## WordPress weak-credential brute-force (authorized, on the WP Scanner page)
The WP Scanner's weak-credential audit now actually sprays when ticked:
- An embedded **top-1000 WordPress password list** (WordPress-specific head + the
  real frequency-ordered base + common mutation rules), still overridable via the
  `wp_passwords` corpus.
- It runs against the **enumerated usernames** (username-as-password first),
  rate-limited, with a hard attempt cap and a per-site time budget, stopping on
  the first hit per user, and confirmed **only** by a definitive XML-RPC
  `wp.getUsersBlogs` success (no lockout, no false positives).
- Ticking the box authorizes active testing for that scan (a per-scan
  `wp_cred_authorized` token sent after an explicit confirm); the server-wide
  `enable_wp_credential_audit` switch still works too. Without either, nothing is
  sprayed — so a select-all/API scan can't brute-force unattended.

## "WP Scan" option in the normal project scan
The standard project scan modal gains a **WordPress scan** selector
(Off / Low / Medium / Deep). When set, the WordPress detection gate verifies which
hosts are really WordPress and only those run the matching WP module set —
low = enumeration + wp-config exposure; medium = +users, backups, endpoints,
misconfig; deep = + the WordPress-tagged nuclei CVE run. The dedicated multi-domain
workflow and the opt-in brute-force remain on the WP Scanner page.

## XSS: hashchange-driven DOM XSS now detected
A sink bound to `window.onhashchange` / `addEventListener('hashchange')` never runs
when a page is opened directly at `base#payload` — the event only fires on a change
after load — so that whole class of hash-router DOM XSS (e.g.
`#"><img src=x onerror=...>`) was being missed. The browser verifier now also loads
the base page and then performs a same-document fragment navigation, firing
`hashchange` so the sink executes; both the canary preflight and the execution
ladder use it, and proof is still nonce-backed browser execution (zero FP).
Verified against a real Chromium with a hashchange-only fixture.

## Report overhaul (pretty, organized, performant on heavy reports)
The self-contained HTML report gains:
- an **executive severity summary** (Critical/High/Medium/Low KPI strip);
- a **sticky global filter** that searches the whole report — findings, hosts,
  URLs, parameters, evidence — hiding non-matching rows and empty sections, so a
  multi-thousand-row report stays navigable (debounced; no lag);
- **collapsible sections** (heavy sections start collapsed and show their count),
  so a large report opens fast;
- **print/PDF** styles (toolbar/TOC hidden, sections auto-expanded, light theme).

---
Full diff: v4.3.0...v4.4.0
