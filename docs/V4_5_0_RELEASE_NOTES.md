# Reconner v4.5.0 — WordPress: proof-gated XML-RPC, real exploits, never-miss detection

This release hardens the WordPress pipeline toward the project motto — **0 false
positives, 0 false negatives, fast / accurate / reliable** — and closes the gap
with (and past) the reference WPScan pipeline. Every change keeps the zero-FP
contract: a finding describes a *demonstrated* primitive, never an advertised
capability.

## XML-RPC is proven, never advertised

Previously `pingback.ping` and `system.multicall` were reported whenever
`system.listMethods` listed them. They are now reported **only when actually
demonstrated on the target host**:

- **`wordpress_xmlrpc_pingback`** — the scanner plants an out-of-band (OAST)
  probe and induces `pingback.ping` to fetch our callback URL as the pingback
  *source* (aimed at a real post discovered via REST, falling back to the site
  root). It is reported **only if the target server actually calls back**; the
  OAST handler records the server's **egress source IP** and promotes a confirmed
  critical finding. No OOB endpoint configured, or no callback caught within the
  window → nothing is reported.
- **`wordpress_xmlrpc_multicall`** — the scanner batches several
  `wp.getUsersBlogs` calls (throwaway bogus creds) into one `system.multicall`
  and reports **only if the host executed each sub-call** (a per-element fault per
  entry) — the exact brute-force amplification primitive. A host that blocks
  batched auth-amplification (WordPress 4.4+ hardening / a security plugin) is not
  reported. Three fixed bogus guesses in one request are a capability probe, far
  below any lockout threshold.

`xmlrpc.php` being live remains an honest **low** (`wordpress_xmlrpc_enabled`).
The advertisement-only `reconner-wp-xmlrpc-multicall` nuclei template was removed
in favour of this in-module proof.

## Real, zero-FP WordPress exploit templates

The always-embedded nuclei pack gains four curated exploit templates whose match
requires unambiguous proof, so a patched/non-vulnerable host can never fire:

- **CVE-2020-11738** — Duplicator `duplicator_download` directory traversal
  leaking `wp-config.php`.
- **Slider Revolution** `revslider_show_image` traversal leaking `wp-config.php`.
- **Exposed SQL dump** — a publicly downloadable WordPress database dump
  (`INSERT INTO` + `wp_options` + `wp_users` required together).
- **CVE-2024-25600** — Bricks Builder unauthenticated RCE, proven by reading the
  public nonce and executing a benign marker command (reported only when the
  marker is echoed back).

The broad plugin/core CVE breadth comes from the official nuclei corpus run under
`-tags wordpress`; this pack is the curated baseline that always ships.

## "WordPress finds no vulnerabilities" — fixed

On an appliance **without `git`**, the official nuclei template corpus was never
provisioned, so `wp_vulns` silently executed only the small embedded pack and
missed every official WordPress plugin/core CVE. Reconner now provisions the full
corpus **git-free** via nuclei's own zip updater on first scan, so the complete
WordPress CVE/exposure set runs.

## Never-miss detection

The detection gate gains WordPress-unique recall boosters that survive a hardened
front end (REST namespace stripped, login path renamed/blocked):

- a live **XML-RPC endpoint advertising WordPress-only methods**
  (`wp.getUsersBlogs` / `wp.getProfile`) — a bar-clearing, zero-FP signal;
- the **`wlwmanifest`**, **oembed**, and **RSD** discovery links as corroborating
  signals.

## Brute-force module fix

The opt-in weak-credential audit (`wp_credaudit`) errored out of a scan because
its per-scan authorization token (`wp_cred_authorized`) was rejected by module
admission. The token is now recognised, so the authorized audit runs as intended
(still default-off, authorization-gated, rate-limited, XML-RPC-confirmed).

## Upgrade

No migration. Rebuild/redeploy. On the first WordPress scan after upgrade the
official template corpus is provisioned once (that scan takes longer); subsequent
scans reuse it.
