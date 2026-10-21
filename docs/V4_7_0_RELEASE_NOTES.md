# Reconner v4.7.0 — recursive subdomain enumeration, fast public-resolver DNS, and a batch of operator-reported fixes

This release makes subdomain discovery dramatically faster and genuinely
recursive, removes a chronic nuclei false positive, and clears a stack of
operator-reported UI and monitoring papercuts.

## Subdomain enumeration

### Recursive discovery (new)

Enumeration no longer stops at the apex. After the apex domain is enumerated,
every newly-discovered **resolving** subdomain is itself enumerated as its own
sub-apex (passive sources + the wildcard-aware resolution gate), and the deeper
names that resolve become the next level's sub-apexes — down to a configurable
depth.

- New config `subdomain_recursion_depth` (default **4**; a logical cap — raise
  it to go deeper). `1` ⇒ apex only (old behavior).
- Only names that actually resolve are descended into; each level is bounded
  (50 sub-apexes) and a global visited set prevents re-work, so a sprawling zone
  cannot explode the fan-out.
- Gated on the same deep-work toggle as brute/permutation, so the fast
  passive-only scan mode stays fast.

### Fast, configurable DNS resolvers (the big speedup)

The dominant cause of enumeration taking **hours** on a few-hundred-name target
was DNS: every native resolution (the admission gate, vhost classification,
wildcard detection) went through the container/host stub resolver — inside
Docker that is the embedded `127.0.0.11` stub, which single-flights lookups and
serializes the whole pass.

- A custom resolver now dials fast public servers directly
  (Cloudflare/Google/Quad9/OpenDNS), picked at random per connection.
- New config `dns_resolvers` (+ `RECON_DNS_RESOLVERS` env). Empty ⇒ the built-in
  public set. The external brute tools (`dnsx`/`puredns`/`massdns`) now use the
  **same** operator-configured list, and the `dnsx` CNAME prefilter finally
  passes `-r` (it previously had none).

### Other enumeration fixes

- **Batched writes + no more rescan spam:** admission writes flush in one
  transaction instead of one INSERT per name, and the live `new_subdomain`
  broadcast now fires only for genuinely new names — a re-scan no longer lights
  up the dashboard as if the whole re-enumeration were fresh discoveries.
- **alterx explosion bounded:** alterx permutation output is capped (150k), and
  a catch-all guard discards a permutation batch when an implausibly high
  fraction of random candidates resolve (an undetected wildcard/catch-all that
  `detectWildcard`'s probes missed) — the exact "suddenly thousands of junk
  subdomains from alterx" symptom. A latent bug that admitted wildcard-only
  names into the live set was also fixed.

## Nuclei

- **Removed a chronic false positive:** the `VMware ESXi SLP - Heap Overflow
  DoS` (CVE-2019-5544) network template confirmed by sending an intrusive crash
  probe to OpenSLP and inferring the vuln from the service going unresponsive —
  a slow, rate-limiting, firewalled, or already-patched host reads identically
  to "vulnerable", and the probe risks knocking over a live host. Blocked by id
  and by display name.
- **Operator control over which templates run (new):** System → Toolchain now
  has a **Scanning configuration** panel (admin) to set DNS resolvers, recursive
  depth, nuclei template IDs to exclude, and extra template repos to clone — all
  persisted to config and applied on the next scan. (Extra-repo URLs are
  validated as http(s) git URLs only, since they are cloned and their YAML runs
  on the box.)

## Monitoring / Changes

- **Technology-change detection (new):** the monitor compared status/title/body/
  security but never the detected technology, so a Server-banner change
  (nginx → cloudflare, a version bump, a new CDN/WAF fronting the origin) was
  invisible. It now records a `tech_change` when the Server header changes.
- **The Changes view is readable again:** old/new values were hard-truncated to
  50 characters with no way to read the rest. They now wrap, show the full value
  on hover, and have a copy button; the change-type badge is colored by class.
- **Richer Telegram change alerts:** the alert now includes the human summary
  (e.g. "3 new subdomain(s) found on x.com") instead of just the change
  category + URL, and the `Target:` header is normalized to a clean host even
  when the target is an endpoint/URL seed.

## Other UI / scan fixes

- **Hosts / HTTP tabs show more than 100 rows:** those list endpoints paginate
  (default 100) and the client discarded the total, so only the first page was
  ever shown. The client now fetches every page.
- **Scan ETA is no longer a constant "7m":** before any module completes there
  was no calibration, so the initial estimate was identical for every target.
  It is now shaped by the known host count (and still calibrates to real elapsed
  time as modules finish).
- **Notification click:** a notification with only an absolute URL (no target)
  was unclickable; it now opens in a new tab.

## Backup / secret-file discovery

- Deeper in-place config/secret coverage (application.yml, config/database.php,
  local.settings.json, secrets.json, firebase.json, settings.php,
  parameters.yml, .env.production, …), each cross-producted with the existing
  backup suffixes and still magic-byte confirmed — pure recall, no new false
  positives.

## Notes

- **Hosts vs URLs** are intentionally distinct layers: *Hosts* are DNS-level
  subdomains (name → IP, alive flag); *URLs/HTTP* are probed live HTTP services
  with status/title/technology. They are shown differently because they are
  different data.
- **Scan cancellation** was investigated: the backend cancel is correct
  (context cancel kills in-flight tool processes via `CommandContext`, and the
  task is marked cancelled across every state). No code change was made for the
  reported "re-probe after cancel" because no mechanism for it exists in the
  current code and a speculative scheduler change would risk the scan lifecycle;
  a reproduction (which target, queued scans, favorite auto-scan state) is
  needed to pin it.
