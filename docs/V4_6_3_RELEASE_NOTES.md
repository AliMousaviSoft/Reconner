# Reconner v4.6.3 — IP-only web assets and domain-scoped network scans

Two gaps between how an operator actually enters a target and what the
pipelines could do with it.

## Web: an IP:port asset now defaults to the most aggressive manual profile

Adding an asset like `https://127.0.0.1:8080` (no domain name — the target
*is* an IP) already routed correctly into the web pipeline: `kind` classifies
it `web`, and every web module (`http_probe`, `dir_discovery`,
`backup_discovery`, …) runs against the URL exactly as it would against a
named host, since none of them care whether the host resolves from DNS or is
a literal address.

What was missing: starting a manual scan on it still defaulted to the **Safe**
profile, which deliberately excludes `backup_discovery`/`dir_discovery` to
keep a first scan light. For a domain-based project that's fine — there's a
whole subdomain tree a later, deeper scan can still pick those checks up on.
For a bare IP, there is no "later" — this one value *is* the entire scope, so
silently skipping backup/config-exposure and path discovery meant they might
never run at all unless the operator noticed and switched profiles by hand.

`ScanModal` now detects a single-value scope whose host is a literal IPv4/IPv6
address (`isIPLiteralScope`, covered by a new unit test) and defaults straight
to **Deep** instead of Safe for it, with a short note explaining why. Domain
scopes are completely unaffected.

## Network: scope can now be a domain, not just an IP

The Network Scanner page's own scope field never validated its input, but
`scanner.ExpandNetworkScope` — called both by the scheduler's own admission
check and by the scan itself — accepted only a literal IP, CIDR, or inclusive
range. A domain typed into that field created the project fine, then failed
*every single scan* with "network scope must be a single IP, CIDR, or
inclusive IP range" — the admission check rejected it before the scan ever
started.

`ExpandNetworkScope` now falls back to a bounded DNS resolution (5s timeout,
so a slow/unresponsive resolver can't hang the admission check it runs inside)
for any token that isn't itself a valid IP/CIDR/range but is shaped like a
hostname. Every resolved address still passes through the existing CDN/WAF
exclusion (`FilterCDNWAF`) exactly like a pasted IP would: a domain that
resolves to a recognised CDN/WAF edge is skipped and reported as such; a real
origin gets the full module selection the operator picked, same as if its IP
had been pasted directly. A malformed range/CIDR (all digits/dots/hyphens,
never a letter) is never misread as a hostname and sent to DNS — the original,
more specific parse error still surfaces for those.

New tests: `TestNetworkScopeResolvesAHostname`,
`TestNetworkScopeRejectsUnresolvableHostname`,
`TestNetworkScopeNeverSendsMalformedIPSyntaxToDNS` (scanner package), and
`TestCreateTaskAdmitsDomainScopedNetworkTarget` (scheduler package) — all use
`localhost`, which resolves via the hosts file/NSS rather than a live query,
so they stay deterministic in CI.

## Upgrade

No migration, no new dependencies (both fixes use the Go/JS standard library).
Rebuild/redeploy to pick up the backend and frontend changes.
