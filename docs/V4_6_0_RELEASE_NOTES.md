# Reconner v4.6.0 — Network Scanner: dedicated pipeline, per-service credential audit, service-aware nuclei

A ground-up upgrade to network scanning, mirroring the WP Scanner's design:
**0 false positives, 0 false negatives, fast and reliable.**

## Dedicated Network Scanner page

Left nav → **Network Scanner** (`/network-scanner`). Create a project from one
or many IP/CIDR/inclusive-range scopes, pick a port-scan profile (fast/normal/
deep) and the modules to run — all individually selectable, exactly like the
WP Scanner's module picker. The existing per-asset scan modal (for `mixed`
projects) gained the same new per-service credential-audit checkboxes.

## Port scanning: faster discovery, verification that never skips

- The fast profile's "important ports" set grew from ~44 to ~180 curated ports
  — remote access, databases, caches, message queues, container/orchestration
  APIs, common web-admin ports — real coverage, still genuinely fast.
- nmap `-sV` service-version verification now runs on **every** profile, not
  only when the operator went deep — a profile changes how many ports get
  scanned, never whether what's found gets verified.

## Service-aware nuclei

`network_nuclei_only` used to pass a fixed `["network","ssl"]` tag pair on
every run, so the official corpus's protocol-specific templates (redis, ssh,
mysql, mongodb, rdp, smb, elasticsearch, docker, …) were synced but never
selected to actually execute. Tags are now computed from the services **this
scan's own fingerprint pass actually detected**.

## New: automatic, zero-guess exposure checks

Part of the `network` module itself, no opt-in needed (neither guesses a
secret — both test a documented *public* server convention):

- **Anonymous FTP access** — confirmed only by the server's own `230` reply to
  the RFC 1635 anonymous login.
- **Redis with no password configured** — confirmed only by an unauthenticated
  `INFO` reply carrying two independent fields together.

## New: opt-in per-service credential audit

Five new individually-selectable, opt-in modules — SSH, FTP, MySQL,
PostgreSQL, Redis — each sharing the same conservative discipline as the WP
Scanner's weak-credential audit: enumerated/curated usernames only, the
top-1000 password corpus, rate-limited, capped, stop-on-first-hit, and
**confirmed only by a definitive protocol-level signal**:

- SSH: a completed `golang.org/x/crypto/ssh` password handshake.
- FTP: the server's own `230` reply.
- MySQL: a successful connection via the real wire protocol
  (`go-sql-driver/mysql` — every auth-plugin variant handled correctly).
- PostgreSQL: a successful connection, or the post-auth `3D000`
  ("database doesn't exist") error that only a correct credential reaches.
- Redis: the server's own `+OK` reply to `AUTH`.

Gated by the server-wide `enable_network_credential_audit` switch **or** a
per-scan `net_cred_authorized` token the UI sends only after an explicit
confirm — default off either way.

RDP, VNC, Telnet and SMB are deliberately **not** included: proving a
credential against them needs a full NTLM/CredSSP or RFB implementation
(high correctness risk) or a dedicated brute tool — and this project already
evaluated and explicitly retired that path (hydra/ncrack remain on the
"retired, never reintroduce" list enforced by `tool_install_test.go` and
`module_contracts_test.go`). Those services are still fully fingerprinted;
only guessing their credentials is out of scope.

## Full write-up

See `docs/NETWORK_SCANNER.md` for the complete module reference.

## Upgrade

No migration. Rebuild/redeploy.
