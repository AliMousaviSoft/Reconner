# Network Scanner

Reconner ships a dedicated, modular network offensive pipeline — the **Network
Scanner** (left nav → *Network Scanner*, route `/network-scanner`) — mirroring
the WP Scanner's design: create a project from one or many IP/CIDR/inclusive-range
scopes, verify everything, then run only the modules you pick.

The whole family is held to the project motto: **0 false positives, 0 false
negatives, fast and reliable**. Every service is confirmed before anything acts
on it (nmap `-sV`, never a bare open port treated as a known service), and every
credential-audit hit is confirmed by a definitive, protocol-level success signal
— never a guess.

## Port discovery is fast *and* accurate

- **Discovery**: naabu TCP-connect discovery (falling back to a bounded native
  connect scan when naabu is unavailable) over a curated ~180-port "important
  ports" set for the **fast** profile — remote access, databases, caches,
  message queues, container/orchestration APIs, common web-admin ports — not
  just the historical top-40. **Normal** sweeps the top 1000 ports; **deep**
  sweeps all 65535.
- **Verification**: nmap `-sV` service-version fingerprinting (with
  best-effort `-O` OS detection) runs on every open port in **every** profile,
  not just the deep one — a profile only changes *how many ports get scanned*,
  never *whether what's found gets verified*. If nmap is unavailable, a native
  banner-grab fallback still records the service hint.
- ICMP host discovery is recorded as a hint only — a missing ping reply never
  suppresses TCP scanning (ICMP is commonly filtered and would otherwise cause
  false negatives).

## Modules (individually selectable, like the WP Scanner)

| Module | What it confirms | Severity |
| --- | --- | --- |
| `network` | Port/service/OS discovery (always on, the gate). | — |
| `network_nuclei_only` | Nuclei run with tags chosen from what was **actually detected** (ssh/ftp/mysql/redis/rdp/smb/postgres/mongodb/…), not a fixed generic pair — so protocol-specific official templates actually get exercised. | medium+ |
| `network_initial_access` | The same proof-gated 401/403 authorization-bypass checks the web scanner uses, against discovered network web services. | medium+ |
| `network_brute` | HTTP Basic credential audit (opt-in). | high |
| `network_brute_ssh` | SSH credential audit (opt-in). | critical |
| `network_brute_ftp` | FTP credential audit (opt-in). | critical |
| `network_brute_mysql` | MySQL credential audit (opt-in). | critical |
| `network_brute_postgres` | PostgreSQL credential audit (opt-in). | critical |
| `network_brute_redis` | Redis credential audit (opt-in). | critical |

Each module self-gates on the discovery result (every brute module only ever
targets services *this scan's own* fingerprint pass already verified open and
identified by name — never a guessed port), so they are safe to run in any
order and independently.

## Zero-false-positive confirmation, per class

- **Service-aware nuclei**: tags are derived from the distinct service names
  this scan detected (`networkNucleiTags`), always including the generic
  `network,ssl` baseline so exposure/misconfig templates with no specific
  service tag still run.
- **Known public-convention exposures** (automatic, part of the `network`
  module — no opt-in needed, since neither guesses anyone's secret):
  - **Anonymous FTP access** — confirmed only by the server's own `230` (user
    logged in) reply to the standard `anonymous`/`anonymous@…` login RFC 1635
    defines as a public, non-secret convention.
  - **Redis with no password configured** — confirmed only by an unauthenticated
    `INFO` reply carrying **both** `redis_version:` and `run_id:` (two
    independent fields), so a stray substring elsewhere can never match alone.

## Opt-in per-service credential audit

Credential testing is dual-use, so it is boxed in exactly like the WP Scanner's
weak-credential audit:

- **No active password testing** unless the operator sets the server-wide
  switch `enable_network_credential_audit: true`
  (env `RECON_ENABLE_NETWORK_CREDENTIAL_AUDIT=true`) **or** ticks the
  per-service box in the Network Scanner UI (which sends the per-scan
  `net_cred_authorized` token after an explicit confirm). Default **off** for
  both.
- **Conservative by construction**: a tiny curated username list per protocol
  (never a username wordlist) × the top-1000 password corpus, serial with a
  delay, a hard attempt cap (6000), a 15-minute wall-clock budget per protocol,
  and stops on the first hit per target. At most 5 targets per protocol per
  scan.
- **A hit is confirmed only by a definitive, protocol-level signal — never a
  guess**:
  - **SSH** — a completed `golang.org/x/crypto/ssh` password handshake (the
    library only returns a live client after the server accepts the
    credential).
  - **FTP** — the server's own `230` (user logged in) reply.
  - **MySQL** — a successful connection via the real MySQL wire protocol
    (`go-sql-driver/mysql`), so every auth-plugin variant the driver supports
    is handled correctly — never a hand-rolled, partially-correct handshake.
  - **PostgreSQL** — a successful connection, **or** the server's own
    post-authentication `3D000` (`invalid_catalog_name`, i.e. "that database
    doesn't exist") error — Postgres authenticates *before* checking the
    target database, so reaching that specific error already proves the
    credential.
  - **Redis** — the server's own `+OK` reply to `AUTH`.
- The working credential lands in the finding **payload** (the PoC, e.g. the
  exact `ssh`/`mysql`/`redis-cli` replay command); the evidence line masks the
  secret.

### Why RDP / VNC / Telnet / SMB are not included

Those four are deliberately **out of scope** for credential testing. Proving a
credential against RDP or SMB needs a full NTLM/CredSSP implementation; VNC
needs a bounded-but-still-binary RFB challenge-response. Hand-rolling either
without a battle-tested library is a real correctness risk under this
project's zero-false-positive bar, and the obvious alternative — a dedicated
brute-force tool (hydra/ncrack) — was **already evaluated and explicitly
retired** earlier in this project's history (see the "retired/unused tool"
guards in `tool_install_test.go` and `module_contracts_test.go`). Those
services are still fully enumerated and fingerprinted by the `network` module;
only guessing their credentials is excluded.

## Custom wordlists

| Corpus id | Used by |
| --- | --- |
| `net_passwords` | the generic top-1000 password list every `network_brute_*` module sprays |

Override/extend it by dropping a `reconner-custom-net_passwords.txt` file in
the wordlists directory, exactly like the WP Scanner's `wp_passwords` corpus.

## API

- `GET /targets/{id}/network-services` — the verified service inventory (ip,
  port, protocol, service, product, version, banner, is_web/web_url/web_title,
  tls, os_guess, rdns).
- Findings surface through the normal findings pipeline (type prefix
  `network_*`), each with a reproduction PoC.
