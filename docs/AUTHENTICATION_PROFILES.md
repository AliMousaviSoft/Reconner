# Authentication Profiles & Session Lifecycle

Reconner treats an authenticated session as a **durable, verification-aware
prerequisite** with explicit health, refresh, and failure states — not an opaque
static header. This is the implementation of issue #45.

An "Authentication Profile" is an **identity** row: it bundles the request
headers / cookies / bearer token, optional captured browser storage, a validation
endpoint, a refresh strategy, CSRF locator, and lifecycle metadata. All secret
material is encrypted at rest.

## Acquisition modes

1. **Browser-assisted / session import.** Log in normally in your own browser
   (solving CAPTCHA / OTP / MFA / WebAuthn yourself), export a Playwright/Chrome
   `storageState` JSON, and import it (Identities panel → *Import browser
   session*). Reconner keeps only the session material for that origin, encrypted
   — your password never touches the scanner.
2. **Static request authentication.** Paste a `Cookie` and/or `Authorization`
   value (Identities panel → *Add identity*). This is the pre-existing behaviour
   and is unchanged.

Each identity has: `label`, `role`, `is_baseline`, `status`, `auth_method`,
`validation_url`/`validation_signal`, `refresh_strategy`, `expires_at`,
`last_verified_at`, `last_refreshed`, `refresh_attempts`.

## Session health

A session is **never** considered valid just because a request returned `200`.
`ValidateSession` compares the authenticated response against an unauthenticated
one and, when configured, requires the `validation_signal` substring:

```
200 + login page        → expired
302 → /login            → expired
200 + authenticated marker → healthy
```

At the **start of every scan** (in the `http_probe` phase) Reconner validates each
configured identity. An expired session is surfaced loudly rather than letting
every authenticated module silently scan the logged-out app.

## Refresh / re-authentication

Set a per-identity `refresh_strategy`:

- `none` — a dead session stays dead (default).
- `replay` — store a login / token-refresh HTTP request; on detected expiry
  Reconner replays it through the SSRF-guarded transport, follows the login
  redirect chain **within the registrable domain only**, rebuilds the `Cookie`
  from the resulting `Set-Cookie`, updates the identity **atomically**, and
  re-validates.
- `manual` — only an operator re-import can restore it; the session reports
  `refresh_required`.

The scan-start preflight self-heals: *detect → refresh → resume*. On-demand
`Validate` / `Refresh` / `Revoke` controls are in the Identities panel.

## Fail-closed guarantee

Reconner never silently continues unauthenticated after an authenticated
prerequisite becomes invalid. An authenticated-only module consults `AuthGate`,
which validates (and if needed refreshes) the baseline identity and returns
`(ready, configured, state)`:

- no identity configured → unauthenticated scan is legitimate, run as normal;
- a configured session that is proven unusable → the module transitions to an
  explicit **blocked** state (recorded as an audit event) instead of producing a
  misleading zero-result run.

## CSRF token tracking

A rotating anti-CSRF token can be declared via a non-secret `csrf_config`
locator `{url, source, name, header}` where `source` is one of `html_input`,
`html_meta`, `json`, `cookie`. Before a state-changing authenticated request,
`FetchFreshCSRF` fetches a **live** token (never a stored one) so the test isn't
rejected by a stale token.

## Sensitive-data handling

- Cookies, tokens, headers and browser storage are **encrypted at rest**.
- The identity-list and auth-events APIs return **metadata only** — no secret
  column is ever selected.
- Every lifecycle audit event is **redacted at the write point**: any
  credential-shaped fragment (`cookie`/`authorization`/`bearer`/`token`/
  `session`/`csrf`) is replaced with `[redacted]` before storage.
- **Revoke** wipes the stored credentials immediately and sets the strategy to
  `none`, so a revoked session can never be replayed.
- Authentication material is **excluded from exported target bundles** — neither
  the JSON summary nor the artifact bundle references any identity/auth column.

## Lifecycle states & audit

States: `healthy`, `expired`, `refresh_required`, `refresh_failed`, `blocked`,
`revoked`, `unknown`. Every transition (validated / expired / refresh_attempt /
refreshed / refresh_failed / blocked / revoked) is recorded in the sanitized
`auth_events` timeline, visible in the Identities panel and the durable task
history.
