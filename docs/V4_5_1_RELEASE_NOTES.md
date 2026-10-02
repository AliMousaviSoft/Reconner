# Reconner v4.5.1 — fix: WordPress scans failing with "phase ledger invariant failed"

Hotfix for a regression introduced alongside the v4.5.0 brute-force admission
fix.

## The bug

Every WordPress scan with the brute-force tick selected (`wp_credaudit` +
`wp_cred_authorized`) completed every real phase successfully and then still
failed with:

```
internal phase ledger invariant failed: 1 phase(s) never reached a terminal state
```

Reproduced live on `blog.aparat.com`, `oiac.org`, and `divar.news` — all
WordPress enumeration/exposure/endpoint/CVE work ran to completion (visible in
the phase ledger as `completed`), but the scan still reported `failed`,
burying genuine findings behind a false failure.

## Root cause

`wp_cred_authorized` is a passthrough authorization flag, not an executable
module — it is read once into the scan context and then stripped out of the
real run loop. Admitting the token into a scan (fixed in v4.5.0, via
`normalizeRequestedModules`) and excluding it from the **phase ledger** (via a
separate switch, `scanOptionToken`) are two different lists. The v4.5.0 fix
only updated the first one, so the token still received a `task_phases` row
with status `pending` that nothing ever dispatches or resolves — and the
end-of-scan terminal-state check correctly flagged that stray row and failed
the whole task.

## Fix

`wp_cred_authorized` is now excluded from the phase ledger the same way every
other behavior-only token (`speed_fast`, `single_endpoint`, …) already is.
Added a regression test (`TestCreateTaskWPCredAuthorizedIsNotAPhase`) that
asserts the token never gets a `task_phases` row and that `tasks.total` stays
consistent with the real phase count.

## Upgrade

No migration. The three scans above (and any other WordPress scan that failed
this way) can simply be re-run via their **Resume** button once this build is
deployed — Resume creates a fresh task through the now-fixed path.
