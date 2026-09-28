# Reconner v3.8.0

## Finding reproducibility (POC completeness)
- Every SQLi/XSS/JWT/account-takeover/race-condition/exposure finding now carries a concrete, replayable **payload** field, not just prose evidence — including blind-boolean SQLi's TRUE/FALSE oracle pair, forged JWT tokens, and account-takeover chain payloads.
- The global **Findings** page now shows the payload inline (with copy button) and an expandable PoC + evidence panel, instead of requiring a trip into the per-target detail view.
- Fixed a gap in the target-detail PoC-URL builder: a compound boolean-SQLi payload (`TRUE=... | FALSE=...`) is now split correctly instead of being stuffed whole into a query parameter.

## File-upload scanner — hardened ~100x
- Massively expanded discovery (source, JS, docs) and payload coverage across RCE, XSS, SQLi, SSRF, and more.
- Real stdlib-encoded image polyglots (GIF/JPEG/PNG) that pass genuine image decoding while carrying a payload.
- New SSRF vectors: HTML-rendering SSRF and DOCX field-code (`INCLUDEPICTURE`) SSRF.
- RFC 5987 filename confusion, path traversal, filename SQLi, MIME-sniff stored XSS, SVG sanitizer-bypass variants.
- Fixed a crash: negative fallback capacity in insertion-point routing.

## Guided Analyze — rebuilt
- Request-first left sidebar (unique requests, not categories), with a clean filter and per-request applicable-test listing.
- New automatic mode, multipart file-upload testing inside guided's safety model (budget-capped, scope-guarded).
- Clearer test-label coverage across all modules.

## Quick scan
- Paste a raw HTTP request (Burp-style) and get an auto-scoped project: every applicable test class (XSS, SQLi, SSRF, file upload, LFI, IDOR, etc.) is auto-detected from the request/response shape and queued automatically.

## Bug Bounty Programs
- Favorite a program to watch it; new assets on a favorited program trigger a notification and, per-favorite policy, an automatic scan (light recon or full scan).
- Professional program list/detail UI: reward ranges, status badges, live sync state.

## Nuclei
- Scans now restricted to medium+ severity by default.
- Audited the custom template pack; fixed a false-positive-prone `docker-compose-exposure` template (anchored YAML matchers).

---
Full diff: v3.6.0...v3.8.0
