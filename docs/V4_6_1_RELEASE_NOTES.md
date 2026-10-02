# Reconner v4.6.1 — Network Scanner: RDP/VNC/Telnet/SMB credential audit (ncrack + hydra)

Completes the Network Scanner's per-service credential audit from v4.6.0.
The four protocols explicitly excluded there — RDP, VNC, Telnet, SMB — are now
covered too, backed by two purpose-built, widely audited network-login
crackers instead of a hand-rolled, correctness-risky native implementation:

- **ncrack** → RDP, VNC, Telnet
- **hydra** → SMB

Both are optional external tools (every new module degrades to a clean skip
when its tool is unavailable, exactly like every other optional tool in
Reconner) and ship in the Docker image alongside nmap/sqlmap/etc.

## Four new opt-in modules

`network_brute_rdp`, `network_brute_vnc`, `network_brute_telnet`,
`network_brute_smb` — each individually selectable in the Network Scanner page
and the per-asset scan modal, sharing the exact same discipline as the five
native modules: gated by `enable_network_credential_audit` or the per-scan
`net_cred_authorized` token, scoped only to services this scan's own
fingerprint pass already verified open and identified by name, and **confirmed
only by the tool's own definitive success report** — never an inferred or
guessed result:

- RDP/VNC/Telnet: ncrack's own "discovered credentials" line for that exact
  protocol.
- SMB: hydra's canonical `[port][smb2] host: … login: … password: …` line.

The underlying process is killed the instant a credential is confirmed
(streamed, not polled after the fact), and the password corpus fed to these
four is capped at 200 entries rather than the full 1000 — RDP/SMB in
particular commonly enforce real account-lockout policies, so a smaller,
higher-signal subset is the responsible default.

## Reversing an earlier retirement — deliberately, on request

hydra and ncrack were previously evaluated and explicitly retired in this
project's history, with test guards (`tool_install_test.go`,
`module_contracts_test.go`) specifically preventing their reintroduction. That
decision is reversed in this release at the operator's explicit direction, for
their own authorized security-testing use. The guards now pin hydra+ncrack as
expected, supported tools instead of rejecting them; uncover/dalfox/gowitness
remain retired.

## Upgrade

No migration. Rebuild/redeploy to pick up the two new apt packages
(`hydra`, `ncrack`) in the Docker image.
