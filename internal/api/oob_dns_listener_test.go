package api

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/recon-platform/internal/config"
)

// TestOOBDNSListenerPromotesLookupToFinding proves the end-to-end DNS channel: a
// bare DNS query for <token>.<zone> — the only thing a DNS-only-egress target can
// do — is caught, correlated by token, and promoted to a confirmed finding, and
// the server answers with the configured callback IP so an egress-capable target
// still connects back over HTTP.
func TestOOBDNSListenerPromotesLookupToFinding(t *testing.T) {
	h := newTestHandler(t)
	h.cfg = &config.Config{BlindXSSCallbackURL: "http://203.0.113.7:8080"}
	if _, err := h.db.Exec(`INSERT INTO targets (id, domain) VALUES ('tgt-1','example.com')`); err != nil {
		t.Fatal(err)
	}
	tok := "rcnoob0123456789abcdef0123"
	if _, err := h.db.Exec(
		`INSERT INTO oob_probes (token, target_id, url, parameter, kind, sink) VALUES (?,?,?,?,?,?)`,
		tok, "tgt-1", "https://victim.example/api?url=x", "url", "ssrf", "param:url"); err != nil {
		t.Fatal(err)
	}

	const port = 15353 // high, unprivileged
	closer, err := h.StartOOBDNSListener("oob.example.com", port)
	if err != nil {
		t.Fatalf("start DNS listener: %v", err)
	}
	defer closer.Close()

	// Give the sockets a moment to be ready.
	time.Sleep(100 * time.Millisecond)

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(tok+".oob.example.com"), dns.TypeA)
	c := &dns.Client{Timeout: 3 * time.Second}
	resp, _, err := c.Exchange(m, "127.0.0.1:15353")
	if err != nil {
		t.Fatalf("dns exchange: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer record, got %d (%v)", len(resp.Answer), resp.Answer)
	}
	if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.String() != "203.0.113.7" {
		t.Fatalf("answer should point at the callback IP, got %v", resp.Answer[0])
	}

	// The lookup must have been promoted to a confirmed blind-SSRF finding.
	var typ, sev string
	if err := h.db.QueryRow(`SELECT type, severity FROM vuln_findings WHERE target_id='tgt-1'`).Scan(&typ, &sev); err != nil {
		t.Fatalf("no finding created from DNS lookup: %v", err)
	}
	if typ != "blind_ssrf" || sev != "critical" {
		t.Fatalf("bad finding: type=%s sev=%s", typ, sev)
	}
	var hits int
	h.db.QueryRow(`SELECT hit_count FROM oob_probes WHERE token=?`, tok).Scan(&hits)
	if hits < 1 {
		t.Fatalf("hit_count=%d want >=1", hits)
	}
}

// TestOOBDNSListenerIgnoresUnknownToken confirms a lookup with no registered token
// is answered (so the zone behaves) but creates no finding — no false positives.
func TestOOBDNSListenerIgnoresUnknownToken(t *testing.T) {
	h := newTestHandler(t)
	h.cfg = &config.Config{BlindXSSCallbackURL: "http://203.0.113.7"}

	const port = 15354
	closer, err := h.StartOOBDNSListener("oob.example.com", port)
	if err != nil {
		t.Fatalf("start DNS listener: %v", err)
	}
	defer closer.Close()
	time.Sleep(100 * time.Millisecond)

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("rcnoobffffffffffffffffffff.oob.example.com"), dns.TypeA)
	c := &dns.Client{Timeout: 3 * time.Second}
	if _, _, err := c.Exchange(m, "127.0.0.1:15354"); err != nil {
		t.Fatalf("dns exchange: %v", err)
	}
	var n int
	h.db.QueryRow(`SELECT COUNT(*) FROM vuln_findings`).Scan(&n)
	if n != 0 {
		t.Fatalf("unknown token must not create a finding, got %d", n)
	}
}
