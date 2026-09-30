package api

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"

	"github.com/miekg/dns"
)

// oobDNSListener holds the UDP+TCP authoritative servers for the OOB zone so both
// can be shut down together.
type oobDNSListener struct {
	udp *dns.Server
	tcp *dns.Server
}

func (l *oobDNSListener) Close() error {
	if l.udp != nil {
		_ = l.udp.Shutdown()
	}
	if l.tcp != nil {
		_ = l.tcp.Shutdown()
	}
	return nil
}

// StartOOBDNSListener runs an authoritative DNS server for the delegated OOB zone
// (e.g. "oob.example.com"). It is the Collaborator/interactsh-class channel the
// HTTP /oob and raw JNDI listeners can't cover: a blind payload that only makes
// the target RESOLVE a name — MySQL LOAD_FILE / MSSQL xp_dirtree over a UNC path,
// a Windows `nslookup`, an Oracle UTL_HTTP whose first act is a DNS lookup, or any
// SSRF/XXE against a host that can resolve DNS but cannot open an outbound
// HTTP/LDAP connection to us — still triggers a lookup of <token>.<zone>. This
// server receives that query, extracts the token from the leftmost label, and
// promotes it to a confirmed finding via the same RecordOOBHit path.
//
// A/AAAA queries inside the zone are answered with the platform's own public
// address (derived from the callback URL) so that, when egress to us IS open, the
// follow-on HTTP connection still lands on our HTTP OOB listener for a second,
// corroborating hit. Bind on both UDP and TCP (large answers / resolvers that
// retry over TCP). Best-effort: a bind failure is returned so serve can log it and
// carry on — the rest of the platform is unaffected.
func (h *Handler) StartOOBDNSListener(zone string, port int) (io.Closer, error) {
	zone = strings.ToLower(strings.Trim(strings.TrimSpace(zone), "."))
	if zone == "" {
		return nil, fmt.Errorf("empty OOB DNS zone")
	}
	if port <= 0 {
		port = 53
	}
	answerV4, answerV6 := h.oobDNSAnswerIPs()
	fqdnZone := dns.Fqdn(zone)

	mux := dns.NewServeMux()
	mux.HandleFunc(fqdnZone, func(w dns.ResponseWriter, r *dns.Msg) {
		h.handleOOBDNSQuery(w, r, fqdnZone, answerV4, answerV6, port)
	})

	addr := fmt.Sprintf(":%d", port)
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("bind udp %s: %w", addr, err)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("bind tcp %s: %w", addr, err)
	}

	l := &oobDNSListener{
		udp: &dns.Server{PacketConn: pc, Handler: mux},
		tcp: &dns.Server{Listener: ln, Handler: mux},
	}
	go func() { _ = l.udp.ActivateAndServe() }()
	go func() { _ = l.tcp.ActivateAndServe() }()
	return l, nil
}

// handleOOBDNSQuery records any token in the queried name and answers with the
// platform's address (A/AAAA) so a subsequent HTTP callback still resolves to us.
func (h *Handler) handleOOBDNSQuery(w dns.ResponseWriter, r *dns.Msg, fqdnZone string, v4, v6 net.IP, port int) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	srcIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	recorded := map[string]bool{}
	for _, q := range r.Question {
		name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
		for _, tok := range oobTokenRe.FindAllString(name, -1) {
			if recorded[tok] {
				continue
			}
			recorded[tok] = true
			h.RecordOOBHit(tok, srcIP, "DNS", dns.TypeToString[q.Qtype], fmt.Sprintf("DNS %s :%d", q.Name, port))
		}
		// Answer in-zone A/AAAA so an egress-capable target then connects to us.
		switch q.Qtype {
		case dns.TypeA:
			if v4 != nil {
				if rr, err := dns.NewRR(fmt.Sprintf("%s 30 IN A %s", q.Name, v4.String())); err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		case dns.TypeAAAA:
			if v6 != nil {
				if rr, err := dns.NewRR(fmt.Sprintf("%s 30 IN AAAA %s", q.Name, v6.String())); err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
	}
	_ = w.WriteMsg(m)
}

// oobDNSAnswerIPs resolves the platform's own public address from the configured
// callback URL, so DNS answers point egress-capable targets back at our HTTP
// listener. Returns (nil,nil) if it cannot be determined — the DNS hit is still
// recorded, which is the whole point; only the follow-on HTTP corroboration is
// lost.
func (h *Handler) oobDNSAnswerIPs() (net.IP, net.IP) {
	if h.cfg == nil {
		return nil, nil
	}
	raw := strings.TrimSpace(h.cfg.BlindXSSCallbackURL)
	if raw == "" {
		return nil, nil
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, nil
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
		return nil, ip
	}
	var v4, v6 net.IP
	if ips, err := net.LookupIP(host); err == nil {
		for _, ip := range ips {
			if t := ip.To4(); t != nil && v4 == nil {
				v4 = t
			} else if ip.To4() == nil && v6 == nil {
				v6 = ip
			}
		}
	}
	return v4, v6
}
