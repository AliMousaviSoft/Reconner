package scanner

import "testing"

func TestNormalizeOOBZone(t *testing.T) {
	cases := map[string]string{
		"oob.example.com":         "oob.example.com",
		"  OOB.Example.COM.  ":    "oob.example.com",
		"https://oob.example.com": "oob.example.com",
		"oob.example.com:53":      "oob.example.com",
		".oob.example.com.":       "oob.example.com",
		"":                        "",
		"localhost":               "", // no dot → not a delegable subdomain
		"example":                 "",
	}
	for in, want := range cases {
		if got := normalizeOOBZone(in); got != want {
			t.Errorf("normalizeOOBZone(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDNSHostFor(t *testing.T) {
	withZone := oobCapability{dnsZone: "oob.example.com"}
	if got := withZone.dnsHostFor("rcnoobabc"); got != "rcnoobabc.oob.example.com" {
		t.Errorf("dnsHostFor with zone = %q", got)
	}
	if got := withZone.dnsHostFor(""); got != "" {
		t.Errorf("empty token must yield empty DNS host, got %q", got)
	}
	noZone := oobCapability{}
	if got := noZone.dnsHostFor("rcnoobabc"); got != "" {
		t.Errorf("no zone must yield empty DNS host, got %q", got)
	}
}
