package scanner

import "testing"

// TestWafSigHeaderPrefixMatch proves a wafSig header selector ending in "-"
// (a name-prefix wildcard, used by vendors like Wallarm whose real response
// header varies — X-Wallarm-Status, X-Wallarm-Block, …) actually matches. The
// exact-key lookup hdr[h] in wafSig.match can never match such an entry since
// no header is literally named "x-wallarm-", which made the whole signature
// dead code until match() gained prefix-scanning for these entries.
func TestWafSigHeaderPrefixMatch(t *testing.T) {
	sig := wafSig{name: "Wallarm", headers: map[string]string{"x-wallarm-": ""}}

	hdr := map[string]string{"x-wallarm-status": "block"}
	if !sig.match(hdr, "", "", "") {
		t.Error("a header starting with the \"x-wallarm-\" prefix must match the Wallarm signature")
	}

	// A completely unrelated header set must not match.
	other := map[string]string{"server": "nginx", "content-type": "text/html"}
	if sig.match(other, "", "", "") {
		t.Error("unrelated headers must not match the Wallarm prefix signature")
	}
}

// TestWafSigHeaderExactMatch proves an ordinary (non-prefix) header selector
// still requires the exact header name, unaffected by the prefix-matching
// path added for entries like Wallarm's.
func TestWafSigHeaderExactMatch(t *testing.T) {
	sig := wafSig{name: "Azure Front Door / App Gateway", headers: map[string]string{"x-azure-ref": ""}}
	if !sig.match(map[string]string{"x-azure-ref": "0123"}, "", "", "") {
		t.Error("exact header name match must still work")
	}
	if sig.match(map[string]string{"x-azure-referrer": "0123"}, "", "", "") {
		t.Error("a differently-named header must not satisfy an exact (non-prefix) selector")
	}
}

func TestDetectWAFSignaturesIncludeWallarm(t *testing.T) {
	found := false
	for _, sig := range wafSignatures {
		if sig.name == "Wallarm" {
			found = true
		}
	}
	if !found {
		t.Fatal("Wallarm signature missing from wafSignatures")
	}
}
