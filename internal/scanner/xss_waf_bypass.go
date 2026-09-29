package scanner

import (
	"fmt"
	"strings"
)

// WAF-bypass request-encoding layer for the browserless XSS confirm ladder —
// the XSS equivalent of sqli_adaptive.go's tamperVariants. Until now XSS had
// NO request-level evasion at all: every vector in xss_payloads.go varies the
// PAYLOAD'S HTML/JS shape (case, tag, handler, obfuscated call), but every one
// of them still sends the literal substring "alert(" on the wire. A WAF whose
// rule is a plain regex/keyword match on "alert(" (or on "<script"/"onerror=")
// blocks all of them identically, so the whole ladder fails together — not
// because the app filters XSS, but because the EDGE never lets the request
// through to find out.
//
// These variants change ONLY how the executable JavaScript is SPELLED on the
// wire, never what it does once parsed:
//
//   - HTML numeric character references (decimal &#97; / hex &#x61;) inside an
//     event-handler attribute VALUE. A browser decodes these before treating
//     the value as script — exactly like it decodes &amp; — so the DECODED
//     script is identical to the plain payload. golang.org/x/net/html decodes
//     them the same way when parsing both the payload template (to compute the
//     expected signal) and the live response, so execPayloadSurvived's
//     differential proof is not weakened by using this form.
//   - JavaScript Unicode identifier escapes (alert === alert). Valid
//     ECMAScript syntax; the substring "alert(" never appears in the request
//     at all. This form is verified as a literal-string survival check only
//     (the HTML parser does not evaluate JS), the same honesty level every
//     other entry in this ladder already uses for its "differential-candidate"
//     tier.
func xssWAFTamperVariants(p xssExecPayload) []xssExecPayload {
	if !strings.Contains(p.Payload, xssAlert) {
		return nil
	}
	variant := func(js string) xssExecPayload {
		return xssExecPayload{
			Payload: strings.Replace(p.Payload, xssAlert, js, 1),
			Elem:    p.Elem, Token: p.Token,
		}
	}
	return []xssExecPayload{
		variant(htmlEntityEncodeDecimal(xssAlert)),
		variant(htmlEntityEncodeHex(xssAlert)),
		variant(jsUnicodeEscapeLetters(xssAlert)),
	}
}

// htmlEntityEncodeDecimal renders every byte of s as a decimal HTML numeric
// character reference (&#NN;). A browser decodes these in an attribute value
// exactly as it decodes any other entity, before the value is treated as an
// event-handler script.
func htmlEntityEncodeDecimal(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 5)
	for _, r := range s {
		fmt.Fprintf(&b, "&#%d;", r)
	}
	return b.String()
}

// htmlEntityEncodeHex is htmlEntityEncodeDecimal's hex form (&#x61;) — some
// WAF request normalizers only canonicalize one numeric base before matching.
func htmlEntityEncodeHex(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 6)
	for _, r := range s {
		fmt.Fprintf(&b, "&#x%x;", r)
	}
	return b.String()
}

// jsUnicodeEscapeLetters rewrites every ASCII letter in s as a JavaScript
// Unicode identifier escape (a for 'a'), leaving punctuation (the call's
// parens and dots) untouched — ( is not valid identifier syntax, but
// alert is a spec-legal spelling of the identifier "alert" that no
// literal-substring WAF signature can match.
func jsUnicodeEscapeLetters(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 6)
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			fmt.Fprintf(&b, "\\u%04x", r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
