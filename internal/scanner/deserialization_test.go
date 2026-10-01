package scanner

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestDeserializationOOBPayloads(t *testing.T) {
	cb := "http://oob.example.com/oob/rcnoob0123456789abcdef0123"
	dnsHost := "rcnoob0123456789abcdef0123.oob.example.com"
	ps := deserializationOOBPayloads(cb, dnsHost)
	if len(ps) != 3 {
		t.Fatalf("expected node + pickle + java payloads, got %d", len(ps))
	}
	joined := strings.Join(ps, "\n")

	// Node node-serialize IIFE with the HTTP callback.
	if !strings.Contains(joined, "_$$ND_FUNC$$_") || !strings.Contains(joined, cb) {
		t.Errorf("node-serialize payload missing marker or callback: %q", ps[0])
	}
	// Java SnakeYAML gadget must use the DNS host (DNS-only-egress catch).
	if !strings.Contains(joined, "ScriptEngineManager") || !strings.Contains(joined, dnsHost) {
		t.Errorf("SnakeYAML payload missing gadget or DNS host")
	}
}

func TestPythonPickleOOBIsValidProto0(t *testing.T) {
	cb := "http://oob.example.com/oob/rcnoobAABBCCDDEEFF00112233"
	b64 := pythonPickleOOB(cb)
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("pickle must be valid base64: %v", err)
	}
	s := string(raw)
	// Protocol-0 opcode structure: GLOBAL builtins.eval, MARK, STRING, TUPLE,
	// REDUCE, STOP — and the callback embedded in the eval'd expression.
	for _, want := range []string{"cbuiltins\neval\n", "(S", "urlopen", cb, "\ntR."} {
		if !strings.Contains(s, want) {
			t.Errorf("pickle stream missing %q; got %q", want, s)
		}
	}
	if !strings.HasSuffix(s, ".") {
		t.Errorf("pickle must end with STOP opcode '.', got %q", s)
	}
}

func TestValueLooksSerialized(t *testing.T) {
	javaB64 := base64.StdEncoding.EncodeToString([]byte{0xAC, 0xED, 0x00, 0x05})
	pickleB64 := base64.StdEncoding.EncodeToString([]byte{0x80, 0x04, 0x95})
	truthy := []string{
		`O:8:"stdClass":0:{}`, // PHP object
		"rO0ABXNy",            // base64 Java (rO0 prefix)
		javaB64,               // base64 decoding to 0xACED
		pickleB64,             // base64 decoding to 0x80
		"_$$ND_FUNC$$_function(){}()",
	}
	for _, v := range truthy {
		if !valueLooksSerialized(v) {
			t.Errorf("valueLooksSerialized(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"", "hello", "12345", "name@example.com"} {
		if valueLooksSerialized(v) {
			t.Errorf("valueLooksSerialized(%q) = true, want false", v)
		}
	}
}

func TestDeserializationProne(t *testing.T) {
	if !deserializationProne(insertionPoint{Param: "session_data", Value: "x"}) {
		t.Error("a name containing 'data' must be prone")
	}
	if !deserializationProne(insertionPoint{Param: "q", Value: `O:8:"x":0:{}`}) {
		t.Error("a PHP-serialized value must be prone regardless of name")
	}
	if deserializationProne(insertionPoint{Param: "q", Value: "hello"}) {
		t.Error("an ordinary param must NOT be prone")
	}
}
