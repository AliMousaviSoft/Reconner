package scanner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// bodyProtoGadget extracts the __proto__ gadget object from a request body.
func bodyProtoGadget(r *http.Request) map[string]any {
	data, _ := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	var obj map[string]any
	if json.Unmarshal(data, &obj) != nil {
		return nil
	}
	if p, ok := obj["__proto__"].(map[string]any); ok {
		return p
	}
	return nil
}

func jsonPoint(url string) insertionPoint {
	return insertionPoint{
		URL: url, Param: "q", Value: "x",
		Method: "POST", ContentType: "application/json", Location: "json",
	}
}

// A server that honours the Express "json spaces" gadget (indents res.json by N
// when __proto__['json spaces']=N) must be confirmed — non-reflective SSPP.
func TestBehavioralSSPPJSONSpaces(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g := bodyProtoGadget(r)
		payload := map[string]any{"ok": true, "user": "alice"}
		w.Header().Set("Content-Type", "application/json")
		if g != nil {
			if n, ok := g["json spaces"].(float64); ok && n > 0 {
				enc, _ := json.MarshalIndent(payload, "", strings.Repeat(" ", int(n)))
				w.Write(enc)
				return
			}
		}
		enc, _ := json.Marshal(payload) // compact baseline
		w.Write(enc)
	}))
	defer srv.Close()

	payload, evidence, method, conf := prototypeBehavioralProof(context.Background(), jsonPoint(srv.URL+"/api"), nil)
	if evidence == "" {
		t.Fatal("json-spaces SSPP gadget must be confirmed")
	}
	if method != "sspp-json-spaces-differential" {
		t.Errorf("method = %q", method)
	}
	if conf != ConfPoC {
		t.Errorf("confidence = %d, want ConfPoC", conf)
	}
	if !strings.Contains(payload, "json spaces") {
		t.Errorf("payload should carry the gadget: %q", payload)
	}
}

// A server honouring the status gadget (and NOT json spaces) must be confirmed
// via the status-override path.
func TestBehavioralSSPPStatusOverride(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g := bodyProtoGadget(r)
		w.Header().Set("Content-Type", "application/json")
		if g != nil {
			if s, ok := g["status"].(float64); ok {
				w.WriteHeader(int(s))
			}
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	_, evidence, method, _ := prototypeBehavioralProof(context.Background(), jsonPoint(srv.URL+"/api"), nil)
	if evidence == "" {
		t.Fatal("status-override SSPP gadget must be confirmed")
	}
	if method != "sspp-status-override-differential" {
		t.Errorf("method = %q", method)
	}
}

// A non-vulnerable server that ignores prototype keys entirely must NOT be
// flagged — the behavioural gadgets must be zero-false-positive.
func TestBehavioralSSPPNoFalsePositive(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`)) // always compact 200, ignores any __proto__
	}))
	defer srv.Close()

	if _, evidence, _, _ := prototypeBehavioralProof(context.Background(), jsonPoint(srv.URL+"/api"), nil); evidence != "" {
		t.Fatalf("non-vulnerable server must not be flagged, got: %s", evidence)
	}
}

// A server that ALWAYS indents (unrelated to pollution) must not be mistaken for
// the json-spaces gadget — the compact baseline requirement guards this.
func TestBehavioralSSPPAlwaysIndentedIsNotFlagged(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		enc, _ := json.MarshalIndent(map[string]any{"ok": true}, "", "    ") // always 4-space
		w.Write(enc)
	}))
	defer srv.Close()

	if _, evidence, _, _ := prototypeBehavioralProof(context.Background(), jsonPoint(srv.URL+"/api"), nil); evidence != "" {
		t.Fatalf("an always-indented server must not be flagged, got: %s", evidence)
	}
}

func TestJSONIndentWidth(t *testing.T) {
	if w := jsonIndentWidth(`{"a":1}`); w != 0 {
		t.Errorf("compact width = %d, want 0", w)
	}
	if w := jsonIndentWidth("{\n         \"a\": 1\n}"); w != 9 {
		t.Errorf("9-space width = %d, want 9", w)
	}
}
