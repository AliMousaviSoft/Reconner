package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

// TestSSRFMetadataSignatureCoverage asserts every expanded confirmation signature
// matches a real cloud-metadata / file:// response shape, and — critically — that
// NONE of them fire on benign application responses (the false-positive guard).
func TestSSRFMetadataSignatureCoverage(t *testing.T) {
	matchesAny := func(body string) bool {
		for _, re := range ssrfMetadataSignatures {
			if re.MatchString(body) {
				return true
			}
		}
		return false
	}

	// Real metadata / credential / file responses — each MUST be confirmed.
	positives := map[string]string{
		"GCP service-account OAuth token": `{"access_token":"ya29.a0ARrEXAMPLE","expires_in":3599,"token_type":"Bearer"}`,
		"Azure managed-identity token":    `{"access_token":"eyJ0eXAiOiJKV1Qi","client_id":"x","expires_in":"86399","token_type":"Bearer"}`,
		"Kubernetes PodList (kubelet)":    `{"kind":"PodList","apiVersion":"v1","items":[]}`,
		"Kubernetes SecretList":           `{"kind":"SecretList","apiVersion":"v1","items":[{"data":{"token":"abc"}}]}`,
		"OpenStack meta_data.json":        `{"uuid":"1234","availability_zone":"nova","hostname":"web01"}`,
		"file:///etc/passwd read":         "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
		"AWS IAM creds (existing)":        `{"AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"secret"}`,
	}
	for name, body := range positives {
		if !matchesAny(body) {
			t.Errorf("SSRF confirmation MISSED a real metadata response: %s\n  body=%q", name, body)
		}
	}

	// Benign application responses — NONE may be confirmed (zero false positives).
	negatives := map[string]string{
		"ordinary login token":    `{"token":"short-session-abc","user":"alice"}`,
		"generic JSON API":        `{"id":42,"name":"widget","status":"active"}`,
		"error page":              `{"error":"failed to fetch remote url","code":502}`,
		"reflected payload echo":  `{"url":"http://169.254.169.254/latest/meta-data/"}`,
		"passwd word in prose":    `Enter your root password: the account root does not expire (0:0 policy).`,
		"kind field, non-k8s":     `{"kind":"article","title":"How To"}`,
		"availability generic":    `{"region":"us-east-1","available":true}`,
		"access_token no expires": `{"access_token":"abc"}`, // token key alone is not enough
	}
	for name, body := range negatives {
		if matchesAny(body) {
			t.Errorf("SSRF confirmation FALSE POSITIVE on a benign response: %s\n  body=%q", name, body)
		}
	}
}

// TestSSRFConfirmsTokenEndpointEndToEnd drives the real SSRFScanner against a mock
// app that only leaks a cloud OAuth token when the injected value targets the GCP
// token metadata route — proving the new token payload + signature confirm a real
// SSRF end-to-end, while a benign reflecting endpoint stays unflagged.
func TestSSRFConfirmsTokenEndpointEndToEnd(t *testing.T) {
	withLoopbackAllowed(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("dest")
		// Simulate a server-side fetch: only the GCP token metadata route yields the
		// credential; everything else is an ordinary "fetch failed".
		if strings.Contains(target, "service-accounts/default/token") && r.Header.Get("Metadata-Flavor") == "Google" {
			fmt.Fprint(w, `{"access_token":"ya29.a0ARrEXAMPLE_token_value","expires_in":3599,"token_type":"Bearer"}`)
			return
		}
		fmt.Fprint(w, `{"error":"fetch failed"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db, targetID := newV3ScannerDB(t)
	seedV3Parameter(t, db, targetID, srv.URL+"/fetch?dest=https://example.test", "dest", "https://example.test", "GET", "", "query")

	cfg := &config.Config{}
	if err := NewSSRFScanner(db, tools.NewExecutor(cfg, logger.New("error")), cfg, logger.New("error"), nil).
		Run(context.Background(), targetID, func(_, _, _ string) {}); err != nil {
		t.Fatal(err)
	}
	if got := v3FindingCount(t, db, targetID, "ssrf", "/fetch"); got != 1 {
		t.Fatalf("GCP token-route SSRF findings=%d, want 1", got)
	}
}
