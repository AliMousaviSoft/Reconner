package scanner

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"sync"
	"testing"

	"github.com/recon-platform/internal/capture"
)

// buildGuidedMultipartCapture builds a realistic captured multipart request,
// exactly as Guided Analyze would import it from a Burp/HAR file.
func buildGuidedMultipartCapture(t *testing.T, targetURL, field, filename, content string) capture.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if e := mw.WriteField("csrf", "guided-test-token"); e != nil {
		t.Fatal(e)
	}
	part, e := mw.CreateFormFile(field, filename)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := part.Write([]byte(content)); e != nil {
		t.Fatal(e)
	}
	if e := mw.Close(); e != nil {
		t.Fatal(e)
	}
	return capture.Request{
		Method:   http.MethodPost,
		URL:      targetURL,
		MimeType: mw.FormDataContentType(),
		Body:     buf.Bytes(),
	}
}

// The captured request's own execution-proof marker must never be embedded
// literally in an ATTACK request's uploaded bytes (that would make every
// upload look "executed"); this only affects the CAPTURED template body
// itself, which mirrors what a real Burp capture would contain.
func TestGuidedFileUploadFindsExecutionOnMultipartCapture(t *testing.T) {
	withLoopbackAllowed(t)
	var mu sync.Mutex
	files := map[string][]byte{}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			mu.Lock()
			body, ok := files[r.URL.Path]
			mu.Unlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			if marker := executedLabMarker(body); marker != "" && strings.Contains(string(body), "<?php") {
				_, _ = w.Write([]byte(marker))
				return
			}
			_, _ = w.Write(body)
			return
		}
		filename, _, body := readLabUpload(r)
		if filename == "" {
			http.Error(w, "no file field", http.StatusBadRequest)
			return
		}
		stored := "/uploads/" + path.Base(filename)
		mu.Lock()
		files[stored] = body
		mu.Unlock()
		writeUploadJSON(w, server.URL+stored)
	}))
	defer server.Close()

	captured := buildGuidedMultipartCapture(t, server.URL+"/upload", "avatar", "profile.jpg", "not actually a php shell")
	template := GuidedTemplate{ID: "guided-t1", Request: captured, Response: capture.Response{Status: http.StatusOK, MimeType: "application/json"}}

	result, err := runGuidedModule(context.Background(), template, "file_upload")
	if err != nil {
		t.Fatalf("runGuidedModule error: %v", err)
	}
	if result.Status != "findings" {
		t.Fatalf("status=%q reason=%q, want findings", result.Status, result.Reason)
	}
	var sawExecution bool
	for _, f := range result.Findings {
		if f.Type == "file_upload" && f.Parameter == "avatar" {
			sawExecution = true
		}
	}
	if !sawExecution {
		t.Fatalf("no file_upload finding for the avatar field: %+v", result.Findings)
	}
}

// A captured request with no multipart file field (a normal JSON/form POST)
// must be cleanly skipped, not silently run with zero test coverage.
func TestGuidedFileUploadSkipsNonMultipartCapture(t *testing.T) {
	withLoopbackAllowed(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	template := GuidedTemplate{
		ID:       "guided-t2",
		Request:  capture.Request{Method: http.MethodPost, URL: server.URL + "/api/save", MimeType: "application/json", Body: []byte(`{"name":"x"}`)},
		Response: capture.Response{Status: http.StatusOK, MimeType: "application/json"},
	}
	result, err := runGuidedModule(context.Background(), template, "file_upload")
	if err != nil {
		t.Fatalf("runGuidedModule error: %v", err)
	}
	if result.Status != "skipped" {
		t.Fatalf("status=%q, want skipped for a request with no multipart file field", result.Status)
	}
}

// A benign, genuinely inert upload (patched sibling: accepts a real image,
// serves it back inertly) must produce zero findings -- proof-gating, not
// upload-acceptance, decides the verdict, exactly like the production engine.
func TestGuidedFileUploadNoFalsePositiveOnInertUpload(t *testing.T) {
	withLoopbackAllowed(t)
	var mu sync.Mutex
	files := map[string][]byte{}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			mu.Lock()
			body, ok := files[r.URL.Path]
			mu.Unlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			// Inert: always serves back exactly what was stored, never executes it.
			_, _ = w.Write(body)
			return
		}
		filename, _, body := readLabUpload(r)
		if filename == "" {
			http.Error(w, "no file field", http.StatusBadRequest)
			return
		}
		stored := "/uploads/" + path.Base(filename)
		mu.Lock()
		files[stored] = body
		mu.Unlock()
		writeUploadJSON(w, server.URL+stored)
	}))
	defer server.Close()

	captured := buildGuidedMultipartCapture(t, server.URL+"/upload", "avatar", "profile.jpg", "just an image")
	template := GuidedTemplate{ID: "guided-t3", Request: captured, Response: capture.Response{Status: http.StatusOK, MimeType: "application/json"}}

	result, err := runGuidedModule(context.Background(), template, "file_upload")
	if err != nil {
		t.Fatalf("runGuidedModule error: %v", err)
	}
	for _, f := range result.Findings {
		t.Errorf("inert upload endpoint produced a false-positive finding: %+v", f)
	}
}
