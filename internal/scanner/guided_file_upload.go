package scanner

// Guided file-upload testing is deliberately its OWN adapter rather than a
// thin call into FileUploadScanner: that engine assumes full-scan scope
// (urlHostInScope-vetted targets, an unbounded request budget, a real
// database-backed OOB/browser proof pipeline) and talks to the network
// directly via the package-level fileUploadClient, which has none of
// guided analyze's safety guarantees (exact-template scope, the 160-request
// module budget, host-pinned verification). Everything here reuses
// file_upload.go's PAYLOAD data (fileUploadAttempts, executableUploadBody,
// extractStoredURLs) -- pure, I/O-free -- but every actual request goes
// through this file's own guided-aware send/verify path.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"

	"github.com/recon-platform/internal/capture"
	"github.com/recon-platform/internal/database"
)

type guidedFileUploadPart struct {
	fieldName, filename, contentType string
}

// guidedMultipartFileFields parses the captured request's multipart body (if
// any) and returns every part shaped like a real file upload (a filename
// parameter on its Content-Disposition). Plain text fields are never
// targeted -- they are preserved verbatim as sibling data by
// guidedMultipartRequest below, exactly like the production engine's
// philosophy of never mutating unrelated form plumbing.
func guidedMultipartFileFields(r capture.Request) (parts []guidedFileUploadPart, boundary string, err error) {
	_, params, err := mime.ParseMediaType(r.MimeType)
	if err != nil || !strings.Contains(strings.ToLower(r.MimeType), "multipart/form-data") || params["boundary"] == "" {
		return nil, "", nil
	}
	boundary = params["boundary"]
	mr := multipart.NewReader(bytes.NewReader(r.Body), boundary)
	for {
		part, e := mr.NextPart()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, boundary, e
		}
		if part.FileName() != "" {
			parts = append(parts, guidedFileUploadPart{fieldName: part.FormName(), filename: part.FileName(), contentType: part.Header.Get("Content-Type")})
		}
		_, _ = io.Copy(io.Discard, part)
	}
	return parts, boundary, nil
}

// guidedMultipartRequest rebuilds the captured multipart body with exactly
// ONE part's filename/content-type/body replaced by the attack attempt;
// every other part (CSRF tokens, tenant IDs, other form fields) is copied
// through byte-for-byte.
func guidedMultipartRequest(ctx context.Context, r capture.Request, boundary, targetField string, a fileUploadAttempt) (*http.Request, error) {
	mr := multipart.NewReader(bytes.NewReader(r.Body), boundary)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	replaced := false
	for {
		part, e := mr.NextPart()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		if !replaced && part.FormName() == targetField && part.FileName() != "" {
			h := make(textproto.MIMEHeader)
			if a.dispositionOverride != "" {
				h.Set("Content-Disposition", a.dispositionOverride)
			} else {
				h.Set("Content-Disposition", fmt.Sprintf(`form-data; name=%q; filename=%q`, targetField, a.filename))
			}
			h.Set("Content-Type", a.contentType)
			w, e := mw.CreatePart(h)
			if e != nil {
				return nil, e
			}
			if _, e := w.Write(a.body); e != nil {
				return nil, e
			}
			replaced = true
			continue
		}
		w, e := mw.CreatePart(part.Header)
		if e != nil {
			return nil, e
		}
		if _, e := io.Copy(w, part); e != nil {
			return nil, e
		}
	}
	if e := mw.Close(); e != nil {
		return nil, e
	}
	req, e := http.NewRequestWithContext(ctx, r.Method, r.URL, &buf)
	if e != nil {
		return nil, e
	}
	for _, h := range r.Headers {
		if !replayHeaderAllowed(h.Name) || strings.EqualFold(h.Name, "Content-Type") {
			continue
		}
		if !validHTTPHeaderName(h.Name) || strings.ContainsAny(h.Value, "\r\n") || len(h.Value) > 16384 {
			continue
		}
		req.Header.Add(h.Name, h.Value)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req, nil
}

// guidedUploadFetch is a deliberately narrower guard than g.roundTrip: proof
// of a file-upload vulnerability inherently requires fetching a DIFFERENT
// path than the captured template (wherever the server actually stored the
// file), which g.roundTrip's exact-template path guard would always reject
// by design. This applies the guard that IS appropriate for that specific
// operation instead: GET only, same scheme+host as the template (never a
// different domain), a small response cap, and it still counts against and
// enforces the same 160-request module budget so limits and reporting stay
// accurate across every guided check.
func guidedUploadFetch(ctx context.Context, g *guidedContext, rawURL string) (status int, body string) {
	base, e := url.Parse(g.request.URL)
	if e != nil {
		return 0, ""
	}
	u, e := url.Parse(rawURL)
	if e != nil || (u.Scheme != "http" && u.Scheme != "https") || !strings.EqualFold(u.Scheme, base.Scheme) || !strings.EqualFold(u.Host, base.Host) {
		return 0, ""
	}
	g.mu.Lock()
	if g.sent >= 160 {
		g.blocked++
		g.mu.Unlock()
		return 0, ""
	}
	g.sent++
	g.mu.Unlock()
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(reqCtx, http.MethodGet, u.String(), nil)
	if e != nil {
		return 0, ""
	}
	for _, h := range g.request.Headers {
		if !replayHeaderAllowed(h.Name) || strings.EqualFold(h.Name, "Content-Type") {
			continue
		}
		if validHTTPHeaderName(h.Name) && !strings.ContainsAny(h.Value, "\r\n") && len(h.Value) <= 16384 {
			req.Header.Add(h.Name, h.Value)
		}
	}
	resp, e := guardedCredentialTransport.RoundTrip(req)
	if e != nil {
		g.mu.Lock()
		g.failed++
		g.mu.Unlock()
		return 0, ""
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()
	return resp.StatusCode, string(raw)
}

func guidedVerifyUploadExecution(ctx context.Context, g *guidedContext, urls []string, a fileUploadAttempt) (string, string) {
	for _, candidate := range urls {
		status, body := guidedUploadFetch(ctx, g, candidate)
		if status >= 200 && status < 400 && strings.Contains(body, a.marker) && !bytes.Contains(a.body, []byte(a.marker)) {
			return candidate, "Uploaded file was retrieved and server-side execution reconstructed the unique marker " + a.marker + "; the full marker does not occur literally in the uploaded source"
		}
	}
	return "", ""
}

func guidedVerifyZipSlip(ctx context.Context, g *guidedContext, urls []string, a fileUploadAttempt) (string, string) {
	for _, candidate := range urls {
		status, body := guidedUploadFetch(ctx, g, candidate)
		if status >= 200 && status < 300 && strings.TrimSpace(body) == a.marker {
			return candidate, "Archive member ../../" + a.marker + ".txt was independently retrieved outside the intended upload directory"
		}
	}
	return "", ""
}

func guidedVerifySQLiFilename(ctx context.Context, t GuidedTemplate, boundary, field string, a fileUploadAttempt, injectedBody string) string {
	clean := fileUploadAttempt{filename: "reconclean.txt", contentType: a.contentType, body: a.body}
	req, e := guidedMultipartRequest(ctx, t.Request, boundary, field, clean)
	if e != nil {
		return ""
	}
	resp, e := guidedClient.Do(req)
	if e != nil {
		return ""
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 || !sqlErrorAppeared(string(raw), injectedBody) {
		return ""
	}
	return "Filename containing a SQL metacharacter (') triggered a new database error signature absent from an identical upload with a clean filename — the filename is very likely inserted into a query unsanitized"
}

// guidedFileUploadChecks tests every multipart file-field part in the
// captured template with the non-OOB, non-browser subset of the production
// file_upload attack ladder. Stored-XSS (SVG, requires a headless-browser
// confirmation) and blind OOB SSRF/XXE (requires callback correlation) are
// skipped, matching this file's existing policy for ssrf/cmdi/xxe: OAST and
// browser verification are not enabled in guided runs. Every mutated-upload
// request is sent via guidedClient, which auto-detects the guided context
// and defers to g.roundTrip (same budget + exact-template guard as every
// other guided check); verification reads use the narrower, deliberate
// guidedUploadFetch guard documented above.
func guidedFileUploadChecks(ctx context.Context, db *database.DB, t GuidedTemplate) {
	g := guidedFrom(ctx)
	if g == nil {
		return
	}
	parts, boundary, err := guidedMultipartFileFields(t.Request)
	if err != nil || len(parts) == 0 {
		return
	}
	for _, part := range parts {
		if ctx.Err() != nil {
			return
		}
		attempts := fileUploadAttempts(oobCapability{}, false, db, t.ID, insertionPoint{URL: t.Request.URL, Param: part.fieldName})
		reported := map[string]bool{}
		for _, a := range attempts {
			if ctx.Err() != nil || reported[a.subtype] || a.proof == proofOOB || a.proof == proofStoredSVG || a.proof == proofConfigEffect {
				continue
			}
			req, e := guidedMultipartRequest(ctx, t.Request, boundary, part.fieldName, a)
			if e != nil {
				continue
			}
			resp, e := guidedClient.Do(req)
			if e != nil {
				continue
			}
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
			resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode >= 400 {
				continue
			}
			urls := extractStoredURLs(t.Request.URL, resp.Header, raw, a.filename)
			var proofURL, evidence string
			switch a.proof {
			case proofExecution:
				proofURL, evidence = guidedVerifyUploadExecution(ctx, g, urls, a)
			case proofZipSlip:
				proofURL, evidence = guidedVerifyZipSlip(ctx, g, urls, a)
			case proofSQLiError:
				proofURL = t.Request.URL
				evidence = guidedVerifySQLiFilename(ctx, t, boundary, part.fieldName, a, string(raw))
			}
			if evidence == "" {
				continue
			}
			_, e = RecordDetectorObservation(ctx, db, DetectorObservation{
				TargetID: t.ID, Type: "file_upload", Subtype: a.subtype, Severity: "critical",
				URL: t.Request.URL, Method: t.Request.Method, Parameter: part.fieldName, Location: "multipart",
				Payload: a.filename, Evidence: evidence + " (proof URL: " + proofURL + ")", Source: "guided",
				DetectionMethod: "retrieval-or-processing-proof", Confidence: ConfPoC, Priority: 500, Verdict: VerifyVerified,
			})
			if e == nil {
				reported[a.subtype] = true
			}
		}
	}
}
