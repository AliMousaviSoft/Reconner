package capture

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func parseRawRequest(raw []byte, absoluteURL string) (Request, error) {
	if len(raw) == 0 {
		return Request{}, fmt.Errorf("request message is empty")
	}
	r, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return Request{}, fmt.Errorf("invalid raw request: %w", err)
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxMessageBytes+1))
	if err != nil || len(body) > MaxMessageBytes {
		return Request{}, fmt.Errorf("request body exceeds limit")
	}
	u := strings.TrimSpace(absoluteURL)
	if parsed, e := url.Parse(u); e != nil || parsed.Scheme == "" || parsed.Host == "" {
		scheme := "https"
		if r.URL != nil && r.URL.Scheme != "" {
			scheme = r.URL.Scheme
		}
		u = scheme + "://" + r.Host + r.URL.RequestURI()
	}
	return Request{
		Method: strings.ToUpper(r.Method), URL: u, HTTPVersion: r.Proto,
		Headers: flattenHeaders(r.Header, r.Host), Body: body,
		MimeType: r.Header.Get("Content-Type"),
	}, nil
}

func parseRawResponse(raw []byte, request Request) (Response, error) {
	dummy, _ := http.NewRequest(request.Method, request.URL, nil)
	r, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), dummy)
	if err != nil {
		return Response{}, fmt.Errorf("invalid raw response: %w", err)
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxMessageBytes+1))
	if err != nil || len(body) > MaxMessageBytes {
		return Response{}, fmt.Errorf("response body exceeds limit")
	}
	return Response{
		Status: r.StatusCode, HTTPVersion: r.Proto, Headers: flattenHeaders(r.Header, ""),
		Body: body, MimeType: r.Header.Get("Content-Type"),
	}, nil
}

func flattenHeaders(h http.Header, host string) []Header {
	out := make([]Header, 0, len(h)+1)
	if host != "" {
		out = append(out, Header{Name: "Host", Value: host})
	}
	for name, values := range h {
		for _, value := range values {
			out = append(out, Header{Name: http.CanonicalHeaderKey(name), Value: value})
		}
	}
	return out
}
