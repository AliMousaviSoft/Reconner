package capture

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
)

var (
	ErrImportTooLarge = errors.New("capture exceeds the import size limit")
	ErrUnsafeXML      = errors.New("XML directives and entities are not allowed")
)

type burpMessage struct {
	Base64 string `xml:"base64,attr"`
	Text   string `xml:",chardata"`
}

type burpItem struct {
	URL            string      `xml:"url"`
	Host           string      `xml:"host"`
	Port           string      `xml:"port"`
	Protocol       string      `xml:"protocol"`
	Method         string      `xml:"method"`
	Path           string      `xml:"path"`
	Status         string      `xml:"status"`
	MimeType       string      `xml:"mimetype"`
	ResponseLength string      `xml:"responselength"`
	Time           string      `xml:"time"`
	Request        burpMessage `xml:"request"`
	Response       burpMessage `xml:"response"`
}

// ParseBurpXML parses Burp's "Save items" XML format. It is deliberately
// bounded and rejects all XML directives before decoding any messages. Go's XML
// decoder does not resolve external entities, and the explicit rejection keeps
// that safety invariant visible and testable.
func ParseBurpXML(raw []byte) ([]Exchange, error) {
	if len(raw) > MaxImportBytes {
		return nil, ErrImportTooLarge
	}
	lower := bytes.ToLower(raw)
	if bytes.Contains(lower, []byte("<!doctype")) || bytes.Contains(lower, []byte("<!entity")) {
		return nil, ErrUnsafeXML
	}

	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Strict = true
	out := make([]Exchange, 0)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("invalid Burp XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.Directive:
			return nil, ErrUnsafeXML
		case xml.StartElement:
			if t.Name.Local != "item" {
				continue
			}
			if len(out) >= MaxItems {
				return nil, fmt.Errorf("capture contains more than %d items", MaxItems)
			}
			var item burpItem
			if err := dec.DecodeElement(&item, &t); err != nil {
				return nil, fmt.Errorf("invalid Burp item %d: %w", len(out)+1, err)
			}
			ex, err := convertBurpItem(item, len(out)+1)
			if err != nil {
				return nil, fmt.Errorf("invalid Burp item %d: %w", len(out)+1, err)
			}
			out = append(out, ex)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("Burp XML contains no HTTP items")
	}
	return out, nil
}

func decodeBurpMessage(m burpMessage) ([]byte, error) {
	var b []byte
	var err error
	if strings.EqualFold(strings.TrimSpace(m.Base64), "true") {
		compact := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
				return -1
			}
			return r
		}, m.Text)
		b, err = base64.StdEncoding.DecodeString(compact)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 message: %w", err)
		}
	} else {
		b = []byte(m.Text)
	}
	if len(b) > MaxMessageBytes {
		return nil, fmt.Errorf("HTTP message exceeds %d bytes", MaxMessageBytes)
	}
	return b, nil
}

func convertBurpItem(item burpItem, sequence int) (Exchange, error) {
	reqRaw, err := decodeBurpMessage(item.Request)
	if err != nil {
		return Exchange{}, fmt.Errorf("request: %w", err)
	}
	respRaw, err := decodeBurpMessage(item.Response)
	if err != nil {
		return Exchange{}, fmt.Errorf("response: %w", err)
	}
	request, err := parseRawRequest(reqRaw, canonicalBurpURL(item))
	if err != nil {
		return Exchange{}, err
	}
	if request.Method == "" {
		request.Method = strings.ToUpper(strings.TrimSpace(item.Method))
	}
	response := Response{}
	if len(respRaw) > 0 {
		response, err = parseRawResponse(respRaw, request)
		if err != nil {
			return Exchange{}, err
		}
	}
	if response.Status == 0 {
		response.Status, _ = strconv.Atoi(strings.TrimSpace(item.Status))
	}
	if response.MimeType == "" {
		response.MimeType = strings.TrimSpace(item.MimeType)
	}
	return Exchange{Source: "burp-xml", Sequence: sequence, Request: request, Response: response}, nil
}

func canonicalBurpURL(item burpItem) string {
	if u, err := url.Parse(strings.TrimSpace(item.URL)); err == nil && u.Scheme != "" && u.Host != "" {
		return u.String()
	}
	scheme := strings.ToLower(strings.TrimSpace(item.Protocol))
	if scheme != "http" && scheme != "https" {
		scheme = "https"
	}
	host := strings.TrimSpace(item.Host)
	port := strings.TrimSpace(item.Port)
	if port != "" && !((scheme == "https" && port == "443") || (scheme == "http" && port == "80")) {
		host += ":" + port
	}
	path := strings.TrimSpace(item.Path)
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path
}
