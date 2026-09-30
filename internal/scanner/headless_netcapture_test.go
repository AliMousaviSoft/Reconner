package scanner

import (
	"context"
	"sort"
	"strings"
	"testing"
)

func TestJSONBodyLeaves(t *testing.T) {
	body := `{"user":{"id":5,"name":"a","active":true},"tags":["x","y"],"score":1.5,"empty":{},"list":[]}`
	leaves := jsonBodyLeaves(body)
	got := map[string]string{}
	for _, l := range leaves {
		got[l.path] = l.typ
	}
	want := map[string]string{
		"user.id":     "integer",
		"user.name":   "string",
		"user.active": "boolean",
		"tags":        "string", // array recurses into its first element under the same path
		"score":       "number",
		"empty":       "object",
		"list":        "array",
	}
	if len(got) != len(want) {
		t.Fatalf("leaf count = %d, want %d (%v)", len(got), len(want), got)
	}
	for path, typ := range want {
		if got[path] != typ {
			t.Errorf("leaf %q type = %q, want %q", path, got[path], typ)
		}
	}
}

func TestJSONBodyLeavesRejectsDottedKeys(t *testing.T) {
	// A key containing a dot would corrupt the dotted-path convention the injectors
	// split on, so it must be skipped rather than emitted.
	leaves := jsonBodyLeaves(`{"a.b":1,"c":2}`)
	for _, l := range leaves {
		if strings.Contains(l.path, "a.b") {
			t.Fatalf("dotted key leaked into path set: %q", l.path)
		}
	}
	if len(leaves) != 1 || leaves[0].path != "c" {
		t.Fatalf("expected only leaf c, got %+v", leaves)
	}
}

func TestJSONBodyLeavesNonJSON(t *testing.T) {
	if l := jsonBodyLeaves("a=1&b=2"); l != nil {
		t.Fatalf("form body should not parse as JSON leaves, got %+v", l)
	}
	if l := jsonBodyLeaves(""); l != nil {
		t.Fatalf("empty body should yield no leaves, got %+v", l)
	}
}

func TestInsertionPointsFromRequestQuery(t *testing.T) {
	pts := insertionPointsFromRequest(capturedNetReq{
		method: "GET",
		url:    "https://api.example.com/v1/search?q=hello&page=2",
	})
	byName := map[string]paramEntry{}
	for _, p := range pts {
		byName[p.Param] = p
	}
	if len(byName) != 2 {
		t.Fatalf("expected 2 query insertion points, got %d (%+v)", len(byName), pts)
	}
	if p := byName["q"]; p.Location != "query" || p.Method != "GET" || p.Value != "hello" || p.Source != "headless-xhr" {
		t.Errorf("q insertion point wrong: %+v", p)
	}
}

func TestInsertionPointsFromRequestJSONBody(t *testing.T) {
	pts := insertionPointsFromRequest(capturedNetReq{
		method:      "POST",
		url:         "https://api.example.com/v1/users?trace=1",
		contentType: "application/json; charset=utf-8",
		postData:    `{"name":"bob","profile":{"age":30}}`,
	})
	var query, jsonPts []paramEntry
	for _, p := range pts {
		switch {
		case p.Location == "query":
			query = append(query, p)
		case strings.HasPrefix(p.Location, "json:"):
			jsonPts = append(jsonPts, p)
		default:
			t.Errorf("unexpected location %q in %+v", p.Location, p)
		}
	}
	if len(query) != 1 || query[0].Param != "trace" {
		t.Errorf("expected the query param trace to survive alongside body, got %+v", query)
	}
	want := map[string]string{"name": "json:string", "profile.age": "json:integer"}
	got := map[string]string{}
	for _, p := range jsonPts {
		got[p.Param] = p.Location
		if p.ContentType != "application/json" {
			t.Errorf("json insertion point %q content-type = %q, want application/json", p.Param, p.ContentType)
		}
		if p.URL != "https://api.example.com/v1/users" {
			t.Errorf("json insertion point %q URL should have query stripped, got %q", p.Param, p.URL)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("json insertion points = %+v, want %+v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("json leaf %q location = %q, want %q", k, got[k], v)
		}
	}
}

func TestInsertionPointsFromRequestFormBody(t *testing.T) {
	pts := insertionPointsFromRequest(capturedNetReq{
		method:      "POST",
		url:         "https://example.com/login",
		contentType: "application/x-www-form-urlencoded",
		postData:    "username=admin&password=secret",
	})
	names := map[string]paramEntry{}
	for _, p := range pts {
		names[p.Param] = p
	}
	if len(names) != 2 {
		t.Fatalf("expected 2 form insertion points, got %d (%+v)", len(names), pts)
	}
	if p := names["username"]; p.Location != "body" || p.Method != "POST" {
		t.Errorf("username form point wrong: %+v", p)
	}
}

func TestInsertionPointsFromRequestNoParams(t *testing.T) {
	// A bare endpoint hit with no query and no body is not an insertion point.
	if pts := insertionPointsFromRequest(capturedNetReq{method: "GET", url: "https://example.com/health"}); pts != nil {
		t.Fatalf("bare endpoint should yield no insertion points, got %+v", pts)
	}
}

func TestNetCaptureDedupAndCap(t *testing.T) {
	nc := newNetCapture(3)
	// Same endpoint, different query VALUES → one insertion point.
	nc.add(capturedNetReq{method: "GET", url: "https://x.test/a?id=1"})
	nc.add(capturedNetReq{method: "GET", url: "https://x.test/a?id=2"})
	if got := len(nc.snapshot()); got != 1 {
		t.Fatalf("value-variants should collapse to 1, got %d", got)
	}
	// Same endpoint, POST with different body VALUES but same shape → still one.
	nc.add(capturedNetReq{method: "POST", url: "https://x.test/b", postData: `{"a":1}`})
	nc.add(capturedNetReq{method: "POST", url: "https://x.test/b", postData: `{"a":9}`})
	if got := len(nc.snapshot()); got != 2 {
		t.Fatalf("same-shape bodies should collapse, expected 2 total, got %d", got)
	}
	// Distinct endpoints fill toward the cap, then the cap holds.
	nc.add(capturedNetReq{method: "GET", url: "https://x.test/c"})
	nc.add(capturedNetReq{method: "GET", url: "https://x.test/d"})
	if got := len(nc.snapshot()); got != 3 {
		t.Fatalf("cap of 3 must hold, got %d", got)
	}
}

func TestCollapseURLValues(t *testing.T) {
	a := collapseURLValues("https://H.test/p?b=2&a=1")
	b := collapseURLValues("https://h.test/p?a=9&b=8")
	if a != b {
		t.Fatalf("value/order/case should collapse: %q vs %q", a, b)
	}
	if c := collapseURLValues("https://h.test/other?a=1"); c == a {
		t.Fatalf("different path must not collapse: %q", c)
	}
}

func TestBodyShapeKey(t *testing.T) {
	j1 := bodyShapeKey(`{"b":1,"a":2}`)
	j2 := bodyShapeKey(`{"a":9,"b":8}`)
	if j1 != j2 || !strings.HasPrefix(j1, "json:") {
		t.Fatalf("json shape should be value-independent and prefixed: %q vs %q", j1, j2)
	}
	f1 := bodyShapeKey("y=1&x=2")
	f2 := bodyShapeKey("x=9&y=8")
	if f1 != f2 || !strings.HasPrefix(f1, "form:") {
		t.Fatalf("form shape should be value-independent and prefixed: %q vs %q", f1, f2)
	}
	if bodyShapeKey("") != "" {
		t.Fatalf("empty body should have empty shape key")
	}
}

func TestHeadlessBudgetScalesWithSpeed(t *testing.T) {
	fastP, fastD, fastS := headlessBudget(WithWebSpeed(context.Background(), SpeedFast))
	normP, normD, normS := headlessBudget(context.Background())
	slowP, slowD, slowS := headlessBudget(WithWebSpeed(context.Background(), SpeedSlow))
	if !(fastP < normP && normP < slowP) {
		t.Errorf("page budget should grow fast<normal<slow: %d %d %d", fastP, normP, slowP)
	}
	if !(fastD <= normD && normD < slowD) {
		t.Errorf("depth budget should not shrink with slower speed: %d %d %d", fastD, normD, slowD)
	}
	if !(fastS < normS && normS < slowS) {
		t.Errorf("seed cap should grow fast<normal<slow: %d %d %d", fastS, normS, slowS)
	}
}

func TestJSONLeafPathsAreSortableStable(t *testing.T) {
	// Guard the invariant bodyShapeKey relies on: leaf paths are plain sortable strings.
	leaves := jsonBodyLeaves(`{"z":1,"a":2,"m":{"n":3}}`)
	var paths []string
	for _, l := range leaves {
		paths = append(paths, l.path)
	}
	sort.Strings(paths)
	if strings.Join(paths, ",") != "a,m.n,z" {
		t.Fatalf("unexpected sorted leaf paths: %v", paths)
	}
}
