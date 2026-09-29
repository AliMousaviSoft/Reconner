package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

// TestNoSQLiRegexBooleanStoresAccuratePayload proves a NoSQLi finding detected
// via the $regex boolean-differential technique records a Payload field that
// actually names the $regex operator used, not a hardcoded "[$ne]" that names a
// completely different MongoDB operator the scanner never sent. store() used to
// hardcode Payload: ip.Param+"[$ne]" for every NoSQLi technique — correct only
// for the literal $ne/$eq path by coincidence, and actively misleading for the
// error-based and $regex-boolean paths, which is exactly the kind of PoC field
// this session has fixed for other detectors before (sqli.go, xss_context.go).
func TestNoSQLiRegexBooleanStoresAccuratePayload(t *testing.T) {
	withLoopbackAllowed(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("q[$regex]") {
		case ".*":
			_, _ = w.Write([]byte(strings.Repeat("item ", 200))) // matches everything
		case "^rcnZZnomatch$":
			_, _ = w.Write([]byte("[]")) // matches nothing
		default:
			// Any other request (plain baseline, error probe, $ne/$eq — which this
			// app does not interpret at all) gets the same generic response, so only
			// the $regex operator produces a material, reproducible difference.
			_, _ = w.Write([]byte(strings.Repeat("baseline ", 50)))
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db, targetID := newV3ScannerDB(t)
	seedV3Parameter(t, db, targetID, srv.URL+"/search", "q", "widgets", "GET", "", "query")

	cfg := &config.Config{}
	if err := NewNoSQLiScanner(db, tools.NewExecutor(cfg, logger.New("error")), cfg, logger.New("error"), nil).
		Run(context.Background(), targetID, func(_, _, _ string) {}); err != nil {
		t.Fatal(err)
	}

	var payload string
	if err := db.QueryRow(`SELECT payload FROM candidates WHERE target_id=? AND type='nosql_injection'`, targetID).Scan(&payload); err != nil {
		t.Fatalf("expected a stored nosql_injection candidate: %v", err)
	}
	if !strings.Contains(payload, "$regex") {
		t.Errorf("payload must name the $regex operator actually used, got %q", payload)
	}
	if strings.Contains(payload, "$ne") {
		t.Errorf("payload must NOT claim the $ne operator was used when $regex is what triggered detection, got %q", payload)
	}
}
