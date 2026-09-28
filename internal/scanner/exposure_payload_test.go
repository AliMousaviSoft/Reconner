package scanner

import "testing"

// Exposure findings are discovery, not injection: the reproduction IS the exact
// URL that exposed the content, so store() must persist it as the Payload too —
// otherwise a reviewer has nothing to replay beyond the finding's own URL field
// (which the UI does not always surface next to "payload").
func TestExposureStorePersistsURLAsPayload(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	s := NewExposureScanner(db, nil, nil, nil, nil)
	s.store(tid, "exposed_config", "high", "https://example.test/.env", "", "Exposed .env file leaks secrets")

	var payload, url string
	if err := db.QueryRow(`SELECT url, payload FROM candidates WHERE target_id=? AND type='exposed_config'`, tid).
		Scan(&url, &payload); err != nil {
		t.Fatal(err)
	}
	if payload != url || payload == "" {
		t.Fatalf("expected payload to equal the exposing URL, got url=%q payload=%q", url, payload)
	}
}
