package scanner

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
)

func TestSanitizeAuthDetailRedactsSecrets(t *testing.T) {
	cases := map[string]string{
		"Cookie: session=abc123deadbeef":         "[redacted]",
		"Authorization: Bearer eyJ0eHAzzz":       "[redacted]",
		"refreshed via token=9f8e7d":             "[redacted]",
		"X-CSRF-Token: 55aa":                     "[redacted]",
		"session expired, detected at preflight": "", // benign word "session" alone (no value) stays
	}
	for in, mustContainRedactedOrNot := range cases {
		got := sanitizeAuthDetail(in)
		if strings.Contains(strings.ToLower(got), "bearer ey") ||
			strings.Contains(got, "abc123deadbeef") || strings.Contains(got, "9f8e7d") || strings.Contains(got, "55aa") {
			t.Errorf("sanitizeAuthDetail(%q) leaked a secret: %q", in, got)
		}
		if mustContainRedactedOrNot == "[redacted]" && !strings.Contains(got, "[redacted]") {
			t.Errorf("sanitizeAuthDetail(%q) = %q, expected a [redacted] marker", in, got)
		}
	}
}

func TestRecordAuthEventPersistsSanitized(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "ae.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	tid := uuid.NewString()
	if _, err := db.Exec(`INSERT INTO targets (id, domain) VALUES (?, 'x.test')`, tid); err != nil {
		t.Fatal(err)
	}

	// A caller mistakenly passes a raw cookie in the detail — it must be redacted
	// at the write point, never stored.
	RecordAuthEvent(context.Background(), db, tid, "id-1", "admin", AuthEventExpired, SessExpired,
		"lost session Cookie: sid=supersecretvalue after 302 to /login")

	var event, state, detail string
	if err := db.QueryRow(`SELECT event, state, detail FROM auth_events WHERE target_id=?`, tid).
		Scan(&event, &state, &detail); err != nil {
		t.Fatalf("auth event not stored: %v", err)
	}
	if event != AuthEventExpired || state != SessExpired {
		t.Errorf("event/state = %q/%q", event, state)
	}
	if strings.Contains(detail, "supersecretvalue") {
		t.Fatalf("stored detail leaked a secret: %q", detail)
	}
	if !strings.Contains(detail, "[redacted]") {
		t.Errorf("expected redaction marker in stored detail: %q", detail)
	}
}

func TestSessionStateFromValidation(t *testing.T) {
	cases := map[string]string{"authenticated": SessHealthy, "expired": SessExpired, "unknown": SessUnknown, "": SessUnknown}
	for in, want := range cases {
		if got := SessStateForVerdict(in); got != want {
			t.Errorf("SessStateForVerdict(%q) = %q, want %q", in, got, want)
		}
	}
}
