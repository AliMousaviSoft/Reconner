package scanner

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/pkg/logger"
)

func TestXSSHeaderInsertionPoints(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "dast.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	tid := uuid.NewString()
	if _, err := db.Exec(`INSERT INTO targets (id, domain) VALUES (?, 'ex.test')`, tid); err != nil {
		t.Fatal(err)
	}
	// Two alive URLs on the SAME host + one on another host + one dead/out-of-range.
	for _, u := range []string{"https://a.ex.test/", "https://a.ex.test/page", "https://b.ex.test/"} {
		if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,source) VALUES (?,?,?,200,'probe')`,
			uuid.NewString(), tid, u); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,source) VALUES (?,?,?,500,'probe')`,
		uuid.NewString(), tid, "https://c.ex.test/"); err != nil {
		t.Fatal(err)
	}

	s := NewDASTScanner(db, &config.Config{}, logger.New("error"), nil)
	pts := s.xssHeaderInsertionPoints(context.Background(), tid)

	// One representative per host (a.ex.test, b.ex.test) × the reflective header set;
	// the 500 host is excluded, and the duplicate a.ex.test path collapses to one host.
	hosts := map[string]int{}
	for _, p := range pts {
		if p.Location != "header" || p.Method != "GET" {
			t.Fatalf("header point must be a GET header insertion: %+v", p)
		}
		hosts[hostOf(p.URL)]++
	}
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts (a,b), got %d: %v", len(hosts), hosts)
	}
	if hosts["a.ex.test"] != len(xssReflectiveHeaders) || hosts["b.ex.test"] != len(xssReflectiveHeaders) {
		t.Fatalf("each host should get one point per reflective header: %v", hosts)
	}
	names := map[string]bool{}
	for _, p := range pts {
		names[p.Param] = true
	}
	for _, want := range []string{"Referer", "X-Forwarded-Host", "User-Agent"} {
		if !names[want] {
			t.Errorf("reflective header %q not tested", want)
		}
	}
	// Host must NOT be tested (owned by host-header-injection; breaks routing).
	if names["Host"] {
		t.Error("Host header must not be an XSS insertion point")
	}
}
