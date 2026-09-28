package scheduler

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// The whole point of prioritized scanning is ASSET-outer/module-inner: the
// complete module group runs against the highest-priority asset before the
// next asset starts, not one module sweeping every asset before the next
// module begins. This proves the call order directly against runPerAssetPhase.
func TestRunPerAssetPhaseIsAssetOuterModuleInner(t *testing.T) {
	s := newTestScheduler(t)
	tid := uuid.NewString()
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain) VALUES (?,?)`, tid, "example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO subdomains (id,target_id,subdomain,is_alive,status_code,page_title) VALUES
		(?,?,?,1,200,'Example Corp — Home'),
		(?,?,?,1,200,'Admin Login')`,
		uuid.NewString(), tid, "example.test",
		uuid.NewString(), tid, "admin.example.test"); err != nil {
		t.Fatal(err)
	}
	taskID := uuid.NewString()
	if _, err := s.db.Exec(`INSERT INTO tasks (id,target_id,type,status,modules,total) VALUES (?,?,?,?,?,?)`,
		taskID, tid, "full_scan", "running", "[]", 1); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var calls []string
	stubRun := func(ctx context.Context, module string) error {
		var host string
		_ = s.db.QueryRow(`SELECT current_asset FROM tasks WHERE id=?`, taskID).Scan(&host)
		mu.Lock()
		calls = append(calls, host+"::"+module)
		mu.Unlock()
		return nil
	}

	results := s.runPerAssetPhase(context.Background(), taskID, tid, []string{"m1", "m2"}, stubRun, func(string, string, string) {})
	if len(results) != 2 {
		t.Fatalf("expected 2 aggregated results, got %+v", results)
	}
	for _, r := range results {
		if r.err != nil {
			t.Fatalf("unexpected error for module %q: %v", r.module, r.err)
		}
	}

	// Main domain must be tested first (both modules) before admin.example.test
	// even starts, regardless of admin's higher raw priority score.
	want := []string{
		"example.test::m1", "example.test::m2",
		"admin.example.test::m1", "admin.example.test::m2",
	}
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Fatalf("expected asset-outer/module-inner order\n  got:  %v\n  want: %v", calls, want)
	}

	var assetsTotal, assetsDone int
	var currentAsset string
	if err := s.db.QueryRow(`SELECT current_asset,assets_done,assets_total FROM tasks WHERE id=?`, taskID).
		Scan(&currentAsset, &assetsDone, &assetsTotal); err != nil {
		t.Fatal(err)
	}
	if assetsTotal != 2 || assetsDone != 2 || currentAsset != "admin.example.test" {
		t.Fatalf("expected progress to reflect the last asset processed, got asset=%q done=%d total=%d", currentAsset, assetsDone, assetsTotal)
	}
}

// Duplicate/wildcard-catch-all hosts get only the light tier, not the full
// requested module group — the whole point of the tail-tier optimization.
func TestRunPerAssetPhaseGivesDuplicatesOnlyTheLightTier(t *testing.T) {
	s := newTestScheduler(t)
	tid := uuid.NewString()
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain) VALUES (?,?)`, tid, "example.test"); err != nil {
		t.Fatal(err)
	}
	// Two hosts with identical status/server/tech/title → wildcard/duplicate pair.
	if _, err := s.db.Exec(`INSERT INTO subdomains (id,target_id,subdomain,is_alive,status_code,page_title,server) VALUES
		(?,?,?,1,200,'Parked','nginx'),
		(?,?,?,1,200,'Parked','nginx')`,
		uuid.NewString(), tid, "a1.example.test",
		uuid.NewString(), tid, "a2.example.test"); err != nil {
		t.Fatal(err)
	}
	taskID := uuid.NewString()
	if _, err := s.db.Exec(`INSERT INTO tasks (id,target_id,type,status,modules,total) VALUES (?,?,?,?,?,?)`,
		taskID, tid, "full_scan", "running", "[]", 1); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var calls []string
	stubRun := func(ctx context.Context, module string) error {
		var host string
		_ = s.db.QueryRow(`SELECT current_asset FROM tasks WHERE id=?`, taskID).Scan(&host)
		mu.Lock()
		calls = append(calls, host+"::"+module)
		mu.Unlock()
		return nil
	}

	group := []string{ModuleNuclei, ModuleSQLi} // nuclei is in the light tier, sqli is not
	s.runPerAssetPhase(context.Background(), taskID, tid, group, stubRun, func(string, string, string) {})

	full, light := 0, 0
	for _, c := range calls {
		switch {
		case strings.HasSuffix(c, "::"+ModuleSQLi):
			full++
		case strings.HasSuffix(c, "::"+ModuleNuclei):
			light++
		}
	}
	if full != 1 {
		t.Fatalf("expected sqli (full-tier only) to run exactly once (the representative), got %d: %v", full, calls)
	}
	if light != 2 {
		t.Fatalf("expected nuclei (light tier) to run on the representative AND the duplicate, got %d: %v", light, calls)
	}
}

// End-to-end wiring: a task created with the "prioritized" token must reach
// the per-asset branch inside executeTask (not silently fall back to the
// ordinary path) and still finish cleanly through the real module dispatch —
// proven with zero scored assets, which forces the branch's own no-data
// fallback (call the real module target-wide) rather than mocking network I/O.
func TestExecuteTaskHonorsPrioritizedFlagEndToEnd(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets(id,domain) VALUES('prio-target','example.com')`); err != nil {
		t.Fatal(err)
	}
	task, err := s.CreateTask("prio-target", []string{ModuleExposure, "prioritized"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	s.executeTask(context.Background(), task.ID)

	var taskStatus string
	if err := s.db.QueryRow(`SELECT status FROM tasks WHERE id=?`, task.ID).Scan(&taskStatus); err != nil {
		t.Fatal(err)
	}
	if taskStatus != "finished" {
		t.Fatalf("expected the prioritized task to finish, got status=%q", taskStatus)
	}
	var phaseStatus string
	if err := s.db.QueryRow(`SELECT status FROM task_phases WHERE task_id=? AND module=?`, task.ID, ModuleExposure).Scan(&phaseStatus); err != nil {
		t.Fatal(err)
	}
	if phaseStatus != "completed" {
		t.Fatalf("expected the exposure phase to complete via the prioritized branch, got status=%q", phaseStatus)
	}
}
