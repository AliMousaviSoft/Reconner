package scheduler

import (
	"context"
	"fmt"
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

// A real, distinct, low-signal tail asset (alive, but no admin panel, no
// interesting name, no params, no high-yield tech — score far below a real
// app-shaped host) must get only the light tier, not the full module group,
// even though it is nobody's duplicate — but ONLY once the target has enough
// distinct assets (lightTierMinAssetCount) for the tradeoff to be worth it.
// Seeds 10 hosts (1 admin + 9 boring) to cross that threshold.
func TestRunPerAssetPhaseGivesLowScoreTailAssetsOnlyTheLightTier(t *testing.T) {
	s := newTestScheduler(t)
	tid := uuid.NewString()
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain) VALUES (?,?)`, tid, "example.test"); err != nil {
		t.Fatal(err)
	}
	// admin.example.test: interesting name + admin panel → clearly above threshold.
	if _, err := s.db.Exec(`INSERT INTO subdomains (id,target_id,subdomain,is_alive,status_code,page_title) VALUES (?,?,?,1,200,'Admin Login')`,
		uuid.NewString(), tid, "admin.example.test"); err != nil {
		t.Fatal(err)
	}
	// 9 boring filler hosts (alive, no title, no other signal → below
	// threshold) so the target crosses lightTierMinAssetCount. Empty titles
	// keep them out of wildcard dedup, so each counts as its own distinct
	// Ordered asset — exactly the "real, distinct, low-signal" case this test
	// is about, not a duplicate.
	for i := 1; i <= 9; i++ {
		if _, err := s.db.Exec(`INSERT INTO subdomains (id,target_id,subdomain,is_alive,status_code,page_title) VALUES (?,?,?,1,200,'')`,
			uuid.NewString(), tid, fmt.Sprintf("cdn%d.example.test", i)); err != nil {
			t.Fatal(err)
		}
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

	has := func(call string) bool {
		for _, c := range calls {
			if c == call {
				return true
			}
		}
		return false
	}
	if !has("admin.example.test::" + ModuleSQLi) {
		t.Fatalf("expected the high-score admin asset to get the full pipeline (sqli), got calls: %v", calls)
	}
	if !has("admin.example.test::" + ModuleNuclei) {
		t.Fatalf("expected the high-score admin asset to also get nuclei, got calls: %v", calls)
	}
	if has("cdn7.example.test::" + ModuleSQLi) {
		t.Fatalf("expected the low-score tail asset to be downgraded off sqli (full tier), got calls: %v", calls)
	}
	if !has("cdn7.example.test::" + ModuleNuclei) {
		t.Fatalf("expected the low-score tail asset to still get the light tier (nuclei), got calls: %v", calls)
	}
}

// Below lightTierMinAssetCount, every distinct asset keeps the FULL module
// group regardless of score — a small target (a handful of subdomains) is
// already fast enough that trading accuracy for speed on its tail isn't
// worth it, and prioritized scanning is now the default for every scan size.
func TestRunPerAssetPhaseKeepsFullDepthOnSmallTargets(t *testing.T) {
	s := newTestScheduler(t)
	tid := uuid.NewString()
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain) VALUES (?,?)`, tid, "example.test"); err != nil {
		t.Fatal(err)
	}
	// Only 2 hosts total — far below lightTierMinAssetCount. cdn7 would be
	// below lightTierScoreThreshold on its own, but the cutoff must not apply.
	if _, err := s.db.Exec(`INSERT INTO subdomains (id,target_id,subdomain,is_alive,status_code,page_title) VALUES
		(?,?,?,1,200,'Admin Login'),
		(?,?,?,1,200,'')`,
		uuid.NewString(), tid, "admin.example.test",
		uuid.NewString(), tid, "cdn7.example.test"); err != nil {
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

	group := []string{ModuleNuclei, ModuleSQLi}
	s.runPerAssetPhase(context.Background(), taskID, tid, group, stubRun, func(string, string, string) {})

	full := 0
	for _, c := range calls {
		if strings.HasSuffix(c, "::"+ModuleSQLi) {
			full++
		}
	}
	if full != 2 {
		t.Fatalf("expected BOTH hosts to get the full pipeline (sqli) on a small target, got %d: %v", full, calls)
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

// Prioritized scanning is now the DEFAULT — a task created with no
// "prioritized"/"classic_order" token at all must still take the per-asset
// branch. Proven the same way as the explicit-token test: current_asset gets
// set (only runPerAssetPhase/updateAssetProgress ever writes it), which a
// task running the plain module-by-module path would never touch.
func TestExecuteTaskDefaultsToPrioritizedWithoutAnyToken(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets(id,domain) VALUES('default-prio-target','example.com')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO subdomains (id,target_id,subdomain,is_alive,status_code) VALUES (?,?,?,1,200)`,
		uuid.NewString(), "default-prio-target", "example.com"); err != nil {
		t.Fatal(err)
	}
	task, err := s.CreateTask("default-prio-target", []string{ModuleExposure}, 1)
	if err != nil {
		t.Fatal(err)
	}
	s.executeTask(context.Background(), task.ID)

	var currentAsset string
	if err := s.db.QueryRow(`SELECT COALESCE(current_asset,'') FROM tasks WHERE id=?`, task.ID).Scan(&currentAsset); err != nil {
		t.Fatal(err)
	}
	if currentAsset == "" {
		t.Fatalf("expected the default (no token) task to run through the per-asset branch and set current_asset, got empty")
	}
}

// "classic_order" opts back into the old module-by-module sweep even though
// prioritized is now the default — current_asset must stay unset because the
// per-asset branch (the only writer of that column) is never entered.
func TestExecuteTaskClassicOrderOptsOutOfPrioritized(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets(id,domain) VALUES('classic-target','example.com')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO subdomains (id,target_id,subdomain,is_alive,status_code) VALUES (?,?,?,1,200)`,
		uuid.NewString(), "classic-target", "example.com"); err != nil {
		t.Fatal(err)
	}
	task, err := s.CreateTask("classic-target", []string{ModuleExposure, "classic_order"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	s.executeTask(context.Background(), task.ID)

	var taskStatus, currentAsset string
	if err := s.db.QueryRow(`SELECT status, COALESCE(current_asset,'') FROM tasks WHERE id=?`, task.ID).Scan(&taskStatus, &currentAsset); err != nil {
		t.Fatal(err)
	}
	if taskStatus != "finished" {
		t.Fatalf("expected the classic-order task to finish, got status=%q", taskStatus)
	}
	if currentAsset != "" {
		t.Fatalf("expected classic_order to skip the per-asset branch entirely, but current_asset=%q was set", currentAsset)
	}
}

// A single-asset-scoped task (the "scan this asset" button) must NEVER enter
// the per-asset branch, regardless of the new prioritized-by-default setting
// — entering it would call ComputeAssetPriority for the WHOLE target and
// could run the module against every other asset too, silently widening a
// scan the operator deliberately narrowed to one host.
func TestExecuteTaskScopedTaskNeverEntersPrioritizedBranch(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets(id,domain) VALUES('scoped-target','example.com')`); err != nil {
		t.Fatal(err)
	}
	// Two live hosts on the target — if the per-asset branch ran, it would
	// have something to iterate over and current_asset would get set.
	if _, err := s.db.Exec(`INSERT INTO subdomains (id,target_id,subdomain,is_alive,status_code) VALUES
		(?,?,?,1,200),(?,?,?,1,200)`,
		uuid.NewString(), "scoped-target", "example.com",
		uuid.NewString(), "scoped-target", "other.example.com"); err != nil {
		t.Fatal(err)
	}
	task, err := s.CreateScopedTask("scoped-target", []string{ModuleExposure}, 1, "other.example.com")
	if err != nil {
		t.Fatal(err)
	}
	s.executeTask(context.Background(), task.ID)

	var taskStatus, currentAsset string
	if err := s.db.QueryRow(`SELECT status, COALESCE(current_asset,'') FROM tasks WHERE id=?`, task.ID).Scan(&taskStatus, &currentAsset); err != nil {
		t.Fatal(err)
	}
	if taskStatus != "finished" {
		t.Fatalf("expected the scoped task to finish, got status=%q", taskStatus)
	}
	if currentAsset != "" {
		t.Fatalf("expected a single-asset-scoped task to never enter the per-asset branch, but current_asset=%q was set", currentAsset)
	}
}
