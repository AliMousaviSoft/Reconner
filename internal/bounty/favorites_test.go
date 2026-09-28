package bounty

import (
	"context"
	"testing"
)

func testProgramForFavorites(t *testing.T, svc *Service) *Program {
	t.Helper()
	p := &Program{Provider: "hackerone", ExternalID: "fav-team", Handle: "fav-acme", Name: "Fav Acme", Status: "live"}
	storeTestProgram(t, svc, p)
	return p
}

func TestSetFavoriteDefaultsToNotifyAndValidatesPolicy(t *testing.T) {
	svc, _ := testCatalog(t)
	p := testProgramForFavorites(t, svc)
	ctx := context.Background()

	if err := svc.SetFavorite(ctx, 7, p.ID, "", 0); err != nil {
		t.Fatal(err)
	}
	favorites, err := svc.ListFavorites(ctx, 7)
	if err != nil {
		t.Fatal(err)
	}
	f, ok := favorites[p.ID]
	if !ok || f.AutoScanPolicy != "notify" || f.WatchIntervalHours != 12 {
		t.Fatalf("expected default notify policy + 12h interval, got %+v ok=%v", f, ok)
	}

	if err := svc.SetFavorite(ctx, 7, p.ID, "aggressive-everything", 0); err == nil {
		t.Fatal("expected an invalid auto_scan_policy to be rejected")
	}

	if err := svc.SetFavorite(ctx, 7, "does-not-exist", "notify", 0); err == nil {
		t.Fatal("expected favoriting a nonexistent program to fail")
	}
}

func TestSetFavoriteUpdatesExistingRowInPlace(t *testing.T) {
	svc, _ := testCatalog(t)
	p := testProgramForFavorites(t, svc)
	ctx := context.Background()

	if err := svc.SetFavorite(ctx, 1, p.ID, "notify", 6); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetFavorite(ctx, 1, p.ID, "full_scan", 24); err != nil {
		t.Fatal(err)
	}
	favorites, err := svc.ListFavorites(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if f := favorites[p.ID]; f.AutoScanPolicy != "full_scan" || f.WatchIntervalHours != 24 {
		t.Fatalf("expected the second SetFavorite to update in place, got %+v", f)
	}
	all, err := svc.FavoritesForProgram(ctx, p.ID)
	if err != nil || len(all) != 1 {
		t.Fatalf("expected exactly one favorite row (updated, not duplicated), got %d err=%v", len(all), err)
	}
}

func TestRemoveFavoriteDeletesOnlyThatUsersRow(t *testing.T) {
	svc, _ := testCatalog(t)
	p := testProgramForFavorites(t, svc)
	ctx := context.Background()

	if err := svc.SetFavorite(ctx, 1, p.ID, "notify", 0); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetFavorite(ctx, 2, p.ID, "light_recon", 0); err != nil {
		t.Fatal(err)
	}
	if err := svc.RemoveFavorite(ctx, 1, p.ID); err != nil {
		t.Fatal(err)
	}
	all, err := svc.FavoritesForProgram(ctx, p.ID)
	if err != nil || len(all) != 1 || all[0].UserID != 2 {
		t.Fatalf("expected only user 2's favorite to remain, got %+v err=%v", all, err)
	}
}

// The notify hook must fire exactly once per NEWLY recorded scope event
// (never for a deduplicated repeat), carrying the real event id so a caller
// can resolve (approve/reject) it.
func TestScopeEventNotifyFiresOnceForNewEventNotOnDuplicate(t *testing.T) {
	svc, _ := testCatalog(t)
	p := testProgramForFavorites(t, svc)
	ctx := context.Background()

	var calls int
	var lastEventID, lastEventType string
	svc.SetScopeEventNotify(func(_ context.Context, targetID, programID, eventID, eventType, identifier string) {
		calls++
		lastEventID, lastEventType = eventID, eventType
		if targetID != "t1" || programID != p.ID || identifier != "new.example.test" {
			t.Errorf("unexpected notify args: target=%s program=%s identifier=%s", targetID, programID, identifier)
		}
	})

	if _, err := svc.db.Exec(`INSERT INTO targets(id,domain) VALUES('t1','example.test')`); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.db.Exec(`INSERT INTO bounty_program_assets(id,program_id,external_id,identifier) VALUES('asset-1',?,'ext-1','new.example.test')`, p.ID); err != nil {
		t.Fatal(err)
	}
	svc.createScopeEvent(ctx, "t1", p.ID, "asset-1", "added", "new.example.test", "{}", "{}")
	if calls != 1 || lastEventType != "added" || lastEventID == "" {
		t.Fatalf("expected exactly one notify call with a real event id, got calls=%d id=%q type=%q", calls, lastEventID, lastEventType)
	}

	// A duplicate pending event for the same (target, asset, type) must not
	// re-notify -- createScopeEvent's own dedup guard should short-circuit
	// before the notify hook ever runs again.
	svc.createScopeEvent(ctx, "t1", p.ID, "asset-1", "added", "new.example.test", "{}", "{}")
	if calls != 1 {
		t.Fatalf("expected the dedup guard to suppress a second notify, got calls=%d", calls)
	}
}
