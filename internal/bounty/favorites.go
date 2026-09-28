package bounty

import (
	"context"
	"fmt"
)

// Favorite is a per-user "watch this program" flag, independent of whether
// the user has already imported the program into a project.
type Favorite struct {
	ProgramID          string `json:"program_id"`
	AutoScanPolicy     string `json:"auto_scan_policy"`
	WatchIntervalHours int    `json:"watch_interval_hours"`
	CreatedAt          string `json:"created_at"`
}

// ProgramFavorite is one user's watch on a program, for FavoritesForProgram
// (the scope-event notify hook's "who is watching this program" lookup).
type ProgramFavorite struct {
	UserID int64 `json:"user_id"`
	Favorite
}

var validAutoScanPolicies = map[string]bool{"notify": true, "light_recon": true, "full_scan": true}

// SetFavorite creates or updates a user's watch on a program. An empty
// policy defaults to "notify" -- the safest option (no automated scan
// without the operator explicitly opting in to more).
func (s *Service) SetFavorite(ctx context.Context, userID int64, programID, autoScanPolicy string, watchIntervalHours int) error {
	if autoScanPolicy == "" {
		autoScanPolicy = "notify"
	}
	if !validAutoScanPolicies[autoScanPolicy] {
		return fmt.Errorf("auto_scan_policy must be notify, light_recon, or full_scan")
	}
	if watchIntervalHours <= 0 {
		watchIntervalHours = 12
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM bounty_programs WHERE id=?`, programID).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return fmt.Errorf("program not found")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO bounty_program_favorites(user_id,program_id,auto_scan_policy,watch_interval_hours)
		VALUES(?,?,?,?)
		ON CONFLICT(user_id,program_id) DO UPDATE SET auto_scan_policy=excluded.auto_scan_policy,watch_interval_hours=excluded.watch_interval_hours`,
		userID, programID, autoScanPolicy, watchIntervalHours)
	return err
}

func (s *Service) RemoveFavorite(ctx context.Context, userID int64, programID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM bounty_program_favorites WHERE user_id=? AND program_id=?`, userID, programID)
	return err
}

// ListFavorites returns every program a user has favorited, keyed by
// program_id for O(1) lookup when rendering the catalog list.
func (s *Service) ListFavorites(ctx context.Context, userID int64) (map[string]Favorite, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT program_id,auto_scan_policy,watch_interval_hours,created_at FROM bounty_program_favorites WHERE user_id=?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Favorite{}
	for rows.Next() {
		var f Favorite
		if err := rows.Scan(&f.ProgramID, &f.AutoScanPolicy, &f.WatchIntervalHours, &f.CreatedAt); err != nil {
			return nil, err
		}
		out[f.ProgramID] = f
	}
	return out, rows.Err()
}

// FavoritesForProgram returns every user watching a program, for the
// scope-event notify hook to fan out to (notify all watchers, then
// auto-scan per each watcher's own policy).
func (s *Service) FavoritesForProgram(ctx context.Context, programID string) ([]ProgramFavorite, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT user_id,auto_scan_policy,watch_interval_hours,created_at FROM bounty_program_favorites WHERE program_id=?`, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProgramFavorite
	for rows.Next() {
		var f ProgramFavorite
		f.ProgramID = programID
		if err := rows.Scan(&f.UserID, &f.AutoScanPolicy, &f.WatchIntervalHours, &f.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
