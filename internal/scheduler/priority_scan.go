package scheduler

import (
	"context"
	"fmt"
	"time"

	"github.com/recon-platform/internal/scanner"
)

// perAssetModuleSet is every module whose Run() is safe and meaningful to scope
// to ONE host at a time (via scanner.WithHostScope) instead of the whole
// target. These are the request-heavy, per-URL injection/testing modules that
// dominate a deep scan's wall-clock time — exactly the ones worth reordering so
// the highest-value asset gets them first on a 1000+-subdomain target.
//
// Deliberately EXCLUDED, and left to run target-wide exactly as before:
//   - capability/recon modules (subdomain_enum, http_probe, js_analysis,
//     js_endpoints, param_discovery, headless_crawl, timemachine,
//     param_reflection, paramfuzz, verify) — they populate the shared state
//     every detector reads, so they must run ONCE, before per-asset scoring
//     even has data to work with.
//   - cross-asset correlation modules (jwt, ato, api_data_exposure, monitor,
//     takeover, intel, passive, origin_ip, shodan, portscan) — these
//     deliberately read findings/state across the WHOLE target to build
//     chains or diffs; scoping them to one host would just break them.
var perAssetModuleSet = map[string]bool{
	ModuleXSS:  true,
	ModuleSQLi: true, ModuleSSRF: true, ModuleLFI: true, ModuleSSTI: true, ModuleCSTI: true,
	ModuleCmdi: true, ModuleXXE: true, ModuleFileUpload: true, ModuleNoSQLi: true,
	ModuleIDOR: true, ModuleRace: true, ModuleCSRF: true, ModuleCORS: true,
	ModuleCachePoison: true, ModuleSmuggling: true, ModuleOpenRedirect: true,
	ModuleAuthz: true, ModuleDirDiscovery: true, ModuleBackupDiscovery: true,
	ModuleExposure: true, ModuleNuclei: true, ModuleVulnScan: true, ModuleOAST: true,
	ModuleBLH: true,
}

// lightTierModuleSet runs on duplicate/wildcard-catch-all hosts instead of the
// full per-asset group: cheap, broad, high-signal checks only. A byte-identical
// duplicate of an already fully-tested app gains little from a second full
// injection pass, but nuclei/exposure/CORS checks are near-free and occasionally
// catch a host-specific misconfiguration a content-identical app doesn't share.
var lightTierModuleSet = map[string]bool{
	ModuleNuclei: true, ModuleExposure: true, ModuleCORS: true,
}

// lightTierScoreThreshold marks the tail of the priority order — a live host
// with no admin panel, no interesting name pattern, no discovered parameter
// surface, no high-yield technology and nothing beyond "it responded" scores
// in single digits here (a dead host scores far below zero). Reordering by
// itself does not shrink a deep scan's wall-clock cost on a 1000-subdomain
// target; without a depth cutoff the tail still silently eats the full
// per-asset module group for near-zero expected yield. Below this score, an
// asset gets lightTierModuleSet instead — same treatment as a duplicate/
// wildcard-catch-all host — UNLESS the requested module group has no
// light-tier overlap, in which case it keeps the full group rather than ever
// running zero modules on a real, distinct, live asset.
const lightTierScoreThreshold = 15

func isPerAssetModule(module string) bool { return perAssetModuleSet[module] }

// collectPerAssetModules gathers every not-yet-handled per-asset module from
// position start onward (not required to be contiguous, though canonical
// ordering makes them so in practice) and marks them handled.
func collectPerAssetModules(modules []string, start int, handled map[int]bool) []string {
	var group []string
	for j := start; j < len(modules); j++ {
		if handled[j] || !isPerAssetModule(modules[j]) {
			continue
		}
		group = append(group, modules[j])
		handled[j] = true
	}
	return group
}

// runPerAssetPhase is the heart of prioritized scanning: ASSET is the outer
// loop, MODULE is the inner loop — the complete per-asset-module group runs
// against the highest-priority asset before moving to the next one, instead of
// running one module against every asset before moving to the next module.
// Duplicates/wildcard-catch-all hosts get only lightTierModuleSet.
//
// Returns one phaseRunResult per requested module, aggregated across every
// asset it ran on (first error wins), so the caller can feed them straight into
// the SAME finishTaskPhase/completedModules bookkeeping the existing parallel-
// group and single-module paths already use — this function changes nothing
// about how a result is recorded, only how many times and against what scope
// each module actually runs.
func (s *Scheduler) runPerAssetPhase(ctx context.Context, taskID, targetID string, group []string, runPlannedModule func(context.Context, string) error, logFn scanner.LogFunc) []phaseRunResult {
	results := make(map[string]*phaseRunResult, len(group))
	for _, m := range group {
		results[m] = &phaseRunResult{module: m}
	}
	if ctx.Err() != nil {
		return finalizePerAssetResults(results, group)
	}

	plan, err := scanner.ComputeAssetPriority(ctx, s.db, targetID)
	if err != nil {
		logFn("warn", "scheduler", fmt.Sprintf("Asset priority scoring failed (%v) — falling back to target-wide execution for %v.", err, group))
		started := time.Now()
		for _, m := range group {
			results[m].err = runPlannedModule(ctx, m)
			results[m].duration = time.Since(started)
		}
		return finalizePerAssetResults(results, group)
	}
	if len(plan.Ordered) == 0 {
		// No scored hosts yet (e.g. recon found nothing alive) — nothing to scope
		// to, so fall back to the target-wide call exactly as an unprioritized
		// scan would, rather than silently skipping every per-asset module.
		started := time.Now()
		for _, m := range group {
			results[m].err = runPlannedModule(ctx, m)
			results[m].duration = time.Since(started)
		}
		return finalizePerAssetResults(results, group)
	}

	var light []string
	for _, m := range group {
		if lightTierModuleSet[m] {
			light = append(light, m)
		}
	}

	type assetWork struct {
		host    string
		score   int
		modules []string
	}
	var work []assetWork
	for _, a := range plan.Ordered {
		mods := group
		if !a.IsMainDomain && a.Score < lightTierScoreThreshold && len(light) > 0 {
			mods = light
		}
		work = append(work, assetWork{host: a.Host, score: a.Score, modules: mods})
	}
	for _, d := range plan.Duplicates {
		if len(light) > 0 {
			work = append(work, assetWork{host: d.Host, score: d.Score, modules: light})
		}
	}

	fullCount := 0
	for _, aw := range work {
		if len(aw.modules) == len(group) {
			fullCount++
		}
	}
	total := len(work)
	logFn("info", "scheduler", fmt.Sprintf(
		"Prioritized scan: %d asset(s) scored (%d full pipeline, %d on the light tier — tail/duplicate/catch-all hosts) — running %v per asset, highest-value first.",
		total, fullCount, total-fullCount, group))

	started := time.Now()
	for i, aw := range work {
		if ctx.Err() != nil {
			break
		}
		s.waitIfPaused(ctx, taskID, logFn)
		if ctx.Err() != nil {
			break
		}
		s.updateAssetProgress(taskID, aw.host, i+1, total)
		assetCtx := scanner.WithHostScope(ctx, []string{aw.host})
		for _, m := range aw.modules {
			if ctx.Err() != nil {
				break
			}
			logFn("info", m, fmt.Sprintf("[asset %d/%d score=%d] %s", i+1, total, aw.score, aw.host))
			if err := runPlannedModule(assetCtx, m); err != nil && results[m].err == nil {
				results[m].err = err
			}
		}
	}
	for _, m := range group {
		results[m].duration = time.Since(started)
	}
	return finalizePerAssetResults(results, group)
}

func finalizePerAssetResults(results map[string]*phaseRunResult, group []string) []phaseRunResult {
	out := make([]phaseRunResult, 0, len(group))
	for _, m := range group {
		out = append(out, *results[m])
	}
	return out
}

// updateAssetProgress persists the current-asset pointer for the target page
// (survives a reload without a live websocket) and broadcasts it for anyone
// watching live.
func (s *Scheduler) updateAssetProgress(taskID, host string, done, total int) {
	_, _ = s.db.Exec(`UPDATE tasks SET current_asset=?, assets_done=?, assets_total=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		host, done, total, taskID)
	var targetID string
	_ = s.db.QueryRow(`SELECT target_id FROM tasks WHERE id=?`, taskID).Scan(&targetID)
	s.hub.Broadcast("asset_progress", map[string]any{
		"task_id":       taskID,
		"target_id":     targetID,
		"current_asset": host,
		"assets_done":   done,
		"assets_total":  total,
	})
}
