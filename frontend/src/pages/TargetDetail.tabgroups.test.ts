import { describe, expect, it } from 'vitest'
import { tabGroupsFor } from './TargetDetail'

// Per-project-type tabs (TargetDetail): a network (IP/CIDR) project never
// populates the web-crawl tables (subdomains/http/js/params/dirs/admin-panels/
// redirects/js-findings/backups — nothing in the network pipeline writes to
// them), and a WordPress project gets its own group for the plugin/theme/
// user/endpoint inventory wp_enum/wp_users/wp_endpoints record. Regressing
// either back to one generic tab set for every project is exactly the bug
// this guards against.
describe('tabGroupsFor', () => {
  const idsOf = (groups: ReturnType<typeof tabGroupsFor>) => groups.flatMap(g => g.tabs.map(t => t.id))

  it('a network project only shows network-relevant tabs', () => {
    const ids = idsOf(tabGroupsFor(true, false))
    expect(ids).toContain('network-services')
    expect(ids).toContain('vulns')
    expect(ids).toContain('nuclei')
    for (const webOnly of ['subdomains', 'http', 'js', 'params', 'dirs', 'admin-panels', 'redirects', 'js-findings', 'backups', 'wp-inventory']) {
      expect(ids).not.toContain(webOnly)
    }
  })

  it('a WordPress project gets a dedicated WordPress group plus the usual web tabs', () => {
    const groups = tabGroupsFor(false, true)
    expect(groups.some(g => g.group === 'WordPress')).toBe(true)
    const ids = idsOf(groups)
    expect(ids).toEqual(expect.arrayContaining(['wp-inventory', 'wp-users', 'wp-endpoints', 'subdomains', 'vulns', 'candidates']))
    expect(ids).not.toContain('network-services')
  })

  it('a plain web project gets neither the network nor the WordPress tabs', () => {
    const ids = idsOf(tabGroupsFor(false, false))
    expect(ids).not.toContain('network-services')
    expect(ids).not.toContain('wp-inventory')
    expect(ids).toContain('subdomains')
    expect(ids).toContain('vulns')
  })

  it('every tab carries a non-empty description for the per-tab help text', () => {
    for (const groups of [tabGroupsFor(true, false), tabGroupsFor(false, true), tabGroupsFor(false, false)]) {
      for (const g of groups) for (const t of g.tabs) expect(t.desc).toBeTruthy()
    }
  })
})
