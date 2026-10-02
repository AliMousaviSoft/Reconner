import { describe, expect, it } from 'vitest'
import { isIPLiteralScope } from './ScanModal'

// A web scan whose scope is a bare IP (no domain) defaults straight to the
// Deep profile (see ScanModal's reset effect) so backup/config-exposure and
// path discovery actually run against it instead of being silently skipped
// under Safe's passive-only default — there is no second, domain-based asset
// that will pick those checks up later; this one value IS the whole scope.
describe('isIPLiteralScope', () => {
  it('detects a bare IPv4 address', () => {
    expect(isIPLiteralScope('127.0.0.1')).toBe(true)
  })

  it('detects an IPv4 host inside a URL with a port', () => {
    expect(isIPLiteralScope('https://127.0.0.1:8080')).toBe(true)
  })

  it('detects an IPv4 host inside a URL with a path', () => {
    expect(isIPLiteralScope('http://203.0.113.5/admin')).toBe(true)
  })

  it('detects a bare IPv6 address', () => {
    expect(isIPLiteralScope('::1')).toBe(true)
  })

  it('detects an IPv6 host inside a bracketed URL', () => {
    expect(isIPLiteralScope('https://[::1]:8443/')).toBe(true)
  })

  it('is false for a plain domain', () => {
    expect(isIPLiteralScope('example.com')).toBe(false)
  })

  it('is false for a domain inside a URL', () => {
    expect(isIPLiteralScope('https://example.com:8080/path')).toBe(false)
  })

  it('is false for a multi-value scope (subdomain enum has other domain-based assets)', () => {
    expect(isIPLiteralScope('127.0.0.1, 10.0.0.1')).toBe(false)
  })

  it('is false for an empty scope', () => {
    expect(isIPLiteralScope('')).toBe(false)
  })
})
