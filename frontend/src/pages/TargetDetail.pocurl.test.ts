import { describe, expect, it } from 'vitest'
import { buildPocUrl, singleValuePayload } from './TargetDetail'

// Blind-boolean SQLi findings record a compound "TRUE=... | FALSE=..." payload
// (see sqli.go) because the finding is a differential, not a single value. A
// naive buildPocUrl would stuff that whole compound string into the query
// param, producing a URL that doesn't reproduce anything. It must instead
// extract the FALSE side (the one that demonstrates the anomaly) as a
// clean, single-click reproduction value.
describe('singleValuePayload', () => {
  it('extracts the FALSE side of a compound boolean-SQLi payload', () => {
    expect(singleValuePayload("TRUE=1 AND 1=1 | FALSE=1 AND 1=2"))
      .toBe('1 AND 1=2')
  })

  it('leaves an ordinary single-value payload untouched', () => {
    expect(singleValuePayload("' OR 1=1-- -")).toBe("' OR 1=1-- -")
  })
})

describe('buildPocUrl', () => {
  it('builds a clean reproduction URL from a compound boolean-SQLi payload', () => {
    const url = buildPocUrl('sqli', 'https://example.test/item?id=1', 'id',
      'TRUE=1 AND 1=1 | FALSE=1 AND 1=2')
    expect(url).toBe('https://example.test/item?id=1+AND+1%3D2')
  })

  it('builds a plain XSS PoC URL from a single-value payload', () => {
    const url = buildPocUrl('xss', 'https://example.test/search?q=x', 'q', '<script>alert(1)</script>')
    expect(url).toContain('example.test/search?q=')
  })

  it('returns null for a finding type that has no single GET-param vector', () => {
    expect(buildPocUrl('account_takeover', 'https://example.test/', 'xss+cookie', 'https://example.test/xss'))
      .toBeNull()
  })

  it('returns null when the payload is missing', () => {
    expect(buildPocUrl('sqli', 'https://example.test/item?id=1', 'id', undefined)).toBeNull()
  })
})
