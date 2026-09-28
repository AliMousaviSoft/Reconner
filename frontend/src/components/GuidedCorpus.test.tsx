import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import GuidedCorpus from './GuidedCorpus'

function ok(data: unknown) {
  return new Response(JSON.stringify({ success: true, data }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

const templates = [
  {
    id: 'tpl-avatar', method: 'POST', route: '/api/avatar', kind: 'state_changing', preflight_status: 'ready', version: 'v1',
    suggestions: [
      { module: 'xss', parameter: 'name', location: 'body', confidence: 80, reason: 'Reflected text field', payloads: ['<svg onload>'], automated: true },
      { module: 'sqli', parameter: 'id', location: 'query', confidence: 70, reason: 'Numeric identifier', payloads: [], automated: true },
    ],
  },
  {
    id: 'tpl-orders', method: 'GET', route: '/api/orders/42', kind: 'read_only', preflight_status: 'ready', version: 'v1',
    suggestions: [
      { module: 'idor', parameter: 'path[0]', location: 'path', confidence: 90, reason: 'Numeric object id in path', payloads: [], automated: true },
    ],
  },
]

// The left sidebar must list unique REQUESTS (not vulnerability categories):
// each captured template shows up once, on its own, with the tests that
// apply to it -- this is what the user explicitly asked for.
describe('GuidedCorpus request-first sidebar', () => {
  it('lists each unique request on the left and shows only its own tests on the right', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('/captures/cap1/templates')) return ok(templates)
      if (url.includes('/captures/cap1/runs')) return ok([])
      if (url.includes('/captures?') || url.endsWith('/captures')) return ok([{ id: 'cap1', source: 'burp_xml', identity_label: '', label: '', status: 'ready', imported: 2, accepted: 2, rejected: 0, created_at: '', expires_at: '' }])
      return ok([])
    })
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()

    render(<MemoryRouter><GuidedCorpus targetId="t1" importedId="cap1"/></MemoryRouter>)

    // Both unique requests appear as separate entries in the left sidebar.
    await waitFor(() => expect(screen.getByText('/api/avatar')).toBeInTheDocument())
    expect(screen.getByText('/api/orders/42')).toBeInTheDocument()

    // The first request (highest sort priority: no hits yet, alphabetical) is
    // auto-selected; its own two tests (XSS, SQLi) show, but not the other
    // request's IDOR test.
    await waitFor(() => expect(screen.getByText('Cross-site scripting')).toBeInTheDocument())
    expect(screen.getByText('SQL injection')).toBeInTheDocument()
    expect(screen.queryByText('IDOR / object access')).not.toBeInTheDocument()

    // Selecting the other request swaps the detail pane to ITS tests only.
    await user.click(screen.getByText('/api/orders/42'))
    await waitFor(() => expect(screen.getByText('IDOR / object access')).toBeInTheDocument())
    expect(screen.queryByText('Cross-site scripting')).not.toBeInTheDocument()

    // Filtering narrows the left list to matching requests only.
    await user.type(screen.getByPlaceholderText('Filter by method or path…'), 'avatar')
    expect(screen.getByText('/api/avatar')).toBeInTheDocument()
    expect(screen.queryByText('/api/orders/42')).not.toBeInTheDocument()
  })
})
