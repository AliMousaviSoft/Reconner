import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import BountyPrograms from './BountyPrograms'

function ok(data: unknown) {
  return new Response(JSON.stringify({ success: true, data }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

const program = {
  id: 'prog-1', provider: 'hackerone', external_id: 'e1', handle: 'acme', name: 'Acme Corp',
  url: 'https://hackerone.com/acme', logo_url: '', description: 'A test program.', status: 'live',
  program_type: 'bug_bounty', industry: 'tech', offers_bounties: true, open_scope: false, safe_harbor: 'full',
  asset_count: 5, in_scope_count: 5, wildcard_count: 1, scope_rank: 1, min_reward_cents: 10000, max_reward_cents: 500000,
  currency: 'USD', started_at: null, published_at: null, provider_updated_at: null, last_synced_at: null,
  detail_synced_at: null, details_loaded: true,
}

// Favoriting is the user-facing entry point for "watch this program"; the
// star must reflect real backend state (not just local optimism) and must
// send the right policy on toggle/change.
describe('BountyPrograms favoriting', () => {
  it('favorites a program, shows the policy selector, and updates the policy', async () => {
    let favorited = false
    let lastPolicy = ''
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      const method = init?.method || 'GET'
      if (url.includes('/bounty/programs') && url.endsWith('/favorite') && method === 'POST') {
        const body = JSON.parse(String(init?.body))
        lastPolicy = body.auto_scan_policy
        favorited = true
        return ok({ status: 'favorited' })
      }
      if (url.includes('/bounty/favorites')) {
        return ok(favorited ? { 'prog-1': { program_id: 'prog-1', auto_scan_policy: lastPolicy || 'notify', watch_interval_hours: 12, created_at: '' } } : {})
      }
      if (url.includes('/bounty/status')) return ok([])
      if (url.includes('/bounty/programs')) return ok({ programs: [program], total: 1, page: 1, limit: 30 })
      return ok({})
    })
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()

    render(<MemoryRouter><BountyPrograms /></MemoryRouter>)
    await screen.findByText('Acme Corp')
    expect(screen.getByTitle(/Favorite —/)).toHaveTextContent('☆')

    await user.click(screen.getByTitle(/Favorite —/))
    await waitFor(() => expect(lastPolicy).toBe('notify'))

    await waitFor(() => expect(screen.getByText('★ watching')).toBeInTheDocument())
    expect(screen.getByTitle('Remove from favorites')).toHaveTextContent('★')

    const policySelect = screen.getByDisplayValue('Notify only')
    await user.selectOptions(policySelect, 'full_scan')
    await waitFor(() => expect(lastPolicy).toBe('full_scan'))
  })
})
