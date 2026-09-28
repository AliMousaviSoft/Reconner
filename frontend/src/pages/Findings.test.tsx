import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import Findings from './Findings'

function ok(data: unknown) {
  return new Response(JSON.stringify({ success: true, data }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

const finding = {
  id: 'f1', target_id: 't1', domain: 'example.test', type: 'sqli', severity: 'high',
  url: 'https://example.test/?id=1', parameter: 'id', payload: "1' AND (1=1)-- -",
  confidence: 95, priority: 10, status: 'finding',
  evidence: 'DB error triggered by boundary (reproduced; absent from baseline)',
  created_at: new Date().toISOString(),
}

// The global Findings page must surface the reproduction payload directly (not
// force the reviewer to open the target detail view first), and clicking the
// PoC toggle or copy button must not navigate the row away.
describe('Findings payload/PoC surfacing', () => {
  it('shows the payload inline and expands full payload + evidence without navigating away', async () => {
    const fetchMock = vi.fn(async () => ok([finding]))
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()

    render(<MemoryRouter><Findings /></MemoryRouter>)
    await screen.findByText('sqli')

    // Truncated payload is visible inline in the table row.
    expect(screen.getByTitle("1' AND (1=1)-- -")).toBeInTheDocument()

    // Expanding shows the full payload and evidence.
    await user.click(screen.getByText('PoC'))
    await waitFor(() => expect(screen.getByText('Evidence')).toBeInTheDocument())
    expect(screen.getAllByText("1' AND (1=1)-- -").length).toBeGreaterThan(1)
    expect(screen.getByText(/DB error triggered by boundary/)).toBeInTheDocument()

    // Collapsing works too.
    await user.click(screen.getByText('hide'))
    await waitFor(() => expect(screen.queryByText('Evidence')).not.toBeInTheDocument())
  })
})
