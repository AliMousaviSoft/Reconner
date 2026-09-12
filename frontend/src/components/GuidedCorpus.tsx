import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  captures,
  type CapturedRequest,
  type CaptureTemplate,
  type GuidedCheck,
  type GuidedOpportunity,
  type GuidedReport,
  type GuidedRun,
} from '../lib/api'
import { Badge, Button, EmptyState } from './ui'
import { useUIStore } from '../store/ui'

type GuidedResult = NonNullable<GuidedReport['results']>[number]
type Candidate = { template: CaptureTemplate; suggestion: GuidedOpportunity }

const moduleOrder = ['idor', 'sqli', 'xss', 'nosqli', 'ssrf', 'open_redirect', 'lfi', 'ssti', 'cors', 'csrf', 'jwt', 'xxe', 'cmdi']
const moduleInfo: Record<string, { title: string; description: string }> = {
  idor: { title: 'IDOR / object access', description: 'Object identifiers that need a second identity and known ownership.' },
  sqli: { title: 'SQL injection', description: 'Database-shaped inputs tested with paired boolean and error controls.' },
  xss: { title: 'Cross-site scripting', description: 'Text inputs checked for unsafe HTML and JavaScript contexts.' },
  nosqli: { title: 'NoSQL injection', description: 'JSON and query fields that may accept document operators.' },
  ssrf: { title: 'Server-side request forgery', description: 'URL-shaped values tested with bounded in-band differentials.' },
  open_redirect: { title: 'Open redirect', description: 'Navigation parameters checked without following external redirects.' },
  lfi: { title: 'File / path traversal', description: 'File-shaped inputs tested with non-destructive controls.' },
  ssti: { title: 'Template injection', description: 'Text fields that may be rendered by a server-side template engine.' },
  cors: { title: 'CORS', description: 'Credentialed reads checked using two unrelated Origin controls.' },
  csrf: { title: 'CSRF', description: 'Cookie-authenticated state changes that need browser and side-effect review.' },
  jwt: { title: 'JWT / token', description: 'Token-shaped authorization headers that need an alternate test identity.' },
  xxe: { title: 'XML external entity', description: 'XML bodies requiring deliberate entity and callback setup.' },
  cmdi: { title: 'Command injection', description: 'Command-shaped fields reserved for explicit active validation.' },
}

const decode = (s: string | null) => new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(atob(s || ''), c => c.charCodeAt(0)))
const encode = (s: string) => { let raw = ''; for (const b of new TextEncoder().encode(s)) raw += String.fromCharCode(b); return btoa(raw) }

function resultPresentation(result?: GuidedResult) {
  if (!result) return { label: 'NOT RUN', variant: 'neutral', detail: 'No result for this request and test yet.' }
  if (result.findings.some(finding => finding.verdict !== 'INCONCLUSIVE')) return { label: 'HIT', variant: 'error', detail: result.reason || `${result.findings.length} signal(s) found.` }
  if (result.findings.length > 0 && result.findings.every(finding => finding.verdict === 'INCONCLUSIVE')) return { label: 'INCONCLUSIVE', variant: 'warning', detail: result.reason || 'A differential signal needs a second identity or manual proof.' }
  if (result.status === 'completed') return { label: 'NO HIT', variant: 'neutral', detail: result.reason || 'No signal found within this check; this is not a guarantee of safety.' }
  if (result.status === 'partial') return { label: 'INCONCLUSIVE', variant: 'warning', detail: result.reason || 'The check did not complete cleanly.' }
  if (result.status === 'blocked') return { label: 'BLOCKED', variant: 'warning', detail: result.reason }
  if (result.status === 'failed') return { label: 'FAILED', variant: 'error', detail: result.reason }
  return { label: result.status.toUpperCase(), variant: 'neutral', detail: result.reason }
}

function replaceJSONPointer(raw: string, pointer: string, payload: string) {
  const root: unknown = JSON.parse(raw)
  const path = pointer.split('/').slice(1).map(part => part.replace(/~1/g, '/').replace(/~0/g, '~'))
  if (!path.length) throw new Error('The suggested JSON parameter has no editable path')
  let value: unknown = payload
  try { value = JSON.parse(payload) } catch { /* keep string payload */ }
  let node: unknown = root
  for (let i = 0; i < path.length - 1; i++) {
    if (typeof node !== 'object' || node === null) throw new Error('The suggested JSON path no longer exists')
    node = (node as Record<string, unknown>)[path[i]]
  }
  if (typeof node !== 'object' || node === null) throw new Error('The suggested JSON path no longer exists')
  ;(node as Record<string, unknown>)[path[path.length - 1]] = value
  return JSON.stringify(root, null, 2)
}

function batchChecks(checks: GuidedCheck[]) {
  const batches: GuidedCheck[][] = []
  let batch: GuidedCheck[] = []
  let templates = new Set<string>()
  for (const check of checks) {
    if (batch.length >= 200 || (!templates.has(check.template_id) && templates.size >= 50)) {
      batches.push(batch)
      batch = []
      templates = new Set<string>()
    }
    batch.push(check)
    templates.add(check.template_id)
  }
  if (batch.length) batches.push(batch)
  return batches
}

export default function GuidedCorpus({ targetId, importedId }: { targetId: string; importedId: string }) {
  const [sessions, setSessions] = useState<Awaited<ReturnType<typeof captures.list>>>([])
  const [captureId, setCaptureId] = useState('')
  const [templates, setTemplates] = useState<CaptureTemplate[]>([])
  const [category, setCategory] = useState('')
  const [confirmed, setConfirmed] = useState(false)
  const [unsafe, setUnsafe] = useState(false)
  const [busy, setBusy] = useState(false)
  const [runs, setRuns] = useState<GuidedRun[]>([])
  const [revealed, setRevealed] = useState<GuidedReport | null>(null)
  const [editor, setEditor] = useState<{ id: string; version: string; request: CapturedRequest } | null>(null)
  const [activeOpportunity, setActiveOpportunity] = useState<GuidedOpportunity | null>(null)
  const [body, setBody] = useState('')
  const [binary, setBinary] = useState(false)
  const [headers, setHeaders] = useState('')
  const { addToast } = useUIStore()
  const error = (e: unknown) => addToast('error', e instanceof Error ? e.message : 'Capture operation failed')

  const candidates = useMemo<Candidate[]>(() => templates.flatMap(template => (template.suggestions || []).map(suggestion => ({ template, suggestion }))), [templates])
  const categories = useMemo(() => [...new Set(candidates.map(candidate => candidate.suggestion.module))].sort((a, b) => {
    const ai = moduleOrder.indexOf(a); const bi = moduleOrder.indexOf(b)
    return (ai < 0 ? 999 : ai) - (bi < 0 ? 999 : bi) || a.localeCompare(b)
  }), [candidates])
  const selectedCandidates = useMemo(() => candidates.filter(candidate => candidate.suggestion.module === category), [candidates, category])
  const categoryTemplates = useMemo(() => {
    const ids = new Set<string>()
    return selectedCandidates.filter(candidate => !ids.has(candidate.template.id) && !!ids.add(candidate.template.id)).map(candidate => candidate.template)
  }, [selectedCandidates])
  const active = runs.some(run => ['pending', 'running', 'paused'].includes(run.status))

  const latestResult = (templateId: string, module: string) => {
    for (const run of runs) {
      const result = run.report.results?.find(row => row.template_id === templateId && row.module === module)
      if (result) return result
    }
    return undefined
  }

  useEffect(() => {
    let live = true
    captures.list(targetId).then(value => {
      if (live) { setSessions(value); setCaptureId(current => importedId || current || value[0]?.id || '') }
    }).catch(e => { if (live) error(e) })
    return () => { live = false }
  }, [targetId, importedId])

  useEffect(() => {
    let live = true
    setTemplates([]); setRuns([]); setEditor(null); setActiveOpportunity(null); setRevealed(null); setConfirmed(false); setUnsafe(false)
    if (!captureId) return
    captures.templates(targetId, captureId).then(value => { if (live) setTemplates(value) }).catch(e => { if (live) error(e) })
    const poll = () => captures.runs(targetId, captureId).then(value => { if (live) setRuns(value) }).catch(() => undefined)
    void poll()
    const timer = setInterval(poll, 4000)
    return () => { live = false; clearInterval(timer) }
  }, [targetId, captureId])

  useEffect(() => {
    if (!categories.includes(category)) setCategory(categories[0] || '')
  }, [categories, category])

  const edit = async (template: CaptureTemplate, opportunity?: GuidedOpportunity) => {
    setBusy(true)
    try {
      const value = await captures.reveal(targetId, captureId, template.id)
      setHeaders(JSON.stringify(value.request.headers || [], null, 2))
      try { setBody(decode(value.request.body)); setBinary(false) } catch { setBody(value.request.body || ''); setBinary(true) }
      setEditor({ id: template.id, ...value }); setActiveOpportunity(opportunity || null); setRevealed(null)
    } catch (e) { error(e) } finally { setBusy(false) }
  }

  const applyPayload = (payload: string) => {
    if (!editor || !activeOpportunity) return
    try {
      const opportunity = activeOpportunity
      if (opportunity.location === 'query') {
        const url = new URL(editor.request.url)
        url.searchParams.set(opportunity.parameter, payload)
        setEditor({ ...editor, request: { ...editor.request, url: url.toString() } })
      } else if (opportunity.location === 'path') {
        const match = /^path\[(\d+)]$/.exec(opportunity.parameter)
        if (!match) throw new Error('The suggested path segment could not be identified')
        const url = new URL(editor.request.url)
        const parts = url.pathname.split('/')
        const indexes = parts.map((part, index) => part ? index : -1).filter(index => index >= 0)
        const target = indexes[Number(match[1])]
        if (target === undefined) throw new Error('The suggested path segment no longer exists')
        parts[target] = encodeURIComponent(payload)
        url.pathname = parts.join('/')
        setEditor({ ...editor, request: { ...editor.request, url: url.toString() } })
      } else if (opportunity.location === 'header') {
        const parsed = JSON.parse(headers) as { name: string; value: string }[]
        if (!Array.isArray(parsed)) throw new Error('Headers are not a JSON array')
        const found = parsed.find(header => header.name.toLowerCase() === opportunity.parameter.toLowerCase())
        if (found) found.value = payload
        else parsed.push({ name: opportunity.parameter, value: payload })
        setHeaders(JSON.stringify(parsed, null, 2))
      } else if (opportunity.location === 'body') {
        if (binary) throw new Error('Suggested payloads cannot be applied to a binary body')
        if ((editor.request.mime_type || '').toLowerCase().includes('json')) {
          setBody(replaceJSONPointer(body, opportunity.parameter, payload))
        } else {
          const values = new URLSearchParams(body)
          values.set(opportunity.parameter, payload)
          setBody(values.toString())
        }
      } else {
        throw new Error('This finding needs a manual workflow rather than a single-field edit')
      }
      setConfirmed(false)
      addToast('success', `Applied suggested value to ${opportunity.parameter}. Review it before saving.`)
    } catch (e) { error(e) }
  }

  const save = async () => {
    if (!editor) return
    setBusy(true)
    try {
      const parsed: unknown = JSON.parse(headers)
      if (!Array.isArray(parsed) || parsed.some(header => typeof header?.name !== 'string' || typeof header?.value !== 'string')) throw new Error('Headers must be an array of {name, value} objects')
      if (binary) atob(body)
      await captures.edit(targetId, captureId, editor.id, { ...editor.request, headers: parsed, body: binary ? body : encode(body) }, editor.version)
      setEditor(null); setActiveOpportunity(null); setBody(''); setHeaders(''); setConfirmed(false)
      setTemplates(await captures.templates(targetId, captureId))
      addToast('success', 'Encrypted request saved. Its baseline was invalidated; run preflight again before testing.')
    } catch (e) { error(e) } finally { setBusy(false) }
  }

  const runChecks = async (requested: GuidedCheck[]) => {
    if (!confirmed) { addToast('error', 'Confirm authorization before sending active test requests.'); return }
    const seen = new Set<string>()
    const unique = requested.filter(check => {
      const key = `${check.template_id}\u0000${check.module}`
      if (seen.has(key)) return false
      seen.add(key); return true
    })
    if (!unique.length) { addToast('error', 'There are no automated suggestions in this selection.'); return }
    setBusy(true)
    try {
      const batches = batchChecks(unique)
      for (const batch of batches) await captures.analyzeChecks(targetId, captureId, batch, unsafe)
      setRuns(await captures.runs(targetId, captureId)); setConfirmed(false)
      addToast('success', `${unique.length} suggested checks queued in ${batches.length} guided run${batches.length === 1 ? '' : 's'}.`)
    } catch (e) { error(e) } finally { setBusy(false) }
  }

  const runAll = () => runChecks(candidates.filter(candidate => candidate.suggestion.automated).map(candidate => ({ template_id: candidate.template.id, module: candidate.suggestion.module })))
  const revealReport = async (id: string) => { setBusy(true); try { setRevealed(await captures.revealReport(targetId, captureId, id)); setEditor(null); setActiveOpportunity(null) } catch (e) { error(e) } finally { setBusy(false) } }
  const removeCapture = async () => {
    if (!captureId || !window.confirm('Delete this saved capture, its encrypted requests, responses, and guided reports?')) return
    setBusy(true)
    try {
      await captures.remove(targetId, captureId)
      const remaining = await captures.list(targetId)
      setSessions(remaining); setCaptureId(remaining[0]?.id || '')
      setTemplates([]); setRuns([]); setEditor(null); setActiveOpportunity(null); setRevealed(null)
      addToast('success', 'Saved capture and encrypted evidence deleted.')
    } catch (e) { error(e) } finally { setBusy(false) }
  }
  const download = () => {
    if (!revealed) return
    const url = URL.createObjectURL(new Blob([JSON.stringify(revealed, null, 2)], { type: 'application/json' }))
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'reconner-guided-test-cases.json'; anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  return <section className="card overflow-hidden">
    <div className="p-4 border-b border-border space-y-3">
      <div><h2 className="text-sm font-semibold">Guided test workspace</h2><p className="text-xs text-text-muted mt-1">Reconner ranks likely test surfaces first. Open a category, inspect the parameter, modify the exact captured request, or run its native proof ladder.</p></div>
      <div className="flex flex-col sm:flex-row sm:items-end gap-2">
        <label className="flex-1"><span className="label">Saved capture</span><select className="input" disabled={busy} value={captureId} onChange={e => setCaptureId(e.target.value)}><option value="">Select capture…</option>{sessions.map(session => <option key={session.id} value={session.id}>{session.label || session.source} · {session.imported} requests · {session.status} · {session.created_at}</option>)}</select></label>
        <Button variant="danger" disabled={busy || active || !captureId} onClick={removeCapture}>Delete capture</Button>
      </div>
    </div>

    {!templates.length ? <EmptyState title="No saved requests" description="Import a Burp XML or Reconner capture above. Discovery itself is passive and sends no traffic."/> : <>
      <div className="grid lg:grid-cols-[280px_minmax(0,1fr)] min-h-[560px]">
        <aside className="border-b lg:border-b-0 lg:border-r border-border bg-surface-3/30 p-3 space-y-3">
          <div className="flex items-center justify-between"><div><p className="text-xs font-semibold uppercase tracking-wide">Test categories</p><p className="text-[10px] text-text-muted mt-0.5">{candidates.length} parameter signals</p></div><Badge>{categories.length}</Badge></div>
          <div className="space-y-1 max-h-[520px] overflow-auto">
            {categories.map(module => {
              const rows = candidates.filter(candidate => candidate.suggestion.module === module)
              const requests = new Set(rows.map(row => row.template.id)).size
              const hits = new Set(rows.filter(row => resultPresentation(latestResult(row.template.id, module)).label === 'HIT').map(row => row.template.id)).size
              const automated = rows.some(row => row.suggestion.automated)
              return <button type="button" key={module} onClick={() => setCategory(module)} className={`w-full text-left rounded-lg border px-3 py-2.5 transition-colors ${category === module ? 'border-accent bg-accent/10' : 'border-transparent hover:border-border hover:bg-white/[.03]'}`}>
                <span className="flex items-center justify-between gap-2"><span className="text-xs font-semibold">{moduleInfo[module]?.title || module}</span><Badge variant={hits ? 'error' : 'neutral'}>{hits ? `${hits} hit` : requests}</Badge></span>
                <span className="mt-1 flex items-center justify-between text-[10px] text-text-muted"><span>{rows.length} parameters · {requests} requests</span><span>{automated ? 'AUTO' : 'MANUAL'}</span></span>
              </button>
            })}
          </div>
          <div className="pt-3 border-t border-border space-y-3">
            <label className="flex gap-2 items-start text-[11px]"><input type="checkbox" disabled={busy} checked={unsafe} onChange={e => { setUnsafe(e.target.checked); setConfirmed(false) }}/><span>Permit repeated state-changing requests. This may modify data or sessions.</span></label>
            <label className="flex gap-2 items-start text-[11px]"><input type="checkbox" disabled={busy} checked={confirmed} onChange={e => setConfirmed(e.target.checked)}/><span>I am authorized to actively test every request I start, using its captured credentials.</span></label>
            <Button className="w-full justify-center" variant="primary" loading={busy} disabled={busy || active || !confirmed || !candidates.some(candidate => candidate.suggestion.automated)} onClick={runAll}>Start all suggested tests</Button>
            <p className="text-[10px] text-text-muted">Runs are split into bounded batches. Manual identity, browser and OAST checks are never started automatically.</p>
          </div>
        </aside>

        <main className="min-w-0 p-3 sm:p-4 space-y-3">
          {category ? <>
            <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3">
              <div><div className="flex flex-wrap items-center gap-2"><h3 className="text-base font-semibold">{moduleInfo[category]?.title || category}</h3><Badge>{selectedCandidates.some(candidate => candidate.suggestion.automated) ? 'automated proof ladder' : 'manual workflow'}</Badge></div><p className="text-xs text-text-muted mt-1">{moduleInfo[category]?.description}</p></div>
              <Button variant="primary" disabled={busy || active || !confirmed || !selectedCandidates.some(candidate => candidate.suggestion.automated)} onClick={() => runChecks(selectedCandidates.filter(candidate => candidate.suggestion.automated).map(candidate => ({ template_id: candidate.template.id, module: candidate.suggestion.module })))}>Run this category</Button>
            </div>
            <div className="space-y-2">
              {categoryTemplates.map(template => {
                const suggestions = selectedCandidates.filter(candidate => candidate.template.id === template.id).map(candidate => candidate.suggestion)
                const result = latestResult(template.id, category)
                const view = resultPresentation(result)
                return <details key={template.id} className="rounded-lg border border-border bg-surface-3/20" open={categoryTemplates.length === 1}>
                  <summary className="cursor-pointer list-none p-3 flex items-center justify-between gap-3">
                    <span className="min-w-0"><span className="text-[10px] font-bold mr-2">{template.method}</span><code className="text-xs break-all text-text-secondary">{template.route}</code><span className="block text-[10px] text-text-muted mt-1">{suggestions.length} suggested parameter{suggestions.length === 1 ? '' : 's'} · {template.kind} · preflight {template.preflight_status}</span></span>
                    <Badge variant={view.variant}>{view.label}</Badge>
                  </summary>
                  <div className="border-t border-border p-3 space-y-3">
                    {suggestions.map((suggestion, index) => <div key={`${suggestion.parameter}-${index}`} className="rounded-lg border border-border/70 bg-surface-2 p-3 space-y-2">
                      <div className="flex flex-wrap items-center gap-2"><code className="text-xs text-accent">{suggestion.parameter}</code><Badge>{suggestion.location}</Badge><Badge variant={suggestion.confidence >= 85 ? 'warning' : 'neutral'}>{suggestion.confidence}% candidate</Badge></div>
                      <p className="text-xs text-text-secondary">{suggestion.reason}</p>
                      {!!suggestion.payloads?.length && <div><p className="text-[10px] uppercase tracking-wide text-text-muted mb-1">Suggested modifications</p><div className="flex flex-wrap gap-1">{suggestion.payloads.map(payload => <code key={payload} className="rounded border border-border bg-surface-3 px-2 py-1 text-[10px] break-all">{payload}</code>)}</div></div>}
                      <div className="flex flex-wrap gap-2 pt-1"><Button size="sm" disabled={busy} onClick={() => edit(template, suggestion)}>Modify request</Button>{suggestion.automated ? <Button size="sm" variant="primary" disabled={busy || active || !confirmed} onClick={() => runChecks([{ template_id: template.id, module: suggestion.module }])}>Run analysis</Button> : <Badge>Manual setup required</Badge>}</div>
                    </div>)}
                    <div className="rounded-lg bg-surface-3/60 p-3 text-xs"><span className="font-semibold">Latest result: {view.label}</span><p className="text-text-muted mt-1">{view.detail}</p>{result && <p className="text-[10px] text-text-muted mt-1">{result.requests} requests sent · {result.findings.length} findings</p>}</div>
                  </div>
                </details>
              })}
            </div>
          </> : <EmptyState title="No test surfaces discovered" description="The saved requests have no supported parameter, path, header, identity or browser test signals."/>}
        </main>
      </div>
    </>}

    {editor && <div className="border-t border-border p-4 space-y-3 bg-surface-3/20">
      <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2"><div><h3 className="text-sm font-semibold">Request editor</h3><p className="text-xs text-severity-medium mt-1">Captured secrets are visible. Saving is local and encrypted; it does not send the request.</p></div><Badge>Burp-style exact template</Badge></div>
      {activeOpportunity && <div className="rounded-lg border border-accent/40 bg-accent/5 p-3"><p className="text-xs"><span className="font-semibold">Payload assistant:</span> change <code className="text-accent">{activeOpportunity.parameter}</code> in {activeOpportunity.location} for {moduleInfo[activeOpportunity.module]?.title || activeOpportunity.module}.</p><p className="text-[11px] text-text-muted mt-1">{activeOpportunity.reason}</p><div className="flex flex-wrap gap-2 mt-2">{activeOpportunity.payloads?.map(payload => <Button size="sm" key={payload} disabled={busy || binary && activeOpportunity.location === 'body'} onClick={() => applyPayload(payload)}>Apply <code className="ml-1 max-w-52 truncate">{payload}</code></Button>)}</div></div>}
      <div className="flex gap-2"><select className="input max-w-32" disabled={busy} value={editor.request.method} onChange={e => setEditor({ ...editor, request: { ...editor.request, method: e.target.value } })}>{['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'].map(method => <option key={method}>{method}</option>)}</select><input aria-label="Request URL" className="input" dir="ltr" disabled={busy} value={editor.request.url} onChange={e => setEditor({ ...editor, request: { ...editor.request, url: e.target.value } })}/></div>
      <label><span className="label">Content-Type</span><input className="input" disabled={busy} value={editor.request.mime_type || ''} onChange={e => setEditor({ ...editor, request: { ...editor.request, mime_type: e.target.value } })}/></label>
      <div className="grid lg:grid-cols-2 gap-3">
        <label className="block"><span className="label">Headers — JSON name/value array</span><textarea className="input font-mono text-xs h-56" dir="ltr" spellCheck={false} disabled={busy} value={headers} onChange={e => setHeaders(e.target.value)}/></label>
        <label className="block"><span className="label">Body {binary ? '(base64 — binary data)' : '(UTF-8)'}</span><textarea className="input font-mono text-xs h-56" dir="ltr" spellCheck={false} disabled={busy} value={body} onChange={e => setBody(e.target.value)}/></label>
      </div>
      <div className="flex flex-wrap gap-2"><Button variant="primary" loading={busy} onClick={save}>Save encrypted request</Button><Button disabled={busy} onClick={() => { setEditor(null); setActiveOpportunity(null); setBody(''); setHeaders('') }}>Close & hide secrets</Button></div>
    </div>}

    {!!runs.length && <div className="border-t border-border p-4 space-y-2"><h3 className="text-sm font-semibold">Run history</h3>{runs.map(run => <details className="rounded-lg border border-border p-3" key={run.id}><summary className="cursor-pointer flex flex-wrap gap-3 items-center text-xs"><Badge>{run.status}</Badge><span>{run.created_at}</span><span>{run.report.results?.length || 0} checks</span></summary><div className="mt-3 space-y-2"><div className="flex flex-wrap gap-2"><Link className="text-xs text-accent" to={`/targets/${targetId}`}>Task {run.task_id.slice(0, 8)}</Link><Button size="sm" disabled={busy || !run.report.results?.length} onClick={() => revealReport(run.id)}>Reveal evidence & test cases</Button></div>{run.report.results?.map((result, index) => { const view = resultPresentation(result); return <div key={index} className="flex flex-col sm:flex-row sm:items-center gap-2 rounded bg-surface-3/40 px-3 py-2 text-xs"><Badge variant={view.variant}>{view.label}</Badge><code>{result.template_id.slice(0, 8)}</code><span>{result.module}</span><span className="text-text-muted">{view.detail}</span></div> })}</div></details>)}</div>}
    {active && <div className="border-t border-border p-3 text-xs bg-accent/5">A guided run is active. <Link className="text-accent" to={`/targets/${targetId}`}>Open task controls</Link></div>}
    {revealed && <div className="border-t border-border p-4 space-y-3"><h3 className="text-sm font-semibold">Reproduction evidence (sensitive)</h3><p className="text-xs text-severity-medium">This export can contain live credentials. DETECTED is a signal, not automatically a confirmed vulnerability. HTTP bodies are base64 in JSON.</p><Button onClick={download}>Download test cases JSON</Button> <Button onClick={() => setRevealed(null)}>Hide evidence</Button><pre dir="ltr" className="text-xs whitespace-pre-wrap break-all max-h-96 overflow-auto">{JSON.stringify(revealed, null, 2)}</pre></div>}
  </section>
}
