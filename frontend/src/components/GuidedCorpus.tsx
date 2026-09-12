import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { captures, type CapturedRequest, type CaptureTemplate, type GuidedRun, type GuidedReport } from '../lib/api'
import { Button, Badge } from './ui'
import { useUIStore } from '../store/ui'

const modules = ['passive', 'xss', 'sqli', 'nosqli', 'ssti', 'lfi', 'ssrf', 'open_redirect', 'cors']
const decode = (s: string | null) => new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(atob(s || ''), c => c.charCodeAt(0)))
const encode = (s: string) => { let raw = ''; for (const b of new TextEncoder().encode(s)) raw += String.fromCharCode(b); return btoa(raw) }

export default function GuidedCorpus({ targetId, importedId }: { targetId: string; importedId: string }) {
  const [sessions, setSessions] = useState<Awaited<ReturnType<typeof captures.list>>>([])
  const [captureId, setCaptureId] = useState('')
  const [templates, setTemplates] = useState<CaptureTemplate[]>([])
  const [selected, setSelected] = useState<string[]>([])
  const [chosen, setChosen] = useState(modules)
  const [confirmed, setConfirmed] = useState(false)
  const [unsafe, setUnsafe] = useState(false)
  const [busy, setBusy] = useState(false)
  const [runs, setRuns] = useState<GuidedRun[]>([])
  const [revealed, setRevealed] = useState<GuidedReport | null>(null)
  const [editor, setEditor] = useState<{ id: string; version: string; request: CapturedRequest } | null>(null)
  const [body, setBody] = useState('')
  const [binary, setBinary] = useState(false)
  const [headers, setHeaders] = useState('')
  const { addToast } = useUIStore()
  const error = (e: unknown) => addToast('error', e instanceof Error ? e.message : 'Capture operation failed')

  useEffect(() => {
    let live = true
    captures.list(targetId).then(v => { if (live) { setSessions(v); setCaptureId(current => importedId || current || v[0]?.id || '') } }).catch(e => { if (live) error(e) })
    return () => { live = false }
  }, [targetId, importedId])

  useEffect(() => {
    let live = true
    setTemplates([]); setSelected([]); setRuns([]); setEditor(null); setRevealed(null); setConfirmed(false); setUnsafe(false)
    if (!captureId) return
    captures.templates(targetId, captureId).then(v => { if (live) { setTemplates(v); setSelected(v.slice(0, 50).map(t => t.id)) } }).catch(e => { if (live) error(e) })
    let polling = false
    const poll = async () => { if (polling) return; polling = true; try { const v = await captures.runs(targetId, captureId); if (live) setRuns(v) } catch (e) { if (live) error(e) } finally { polling = false } }
    void poll(); const timer = setInterval(poll, 4000)
    return () => { live = false; clearInterval(timer) }
  }, [targetId, captureId])

  const edit = async (id: string) => {
    setBusy(true)
    try {
      const v = await captures.reveal(targetId, captureId, id)
      setHeaders(JSON.stringify(v.request.headers || [], null, 2))
      try { setBody(decode(v.request.body)); setBinary(false) } catch { setBody(v.request.body || ''); setBinary(true) }
      setEditor({ id, ...v }); setRevealed(null)
    } catch (e) { error(e) } finally { setBusy(false) }
  }
  const save = async () => {
    if (!editor) return
    setBusy(true)
    try {
      const parsed = JSON.parse(headers)
      if (!Array.isArray(parsed) || parsed.some(h => typeof h?.name !== 'string' || typeof h?.value !== 'string')) throw new Error('Headers must be an array of {name, value} objects')
      if (binary) atob(body)
      await captures.edit(targetId, captureId, editor.id, { ...editor.request, headers: parsed, body: binary ? body : encode(body) }, editor.version)
      setEditor(null); setBody(''); setHeaders(''); setConfirmed(false)
      setTemplates(await captures.templates(targetId, captureId))
      addToast('success', 'Request saved encrypted. Its previous baseline was invalidated; existing runs keep their original snapshot.')
    } catch (e) { error(e) } finally { setBusy(false) }
  }
  const analyze = async () => {
    if (!confirmed || !selected.length || !chosen.length || selected.length > 50) return
    setBusy(true)
    try { await captures.analyze(targetId, captureId, selected, chosen, unsafe); setRuns(await captures.runs(targetId, captureId)); setConfirmed(false); addToast('success', 'Guided analysis queued. Results will appear here automatically.') }
    catch (e) { error(e) } finally { setBusy(false) }
  }
  const revealReport = async (id: string) => { setBusy(true); try { setRevealed(await captures.revealReport(targetId, captureId, id)); setEditor(null) } catch (e) { error(e) } finally { setBusy(false) } }
  const removeCapture = async () => {
    if (!captureId || !window.confirm('Delete this saved capture, its encrypted requests, responses, and guided reports?')) return
    setBusy(true)
    try {
      await captures.remove(targetId, captureId)
      const remaining = await captures.list(targetId)
      setSessions(remaining); setCaptureId(remaining[0]?.id || '')
      setTemplates([]); setSelected([]); setRuns([]); setEditor(null); setRevealed(null)
      addToast('success', 'Saved capture and encrypted evidence deleted.')
    } catch (e) { error(e) } finally { setBusy(false) }
  }
  const download = () => {
    if (!revealed) return
    const u = URL.createObjectURL(new Blob([JSON.stringify(revealed, null, 2)], { type: 'application/json' }))
    const a = document.createElement('a'); a.href = u; a.download = 'reconner-guided-test-cases.json'; a.click(); setTimeout(() => URL.revokeObjectURL(u), 1000)
  }
  const active = runs.some(r => ['pending', 'running', 'paused'].includes(r.status))
  return <section className="card p-4 space-y-4">
    <h2 className="text-sm font-semibold">Analyze saved requests</h2>
    <p className="text-xs text-text-muted">Import a capture above, or reopen one below. Active tests use captured credentials and send requests only to the selected routes. Importing alone sends no traffic.</p>
    <div className="flex items-end gap-2"><label className="flex-1"><span className="label">Saved capture</span><select className="input" disabled={busy} value={captureId} onChange={e => setCaptureId(e.target.value)}><option value="">Select capture…</option>{sessions.map(s => <option key={s.id} value={s.id}>{s.label || s.source} · {s.imported} requests · {s.status} · {s.created_at}</option>)}</select></label><Button disabled={busy || active || !captureId} onClick={removeCapture}>Delete capture</Button></div>
    {!!templates.length && <>
      <div className="flex gap-3 items-center text-xs"><Button disabled={busy} onClick={() => setSelected(templates.slice(0, 50).map(t => t.id))}>Select first 50</Button><Button disabled={busy} onClick={() => setSelected([])}>Clear</Button>{selected.length} / {templates.length} selected (maximum 50 per run)</div>
      <div className="max-h-96 overflow-auto"><table className="w-full"><thead><tr>{['Select', 'Request', 'Policy', 'Edit'].map(h => <th key={h} className="table-header">{h}</th>)}</tr></thead><tbody>{templates.map(t => <tr key={t.id} className="border-b border-border">
        <td className="table-cell"><input aria-label={`Select ${t.method} ${t.route}`} type="checkbox" disabled={busy} checked={selected.includes(t.id)} onChange={e => { setConfirmed(false); setSelected(v => e.target.checked ? [...v, t.id] : v.filter(id => id !== t.id)) }}/></td>
        <td className="table-cell"><code className="text-xs break-all">{t.method} {t.route}</code><p className="text-[10px] text-text-muted">{t.id.slice(0, 8)}</p></td>
        <td className="table-cell"><Badge>{t.kind}</Badge><p className="text-[10px] text-text-muted mt-1">preflight: {t.preflight_status}</p></td><td className="table-cell"><Button disabled={busy} onClick={() => edit(t.id)}>Reveal & edit</Button></td>
      </tr>)}</tbody></table></div>
      <div className="flex flex-wrap gap-3">{modules.map(m => <label className="text-xs flex gap-1 items-center" key={m}><input type="checkbox" checked={chosen.includes(m)} disabled={busy} onChange={e => { setConfirmed(false); setChosen(v => e.target.checked ? [...v, m] : v.filter(x => x !== m)) }}/>{m}</label>)}</div>
      <p className="text-xs text-text-muted">Native injection checks + XSS context signals, paired CORS checks and redirects. Eight insertion points, 160 requests and 45 seconds per module/request; limits are reported as partial coverage. No crawling, browser navigation, external tools or OAST callbacks.</p>
      <label className="flex gap-2 items-start text-xs"><input type="checkbox" disabled={busy} checked={unsafe} onChange={e => { setUnsafe(e.target.checked); setConfirmed(false) }}/><span>Also permit repeated POST/PUT/PATCH/DELETE and sensitive routes in my selection. These may create, modify or delete data or invalidate sessions.</span></label>
      <label className="flex gap-2 items-start text-xs"><input type="checkbox" disabled={busy} checked={confirmed} onChange={e => setConfirmed(e.target.checked)}/><span>I am authorized to actively test these selected requests, using their captured credentials.</span></label>
      <div className="flex gap-2"><Button variant="primary" loading={busy} disabled={busy || active || !confirmed || !selected.length || selected.length > 50 || !chosen.length} onClick={analyze}>Analyze directly</Button>{active && <Button onClick={() => window.location.assign(`/targets/${targetId}`)}>Open task controls</Button>}</div>
    </>}
    {editor && <div className="border border-border rounded-lg p-4 space-y-3">
      <h3 className="text-sm font-semibold">Manual request editor</h3><p className="text-xs text-severity-medium">Secrets are visible below. Saving does not send traffic.</p>
      <div className="flex gap-2"><select className="input max-w-32" disabled={busy} value={editor.request.method} onChange={e => setEditor({ ...editor, request: { ...editor.request, method: e.target.value } })}>{['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'].map(m => <option key={m}>{m}</option>)}</select><input aria-label="Request URL" className="input" dir="ltr" disabled={busy} value={editor.request.url} onChange={e => setEditor({ ...editor, request: { ...editor.request, url: e.target.value } })}/></div>
      <label><span className="label">Content-Type</span><input className="input" disabled={busy} value={editor.request.mime_type || ''} onChange={e => setEditor({ ...editor, request: { ...editor.request, mime_type: e.target.value } })}/></label>
      <label className="block"><span className="label">Headers — JSON array of name/value pairs (duplicates preserved)</span><textarea className="input font-mono text-xs h-40" dir="ltr" spellCheck={false} disabled={busy} value={headers} onChange={e => setHeaders(e.target.value)}/></label>
      <label className="block"><span className="label">Body {binary ? '(base64 — binary data)' : '(UTF-8)'}</span><textarea className="input font-mono text-xs h-48" dir="ltr" spellCheck={false} disabled={busy} value={body} onChange={e => setBody(e.target.value)}/></label>
      <Button variant="primary" loading={busy} onClick={save}>Save encrypted request</Button> <Button disabled={busy} onClick={() => { setEditor(null); setBody(''); setHeaders('') }}>Close & hide</Button>
    </div>}
    {runs.map(run => <div className="border border-border rounded-lg p-3 space-y-2" key={run.id}>
      <div className="flex flex-wrap gap-3 items-center text-xs"><Badge>{run.status}</Badge><span>{run.created_at}</span><Link className="text-accent" to={`/targets/${targetId}`}>Task {run.task_id.slice(0, 8)}</Link><Button disabled={busy || !run.report.results?.length} onClick={() => revealReport(run.id)}>Reveal evidence & test cases</Button></div>
      <div className="max-h-80 overflow-auto"><table className="w-full"><thead><tr>{['Request', 'Module', 'Result', 'Requests / findings', 'Details'].map(h => <th className="table-header" key={h}>{h}</th>)}</tr></thead><tbody>{run.report.results?.map((r, i) => <tr key={i} className="border-b border-border"><td className="table-cell text-xs">{r.template_id.slice(0, 8)}</td><td className="table-cell text-xs">{r.module}</td><td className="table-cell"><Badge variant={r.status === 'findings' ? 'warning' : 'neutral'}>{r.status}</Badge></td><td className="table-cell text-xs">{r.requests} / {r.findings.length}</td><td className="table-cell text-xs">{r.reason || 'No signal found within this check; not a guarantee of safety'}</td></tr>)}</tbody></table></div>
      {!!run.report.manual_modules && <details className="text-xs"><summary>Additional pipelines requiring manual setup / not executed</summary><ul className="list-disc pl-5 mt-2 space-y-1">{Object.entries(run.report.manual_modules).map(([m, reason]) => <li key={m}>{m}: {reason}</li>)}</ul></details>}
    </div>)}
    {revealed && <div className="border border-border rounded-lg p-3 space-y-3"><h3 className="text-sm font-semibold">Reproduction evidence (sensitive)</h3><p className="text-xs text-severity-medium">Export can contain live credentials. Do not upload it publicly. DETECTED is a signal, not a confirmed vulnerability. HTTP bodies in JSON use base64.</p><Button onClick={download}>Download test cases JSON</Button> <Button onClick={() => setRevealed(null)}>Hide evidence</Button><pre dir="ltr" className="text-xs whitespace-pre-wrap break-all max-h-96 overflow-auto">{JSON.stringify(revealed, null, 2)}</pre></div>}
  </section>
}
