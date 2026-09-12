import { useEffect, useMemo, useState } from 'react'
import { captures, targets as targetsApi, type CapturePreview } from '../lib/api'
import type { Target } from '../types'
import { Badge, Button, EmptyState, Spinner } from '../components/ui'
import { useUIStore } from '../store/ui'
import GuidedCorpus from '../components/GuidedCorpus'

const sourceFor = async (file: File) => {
  const prefix = (await file.slice(0, 4096).text()).trimStart()
  if (prefix.startsWith('<')) return 'burp_xml'
  if (prefix.startsWith('{')) return 'reconner_json'
  throw new Error('Unsupported capture file. Choose Burp XML or Reconner capture JSON.')
}

export default function GuidedAnalyze() {
  const [targets, setTargets] = useState<Target[]>([])
  const [targetId, setTargetId] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [identity, setIdentity] = useState('User A')
  const [label, setLabel] = useState('')
  const [preview, setPreview] = useState<CapturePreview | null>(null)
  const [busy, setBusy] = useState<'preview'|'import'|null>(null)
  const [captureId, setCaptureId] = useState('')
  const [preflight, setPreflight] = useState<Awaited<ReturnType<typeof captures.preflight>> | null>(null)
  const [preflighting, setPreflighting] = useState(false)
  const { addToast } = useUIStore()

  useEffect(() => { targetsApi.list().then(v => { const web = v.filter(t => t.kind !== 'network'); setTargets(web); if (web[0]) setTargetId(web[0].id) }).catch(() => addToast('error', 'Could not load projects')) }, [])

  const domainMap = useMemo(() => {
    const map = new Map<string, { routes: number; tests: Set<string>; auto: number }>()
    for (const item of preview?.items || []) {
      if (!item.accepted) continue
      let host = 'unknown'
      try { host = new URL(item.route).host } catch { /**/ }
      const row = map.get(host) || { routes: 0, tests: new Set<string>(), auto: 0 }
      row.routes++; if (item.auto_eligible) row.auto++
      for (const test of item.suggested_tests || []) row.tests.add(test)
      map.set(host, row)
    }
    return [...map.entries()]
  }, [preview])

  const submit = async (commit: boolean) => {
    if (!file || !targetId) { addToast('error', 'Choose a project and capture file'); return }
    setBusy(commit ? 'import' : 'preview')
    try {
      const source = await sourceFor(file)
      if (commit) {
        const result = await captures.import(targetId, file, source, identity.trim(), label.trim())
        setPreview(result.preview)
        setCaptureId(result.capture_id)
        setPreflight(null)
        addToast('success', `${result.templates_stored} encrypted request templates imported; no traffic was sent`)
      } else {
        const result = await captures.preview(targetId, file, source, identity.trim(), label.trim())
        setPreview(result.preview)
        addToast('success', `Passive preview ready: ${result.preview.accepted} in-scope requests`)
      }
    } catch (e) { addToast('error', e instanceof Error ? e.message : 'Capture import failed') }
    finally { setBusy(null) }
  }

  const runPreflight = async () => {
    if (!captureId || !targetId) return
    setPreflighting(true)
    try {
      const result = await captures.preflight(targetId, captureId)
      setPreflight(result)
      addToast(result.failed_or_stale ? 'error' : 'success', `${result.ready} baselines ready; ${result.failed_or_stale} stale/failed; ${result.mutations_sent} mutations`)
    } catch (e) { addToast('error', e instanceof Error ? e.message : 'Preflight failed') }
    finally { setPreflighting(false) }
  }

  // Selecting a file now visibly processes it; import and active traffic remain
  // separate explicit actions. Inputs are locked during this short preview.
  useEffect(() => { if (file && targetId) void submit(false) }, [file, targetId])

  return (
    <div className="space-y-5 max-w-[1500px] mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-3">
        <div><h1 className="text-xl font-bold">Guided Analyze</h1><p className="text-xs text-text-muted mt-1">Turn researcher-driven Burp or Chrome traffic into a narrow, state-aware test corpus.</p></div>
        <Badge variant="success">Passive import · 0 target requests</Badge>
      </div>

      <section className="card p-4 sm:p-5 space-y-4">
        <div className="grid md:grid-cols-2 gap-4">
          <label><span className="label">Project</span><select className="input" disabled={!!busy || preflighting} value={targetId} onChange={e => { setTargetId(e.target.value); setPreview(null); setCaptureId(''); setPreflight(null) }}><option value="">Choose project…</option>{targets.map(t => <option key={t.id} value={t.id}>{t.name || t.domain}</option>)}</select></label>
          <label><span className="label">Capture file (XML / JSON, with or without extension)</span><input className="input file:mr-3 file:text-xs file:bg-transparent file:border-0 file:text-accent" type="file" disabled={!!busy || preflighting} onChange={e => { setFile(e.target.files?.[0] || null); setPreview(null); setCaptureId(''); setPreflight(null) }}/></label>
          <label><span className="label">Identity</span><input className="input" disabled={!!busy || preflighting} value={identity} maxLength={80} onChange={e => setIdentity(e.target.value)} placeholder="User A / User B / Admin"/></label>
          <label><span className="label">Capture label</span><input className="input" disabled={!!busy || preflighting} value={label} maxLength={120} onChange={e => setLabel(e.target.value)} placeholder="Checkout → invoice flow"/></label>
        </div>
        <div className="rounded-lg border border-border bg-surface-3/40 p-3 text-xs text-text-secondary">
          Burp: select in-scope HTTP history items and use <b>Save items</b> as XML. Chrome: load the bundled DevTools extension and export <code>reconner-capture/v1</code> JSON. Preview and import never replay traffic.
        </div>
        {file && <p role="status" className="text-xs text-accent">Selected: {file.name} · {(file.size / 1048576).toFixed(1)} MiB. Preview runs automatically; use the preview button to retry, then import the requests to save them.</p>}
        <div className="flex flex-wrap gap-2"><Button variant="primary" loading={busy === 'preview'} disabled={!file || !targetId || !!busy} onClick={() => submit(false)}>Re-run preview</Button><Button loading={busy === 'import'} disabled={!file || !targetId || !!busy} onClick={() => submit(true)}>Import requests</Button></div>
      </section>

      {targetId && <GuidedCorpus key={targetId} targetId={targetId} importedId={captureId}/>}

      {!preview ? <EmptyState title="No capture analyzed yet" description="Choose a Burp XML or Reconner Chrome JSON file. The first pass is local, passive, scope-checked and redacted."/> : <>
        <section className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-8 gap-2">
          {[['Total',preview.total],['In scope',preview.accepted],['Rejected',preview.rejected],['Sensitive',preview.sensitive],['Read-only',preview.read_only],['Writes',preview.state_changing],['Auth',preview.authentication],['Unknown',preview.unknown]].map(([k,v]) => <div className="card p-3" key={String(k)}><p className="text-[10px] uppercase tracking-wide text-text-muted">{k}</p><p className="text-xl font-bold mt-1">{v}</p></div>)}
        </section>

        <section className="grid xl:grid-cols-[.8fr_1.2fr] gap-4">
          <div className="card p-4"><h2 className="text-sm font-semibold mb-3">Domain and scenario map</h2><div className="space-y-2">{domainMap.map(([host,row]) => <div key={host} className="rounded-lg border border-border p-3"><div className="flex items-center justify-between"><code className="text-xs text-accent">{host}</code><span className="text-[10px] text-text-muted">{row.routes} routes · {row.auto} proof-only eligible</span></div><div className="flex flex-wrap gap-1 mt-2">{[...row.tests].map(test => <Badge key={test}>{test}</Badge>)}</div></div>)}</div></div>
          <div className="card overflow-hidden"><div className="p-4 border-b border-border"><h2 className="text-sm font-semibold">Request review</h2><p className="text-[11px] text-text-muted mt-1">Values are hidden; state-changing requests are never auto-eligible.</p></div><div className="max-h-[520px] overflow-auto"><table className="w-full"><thead className="sticky top-0 bg-surface-2"><tr>{['Method / route','Kind','Suggested tests','Policy'].map(h => <th className="table-header" key={h}>{h}</th>)}</tr></thead><tbody>{preview.items.map(item => <tr key={item.sequence} className="border-b border-border/60"><td className="table-cell max-w-md"><span className="text-[10px] font-bold mr-2">{item.method}</span><code className="text-[11px] text-text-secondary break-all">{item.route}</code></td><td className="table-cell"><Badge variant={item.operation_kind === 'state_changing' ? 'warning' : 'neutral'}>{item.operation_kind}</Badge></td><td className="table-cell"><div className="flex flex-wrap gap-1">{(item.suggested_tests || []).map(t => <span key={t} className="text-[10px] text-accent">{t}</span>)}</div></td><td className="table-cell"><Badge variant={item.auto_eligible ? 'success' : 'neutral'}>{item.auto_eligible ? 'proof-only' : item.accepted ? 'manual review' : 'rejected'}</Badge></td></tr>)}</tbody></table></div></div>
        </section>
        <section className="card p-4 flex flex-col sm:flex-row sm:items-center gap-3"><div className="flex items-start gap-3 flex-1"><div className="mt-0.5">{preflighting ? <Spinner className="w-5 h-5"/> : <span className="text-accent">◎</span>}</div><div><p className="text-sm font-medium">Exact-template baseline preflight</p><p className="text-xs text-text-muted mt-1">After import, explicitly replay only captured GET/HEAD/OPTIONS templates. Scope and DNS destination are checked again, redirects are not followed, and no parameters are mutated.</p>{preflight && <p className="text-xs mt-2"><span className="text-severity-low">{preflight.ready} ready</span> · <span className="text-severity-medium">{preflight.failed_or_stale} stale/failed</span> · {preflight.requests_sent} baseline requests · {preflight.mutations_sent} mutations</p>}</div></div><Button variant="primary" loading={preflighting} disabled={!captureId || preflighting} onClick={runPreflight}>Run safe preflight</Button></section>
        {preflight && <section className="card overflow-hidden"><div className="p-4 border-b border-border"><h2 className="text-sm font-semibold">Preflight evidence</h2></div><div className="max-h-[420px] overflow-auto"><table className="w-full"><thead><tr>{['Route','Captured → live','Verdict','Reason'].map(h => <th className="table-header" key={h}>{h}</th>)}</tr></thead><tbody>{preflight.results.map(r => <tr key={r.template_id} className="border-b border-border/60"><td className="table-cell"><code className="text-[11px] break-all">{r.method} {r.route}</code></td><td className="table-cell text-xs">{r.captured_status || '—'} → {r.http_status || '—'}</td><td className="table-cell"><Badge variant={r.status === 'ready' ? 'success' : r.status === 'blocked' ? 'neutral' : 'warning'}>{r.status}</Badge></td><td className="table-cell text-[11px] text-text-muted">{r.reason}</td></tr>)}</tbody></table></div></section>}
      </>}
    </div>
  )
}
