import { useEffect, useState } from 'react'
import { targets as targetsApi } from '../../lib/api'
import { useUIStore } from '../../store/ui'

type Ident = { id: string; label: string; role: string; is_baseline: boolean; status: string; auth_method: string; last_verified_at: string; expires_at: string; last_refreshed: string; refresh_strategy: string; refresh_attempts: number; has_validation: boolean }
type AuthEvent = { identity_label: string; event: string; state: string; detail: string; created_at: string }

const STATUS_STYLE: Record<string, string> = {
  authenticated: 'badge-low',
  expired: 'badge-medium',
  unauthenticated: 'badge-critical',
  revoked: 'badge-critical',
  unknown: 'badge-neutral',
}

// Builds the raw header map from a pasted Cookie / Authorization value.
function headersFrom(cookie: string, bearer: string): Record<string, string> {
  const h: Record<string, string> = {}
  if (cookie.trim()) h['Cookie'] = cookie.trim()
  if (bearer.trim()) h['Authorization'] = bearer.trim().toLowerCase().startsWith('bearer ') ? bearer.trim() : `Bearer ${bearer.trim()}`
  return h
}

// IdentitiesPanel arms a target with multiple test users so the authorization
// engine can run PROVABLE cross-identity BOLA (User B reading User A's objects).
export const IdentitiesPanel = ({ targetId }: { targetId: string }) => {
  const [list, setList] = useState<Ident[]>([])
  const [label, setLabel] = useState('User A')
  const [cookie, setCookie] = useState('')
  const [bearer, setBearer] = useState('')
  const [baseline, setBaseline] = useState(true)
  const [validationUrl, setValidationUrl] = useState('')
  const [validationSignal, setValidationSignal] = useState('')
  const [origin, setOrigin] = useState('')
  const [storageState, setStorageState] = useState('')
  const [saving, setSaving] = useState(false)
  const [importing, setImporting] = useState(false)
  const [verifying, setVerifying] = useState('')
  const [refreshing, setRefreshing] = useState('')
  const [events, setEvents] = useState<AuthEvent[]>([])
  const { addToast } = useUIStore()

  const load = () => targetsApi.identities(targetId).then(setList).catch(() => setList([]))
  const loadEvents = () => targetsApi.authEvents(targetId).then(setEvents).catch(() => setEvents([]))
  useEffect(() => { load(); loadEvents() }, [targetId])

  const add = async () => {
    const headers = headersFrom(cookie, bearer)
    if (Object.keys(headers).length === 0) { addToast('error', 'Paste a Cookie or Authorization value'); return }
    setSaving(true)
    try {
      await targetsApi.addIdentity(targetId, { label: label || 'user', headers, is_baseline: baseline, validation_url: validationUrl, validation_signal: validationSignal })
      setCookie(''); setBearer('')
      addToast('success', `Identity "${label}" saved`)
      load()
    } catch (e) { addToast('error', e instanceof Error ? e.message : 'Failed') }
    finally { setSaving(false) }
  }

  const del = async (iid: string) => { await targetsApi.delIdentity(targetId, iid).catch(() => {}); load() }

  const importSession = async () => {
    if (!origin.trim() || !storageState.trim()) { addToast('error', 'Need origin + storageState JSON'); return }
    setImporting(true)
    try {
      await targetsApi.importSession(targetId, {
        label: label || 'user', origin: origin.trim(), storage_state: storageState.trim(),
        is_baseline: baseline, validation_url: validationUrl, validation_signal: validationSignal,
      })
      setStorageState('')
      addToast('success', `Browser session imported as "${label}"`)
      load()
    } catch (e) { addToast('error', e instanceof Error ? e.message : 'Import failed') }
    finally { setImporting(false) }
  }

  const verify = async (iid: string) => {
    setVerifying(iid)
    try {
      const r = await targetsApi.validateIdentity(targetId, iid)
      addToast(r.status === 'authenticated' ? 'success' : 'warning', `Session: ${r.status}`)
      load(); loadEvents()
    } catch (e) { addToast('error', e instanceof Error ? e.message : 'Verify failed') }
    finally { setVerifying('') }
  }

  const refresh = async (iid: string) => {
    setRefreshing(iid)
    try {
      const r = await targetsApi.refreshIdentity(targetId, iid)
      addToast(r.refreshed ? 'success' : 'warning', r.refreshed ? 'Session refreshed' : `Refresh: ${r.state}`)
      load(); loadEvents()
    } catch (e) { addToast('error', e instanceof Error ? e.message : 'Refresh failed') }
    finally { setRefreshing('') }
  }

  const revoke = async (iid: string) => {
    if (!confirm('Revoke this profile? Its stored credentials will be wiped immediately.')) return
    try {
      await targetsApi.revokeIdentity(targetId, iid)
      addToast('success', 'Profile revoked — credentials wiped')
      load(); loadEvents()
    } catch (e) { addToast('error', e instanceof Error ? e.message : 'Revoke failed') }
  }

  return (
    <details className="card p-4">
      <summary className="text-sm font-medium cursor-pointer select-none">
        Identities — cross-identity BOLA {list.length > 0 && <span className="text-accent-hover">({list.length})</span>}
      </summary>
      <div className="mt-3 space-y-3">
        <p className="text-xs text-text-muted">
          Add ≥2 logged-in users. Mark one <b>baseline</b> (the owner). The IDOR engine will try to read the
          baseline's objects as the other user and only reports a <b>confirmed BOLA</b> when it succeeds
          while an unauthenticated request is denied.
        </p>

        {list.length > 0 && (
          <ul className="space-y-1">
            {list.map(i => (
              <li key={i.id} className="flex flex-wrap items-center gap-2 text-xs bg-white/[.03] rounded-lg px-2.5 py-1.5">
                <span className="font-medium">{i.label}</span>
                {i.is_baseline && <span className="badge-info">baseline / owner</span>}
                <span className={STATUS_STYLE[i.status] || 'badge-neutral'}>{i.status || 'unknown'}</span>
                {i.refresh_strategy && i.refresh_strategy !== 'none' && <span className="badge-neutral" title="refresh strategy">↻ {i.refresh_strategy}</span>}
                {i.expires_at && <span className="text-text-muted" title="expires">exp {i.expires_at.slice(0, 16).replace('T', ' ')}</span>}
                {i.last_verified_at && <span className="text-text-muted" title="last validated">✓ {i.last_verified_at.slice(0, 16).replace('T', ' ')}</span>}
                <span className="ml-auto flex items-center gap-2">
                  <button onClick={() => verify(i.id)} disabled={verifying === i.id}
                    className="text-accent-hover hover:underline">{verifying === i.id ? '…' : 'Validate'}</button>
                  {i.refresh_strategy && i.refresh_strategy !== 'none' && i.status !== 'revoked' && (
                    <button onClick={() => refresh(i.id)} disabled={refreshing === i.id}
                      className="text-accent-hover hover:underline">{refreshing === i.id ? '…' : 'Refresh'}</button>
                  )}
                  {i.status !== 'revoked' && (
                    <button onClick={() => revoke(i.id)} className="text-text-muted hover:text-severity-high">Revoke</button>
                  )}
                  <button onClick={() => del(i.id)} className="text-text-muted hover:text-severity-critical" title="delete">✕</button>
                </span>
              </li>
            ))}
          </ul>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <input value={label} onChange={e => setLabel(e.target.value)} placeholder="Label (e.g. User A)"
            className="input text-xs" />
          <label className="flex items-center gap-2 text-xs text-text-secondary">
            <input type="checkbox" checked={baseline} onChange={e => setBaseline(e.target.checked)} />
            baseline (the object owner)
          </label>
        </div>
        <input value={cookie} onChange={e => setCookie(e.target.value)}
          placeholder="Cookie:  session=abc123; ..." className="input text-xs font-mono" />
        <input value={bearer} onChange={e => setBearer(e.target.value)}
          placeholder="Authorization:  eyJhbGci...  (Bearer added automatically)" className="input text-xs font-mono" />
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <input value={validationUrl} onChange={e => setValidationUrl(e.target.value)}
            placeholder="Validation URL (e.g. /api/me) — for Verify" className="input text-xs font-mono" />
          <input value={validationSignal} onChange={e => setValidationSignal(e.target.value)}
            placeholder='Signal text (e.g. "username") — optional' className="input text-xs font-mono" />
        </div>
        <button onClick={add} disabled={saving} className="btn-secondary text-xs">
          {saving ? 'Saving…' : '+ Add identity (headers)'}
        </button>

        {/* Browser session import (capture mode) */}
        <div className="border-t border-white/[.06] pt-3 space-y-2">
          <p className="text-xs text-text-muted">
            <b>Capture a real browser session</b>: log in normally in your own browser (solve CAPTCHA/OTP/MFA
            yourself), export a Playwright/Chrome <code className="code">storageState</code> JSON, and paste it
            below. Reconner keeps only the session material for this origin, encrypted.
          </p>
          <input value={origin} onChange={e => setOrigin(e.target.value)}
            placeholder="Origin:  https://app.example.com" className="input text-xs font-mono" />
          <textarea value={storageState} onChange={e => setStorageState(e.target.value)}
            placeholder='{"cookies":[...],"origins":[...]}' rows={3}
            className="input text-xs font-mono" />
          <button onClick={importSession} disabled={importing} className="btn-secondary text-xs">
            {importing ? 'Importing…' : 'Import browser session'}
          </button>
        </div>

        {/* Authentication-lifecycle timeline (sanitized — never shows secrets). */}
        {events.length > 0 && (
          <div className="border-t border-white/[.06] pt-3">
            <p className="text-xs font-medium mb-1.5">Authentication timeline</p>
            <ul className="space-y-1 max-h-48 overflow-auto">
              {events.map((e, idx) => (
                <li key={idx} className="flex items-start gap-2 text-[11px] text-text-muted">
                  <span className="tabular-nums shrink-0">{e.created_at.slice(0, 19).replace('T', ' ')}</span>
                  <span className="font-medium text-text-secondary shrink-0">{e.identity_label || '—'}</span>
                  <span className={STATUS_STYLE[e.state] || 'badge-neutral'}>{e.event}</span>
                  {e.detail && <span className="truncate">{e.detail}</span>}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </details>
  )
}
