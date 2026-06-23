import { useState, useEffect } from 'react'
import { AlertTriangle, Link, Brain, ChevronDown, ChevronRight, Clock, Sparkles, Loader } from 'lucide-react'

const API = 'http://localhost:8000'
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 }
const TYPE_ICON = { sigma: AlertTriangle, correlation: Link, ml: Brain }
const TYPE_COLOR = { sigma: '#a78bfa', correlation: '#38bdf8', ml: '#4ade80' }

const RISK_COLOR = { high: '#ef4444', medium: '#f97316', low: '#4ade80', unknown: '#94a3b8', internal: '#6366f1' }

function timeAgo(ts) {
  const diff = Date.now() / 1000 - ts
  if (diff < 60) return `${Math.floor(diff)}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  return `${Math.floor(diff / 3600)}h ago`
}

function EnrichmentBadge({ ip }) {
  const [data, setData] = useState(null)
  useEffect(() => {
    if (!ip || !/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return
    fetch(`${API}/api/enrich/${ip}`).then(r => r.json()).then(setData).catch(() => {})
  }, [ip])
  if (!data || data.is_private) return null
  const color = RISK_COLOR[data.risk_level]
  return (
    <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
      {data.country_code && (
        <span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 3, background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>
          {data.country_code}
        </span>
      )}
      {data.abuse_score != null && (
        <span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 3, fontWeight: 700, background: `${color}22`, color, border: `1px solid ${color}44` }}>
          {data.abuse_score}/100
        </span>
      )}
      {data.is_hosting && (
        <span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 3, background: '#f9731622', color: '#f97316', border: '1px solid #f9731644' }}>
          HOSTING
        </span>
      )}
    </span>
  )
}

function AIInlinePanel({ alertId }) {
  const [mode, setMode] = useState(null)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  const run = async (task) => {
    if (mode === task && result) { setMode(null); setResult(null); return }
    setMode(task); setLoading(true); setError(null); setResult(null)
    try {
      const res = await fetch(`${API}/api/ai/${task}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ alert_id: alertId }),
      })
      const data = await res.json()
      if (!res.ok || data.error) throw new Error(data.detail || data.error || `HTTP ${res.status}`)
      setResult(data.content)
    } catch(e) { setError(e.message) }
    finally { setLoading(false) }
  }

  const BTN = (active) => ({
    display: 'flex', alignItems: 'center', gap: 4,
    padding: '3px 9px', borderRadius: 4, border: '1px solid',
    borderColor: active ? 'var(--accent-cyan)' : 'var(--border)',
    background: active ? '#0c4a6e33' : 'transparent',
    color: active ? 'var(--accent-cyan)' : 'var(--text-muted)',
    cursor: 'pointer', fontSize: 11, fontWeight: 500,
  })

  return (
    <div style={{ marginTop: 10, paddingTop: 10, borderTop: '1px solid #1e293b' }}>
      <div style={{ display: 'flex', gap: 6, marginBottom: (loading || result || error) ? 10 : 0, alignItems: 'center' }}>
        <Sparkles size={11} color="var(--accent-cyan)" />
        <span style={{ fontSize: 10, color: 'var(--text-muted)', marginRight: 2 }}>AI:</span>
        {[{ id: 'explain', label: 'Explain' }, { id: 'recommend', label: 'Actions' }, { id: 'mitre', label: 'ATT&CK' }].map(btn => (
          <button key={btn.id} onClick={() => run(btn.id)} style={BTN(mode === btn.id && (result || loading))}>
            {loading && mode === btn.id && <Loader size={9} style={{ animation: 'spin 1s linear infinite' }} />}
            {btn.label}
          </button>
        ))}
      </div>
      {(loading || result || error) && (
        <div style={{ background: 'var(--bg-primary)', borderRadius: 6, padding: '10px 12px', fontSize: 12, border: '1px solid var(--border)', maxHeight: 280, overflowY: 'auto' }}>
          {loading && <span style={{ color: 'var(--text-muted)' }}>Gemini is reasoning... this may take up to several minutes</span>}
          {error && <span style={{ color: 'var(--sev-critical)' }}>{error.includes('API key') ? '⚠ GEMINI_API_KEY not set' : error}</span>}
          {result && (
            <div style={{ color: 'var(--text-secondary)', lineHeight: 1.7 }}>
              {result.split('\n').map((line, i) => {
                if (line.startsWith('## ') || line.startsWith('### '))
                  return <div key={i} style={{ fontWeight: 700, color: 'var(--text-primary)', margin: '10px 0 4px' }}>{line.replace(/^#+\s/, '')}</div>
                if (line.startsWith('- ') || line.startsWith('* '))
                  return <div key={i} style={{ display: 'flex', gap: 6, margin: '2px 0 2px 8px' }}><span style={{ color: 'var(--accent-cyan)' }}>•</span><span>{line.slice(2)}</span></div>
                if (line === '') return <div key={i} style={{ height: 5 }} />
                const parts = line.split(/(\*\*[^*]+\*\*)/)
                return <div key={i}>{parts.map((p, j) => p.startsWith('**') ? <strong key={j} style={{ color: 'var(--text-primary)' }}>{p.slice(2,-2)}</strong> : p)}</div>
              })}
            </div>
          )}
        </div>
      )}
      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
    </div>
  )
}

function AlertCard({ alert }) {
  const [expanded, setExpanded] = useState(false)
  const Icon = TYPE_ICON[alert.alert_type] || AlertTriangle
  const color = TYPE_COLOR[alert.alert_type] || '#94a3b8'
  const sev = alert.severity?.toLowerCase()
  const border = sev === 'critical' ? 'var(--sev-critical)' : sev === 'high' ? 'var(--sev-high)' : sev === 'medium' ? 'var(--sev-medium)' : 'var(--sev-low)'

  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderLeft: `3px solid ${border}`, borderRadius: 7, marginBottom: 7, overflow: 'hidden' }}>
      <div onClick={() => setExpanded(e => !e)} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px', cursor: 'pointer' }}>
        <Icon size={13} color={color} style={{ flexShrink: 0 }} />
        <span className={`badge badge-${sev}`}>{sev?.toUpperCase()}</span>
        <span className={`badge badge-${alert.alert_type}`}>{alert.alert_type?.toUpperCase()}</span>
        <span style={{ flex: 1, fontWeight: 600, fontSize: 13, color: 'var(--text-primary)' }}>{alert.title}</span>
        {alert.source_key && (
          <span style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
            <span style={{ fontSize: 11, fontFamily: 'var(--mono)', color: 'var(--accent-cyan)' }}>{alert.source_key}</span>
            <EnrichmentBadge ip={alert.source_key} />
          </span>
        )}
        <span style={{ display: 'flex', alignItems: 'center', gap: 3, fontSize: 11, color: 'var(--text-muted)', flexShrink: 0 }}>
          <Clock size={10} />{timeAgo(alert.timestamp)}
        </span>
        {alert.hit_count > 1 && <span style={{ fontSize: 10, background: '#334155', color: 'var(--text-secondary)', borderRadius: 10, padding: '1px 6px' }}>×{alert.hit_count}</span>}
        {expanded ? <ChevronDown size={13} color="var(--text-muted)" /> : <ChevronRight size={13} color="var(--text-muted)" />}
      </div>

      {expanded && (
        <div style={{ padding: '0 14px 12px', borderTop: '1px solid var(--border)', paddingTop: 10 }}>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 11, color: '#a3e635', background: '#0a0f1e', padding: '8px 12px', borderRadius: 5, border: '1px solid #1e293b', marginBottom: 10, wordBreak: 'break-all' }}>
            <span style={{ color: '#475569', marginRight: 8 }}>$</span>{alert.event_message}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, fontSize: 12 }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {alert.mitre_tactic && <div><span style={{ color: 'var(--text-muted)' }}>Tactic: </span><span style={{ color: 'var(--text-primary)' }}>{alert.mitre_tactic}</span></div>}
              {alert.mitre_techniques?.length > 0 && <div><span style={{ color: 'var(--text-muted)' }}>Techniques: </span><span style={{ color: 'var(--accent-cyan)', fontFamily: 'var(--mono)', fontSize: 11 }}>{alert.mitre_techniques.join(', ')}</span></div>}
              {alert.anomaly_score > 0 && <div><span style={{ color: 'var(--text-muted)' }}>ML Score: </span><span style={{ color: '#4ade80', fontWeight: 600 }}>{alert.anomaly_score?.toFixed(3)}</span></div>}
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4, fontFamily: 'var(--mono)' }}>ID: {alert.alert_id?.slice(0, 16)}</div>
            </div>
            {alert.xai_features?.length > 0 && (
              <div>
                <div style={{ color: 'var(--text-muted)', marginBottom: 4 }}>XAI Drivers:</div>
                {alert.xai_features.slice(0, 4).map((f, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
                    <div style={{ height: 4, borderRadius: 2, width: `${Math.round(f.deviation * 80)}px`, background: 'var(--accent-cyan)', flexShrink: 0 }} />
                    <span style={{ fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--text-secondary)' }}>{f.feature}</span>
                  </div>
                ))}
              </div>
            )}
            {alert.chain_steps?.length > 0 && (
              <div>
                <div style={{ color: 'var(--text-muted)', marginBottom: 4 }}>Chain Steps:</div>
                {alert.chain_steps.map((s, i) => (
                  <div key={i} style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 2 }}>{i + 1}. [{s.step}] {s.message?.slice(0, 60)}</div>
                ))}
              </div>
            )}
          </div>
          <AIInlinePanel alertId={alert.alert_id} />
        </div>
      )}
    </div>
  )
}

export default function AlertFeedV5({ alerts }) {
  const [filter, setFilter] = useState('all')
  const [typeFilter, setTypeFilter] = useState('all')

  const filtered = alerts
    .filter(a => filter === 'all' || a.severity === filter)
    .filter(a => typeFilter === 'all' || a.alert_type === typeFilter)
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9))

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', gap: 6, marginBottom: 12, flexWrap: 'wrap', alignItems: 'center' }}>
        {['all','critical','high','medium','low'].map(s => (
          <button key={s} onClick={() => setFilter(s)} style={{ padding: '4px 12px', borderRadius: 5, border: '1px solid var(--border)', background: filter === s ? 'var(--bg-card)' : 'transparent', color: filter === s ? 'var(--text-primary)' : 'var(--text-muted)', cursor: 'pointer', fontSize: 12, textTransform: 'capitalize', fontWeight: filter === s ? 600 : 400 }}>{s}</button>
        ))}
        <div style={{ width: 1, background: 'var(--border)', height: 16, margin: '0 2px' }} />
        {['all','sigma','correlation','ml'].map(t => (
          <button key={t} onClick={() => setTypeFilter(t)} style={{ padding: '4px 12px', borderRadius: 5, border: '1px solid var(--border)', background: typeFilter === t ? 'var(--bg-card)' : 'transparent', color: typeFilter === t ? 'var(--text-primary)' : 'var(--text-muted)', cursor: 'pointer', fontSize: 12, textTransform: 'capitalize', fontWeight: typeFilter === t ? 600 : 400 }}>{t}</button>
        ))}
        <span style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-muted)' }}>{filtered.length} alerts</span>
      </div>
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {filtered.length === 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '60%', color: 'var(--text-muted)', gap: 10 }}>
            <AlertTriangle size={32} style={{ opacity: 0.2 }} />
            <div style={{ fontSize: 14 }}>No alerts yet</div>
            <div style={{ fontSize: 12 }}>Run: <code style={{ fontFamily: 'var(--mono)', color: 'var(--accent-cyan)' }}>bash examples/send_kill_chain.sh</code></div>
          </div>
        ) : filtered.map(a => <AlertCard key={a.alert_id} alert={a} />)}
      </div>
    </div>
  )
}
