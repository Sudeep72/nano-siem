import { useState } from 'react'
import { AlertTriangle, Link, Brain, ChevronDown, ChevronRight, Clock, Sparkles, Loader } from 'lucide-react'

const API = 'http://localhost:8000'
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 }
const TYPE_ICON = { sigma: AlertTriangle, correlation: Link, ml: Brain }
const TYPE_COLOR = { sigma: '#a78bfa', correlation: '#38bdf8', ml: '#4ade80' }

function timeAgo(ts) {
  const diff = Date.now() / 1000 - ts
  if (diff < 60) return `${Math.floor(diff)}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  return `${Math.floor(diff / 3600)}h ago`
}

function AIInlinePanel({ alertId }) {
  const [mode, setMode]       = useState(null)   // 'explain' | 'recommend' | 'mitre'
  const [loading, setLoading] = useState(false)
  const [result, setResult]   = useState(null)
  const [error, setError]     = useState(null)

  const run = async (task) => {
    if (mode === task && result) { setMode(null); setResult(null); return }
    setMode(task)
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const res = await fetch(`${API}/api/ai/${task}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ alert_id: alertId }),
      })
      const data = await res.json()
      if (!res.ok || data.error) throw new Error(data.detail || data.error || `HTTP ${res.status}`)
      setResult(data.content)
    } catch(e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  const BTN_STYLE = (active) => ({
    display: 'flex', alignItems: 'center', gap: 4,
    padding: '3px 8px', borderRadius: 4, border: '1px solid',
    borderColor: active ? 'var(--accent-cyan)' : 'var(--border)',
    background: active ? '#0c4a6e33' : 'transparent',
    color: active ? 'var(--accent-cyan)' : 'var(--text-muted)',
    cursor: 'pointer', fontSize: 11, fontWeight: 500,
  })

  return (
    <div style={{ marginTop: 8, paddingTop: 8, borderTop: '1px solid #1e293b' }}>
      <div style={{ display: 'flex', gap: 6, marginBottom: loading || result || error ? 10 : 0 }}>
        <Sparkles size={12} color="var(--accent-cyan)" style={{ alignSelf: 'center' }} />
        <span style={{ fontSize: 10, color: 'var(--text-muted)', marginRight: 4, alignSelf: 'center' }}>AI:</span>
        {[
          { id: 'explain',   label: 'Explain' },
          { id: 'recommend', label: 'Actions' },
          { id: 'mitre',     label: 'ATT&CK' },
        ].map(btn => (
          <button key={btn.id} onClick={() => run(btn.id)} style={BTN_STYLE(mode === btn.id && (result || loading))}>
            {loading && mode === btn.id
              ? <Loader size={10} style={{ animation: 'spin 1s linear infinite' }} />
              : null}
            {btn.label}
          </button>
        ))}
      </div>

      {(loading || result || error) && (
        <div style={{
          background: 'var(--bg-primary)', borderRadius: 4,
          padding: '10px 12px', fontSize: 12, lineHeight: 1.7,
          border: '1px solid var(--border)',
          maxHeight: 300, overflowY: 'auto',
        }}>
          {loading && (
            <span style={{ color: 'var(--text-muted)' }}>Gemini is reasoning...</span>
          )}
          {error && (
            <span style={{ color: 'var(--sev-critical)' }}>
              {error.includes('API key') ? '⚠ GEMINI_API_KEY not set — run: export GEMINI_API_KEY=your_key' : error}
            </span>
          )}
          {result && (
            <div style={{ color: 'var(--text-secondary)', whiteSpace: 'pre-wrap', fontFamily: 'inherit' }}>
              {result.split('\n').map((line, i) => {
                if (line.startsWith('### ')) return <div key={i} style={{ fontWeight: 700, color: 'var(--accent-cyan)', margin: '10px 0 4px', fontSize: 12 }}>{line.slice(4)}</div>
                if (line.startsWith('## '))  return <div key={i} style={{ fontWeight: 700, color: 'var(--text-primary)', margin: '12px 0 4px', borderBottom: '1px solid var(--border)', paddingBottom: 3 }}>{line.slice(3)}</div>
                if (line.startsWith('- ') || line.startsWith('* ')) return <div key={i} style={{ display: 'flex', gap: 6, margin: '2px 0 2px 8px' }}><span style={{ color: 'var(--accent-cyan)' }}>•</span><span>{line.slice(2)}</span></div>
                if (line === '') return <div key={i} style={{ height: 6 }} />
                if (line === '---') return <hr key={i} style={{ border: 'none', borderTop: '1px solid var(--border)', margin: '8px 0' }} />
                // Handle **bold**
                const parts = line.split(/(\*\*[^*]+\*\*)/)
                return <div key={i}>{parts.map((p, j) => p.startsWith('**') ? <strong key={j} style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{p.slice(2,-2)}</strong> : p)}</div>
              })}
            </div>
          )}
        </div>
      )}
      <style>{`@keyframes spin { from { transform: rotate(0deg) } to { transform: rotate(360deg) } }`}</style>
    </div>
  )
}

function AlertCard({ alert }) {
  const [expanded, setExpanded] = useState(false)
  const [showAI, setShowAI]     = useState(false)
  const Icon   = TYPE_ICON[alert.alert_type] || AlertTriangle
  const color  = TYPE_COLOR[alert.alert_type] || '#94a3b8'
  const sev    = alert.severity?.toLowerCase()
  const sevBorderColor = sev === 'critical' ? 'var(--sev-critical)' :
                         sev === 'high'     ? 'var(--sev-high)'     :
                         sev === 'medium'   ? 'var(--sev-medium)'   : 'var(--sev-low)'

  return (
    <div style={{
      background: 'var(--bg-card)', border: `1px solid var(--border)`,
      borderLeft: `3px solid ${sevBorderColor}`,
      borderRadius: 6, marginBottom: 8, overflow: 'hidden',
    }}>
      {/* Header */}
      <div onClick={() => setExpanded(e => !e)} style={{
        display: 'flex', alignItems: 'center', gap: 10,
        padding: '10px 14px', cursor: 'pointer',
      }}>
        <Icon size={14} color={color} style={{ flexShrink: 0 }} />
        <span className={`badge badge-${sev}`}>{sev?.toUpperCase()}</span>
        <span className={`badge badge-${alert.alert_type}`}>{alert.alert_type?.toUpperCase()}</span>
        <span style={{ flex: 1, fontWeight: 600, fontSize: 13 }}>{alert.title}</span>
        {alert.source_key && (
          <span style={{ fontSize: 11, fontFamily: 'var(--mono)', color: 'var(--accent-cyan)', flexShrink: 0 }}>
            {alert.source_key}
          </span>
        )}
        <span style={{ display: 'flex', alignItems: 'center', gap: 3, fontSize: 11, color: 'var(--text-muted)', flexShrink: 0 }}>
          <Clock size={10} />{timeAgo(alert.timestamp)}
        </span>
        {alert.hit_count > 1 && (
          <span style={{ fontSize: 10, background: '#334155', color: 'var(--text-secondary)', borderRadius: 10, padding: '1px 6px' }}>
            ×{alert.hit_count}
          </span>
        )}
        {expanded ? <ChevronDown size={14} color="var(--text-muted)" /> : <ChevronRight size={14} color="var(--text-muted)" />}
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div style={{ padding: '0 14px 12px', borderTop: '1px solid var(--border)', paddingTop: 10 }}>
          {/* Log message */}
          <div style={{
            fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-secondary)',
            background: 'var(--bg-primary)', padding: '6px 10px', borderRadius: 4, marginBottom: 10,
            wordBreak: 'break-all',
          }}>
            {alert.event_message}
          </div>

          {/* Metadata grid */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, fontSize: 12, marginBottom: 10 }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {alert.mitre_tactic && (
                <div><span style={{ color: 'var(--text-muted)' }}>Tactic: </span>
                  <span>{alert.mitre_tactic}</span></div>
              )}
              {alert.mitre_techniques?.length > 0 && (
                <div><span style={{ color: 'var(--text-muted)' }}>Techniques: </span>
                  <span style={{ color: 'var(--accent-cyan)', fontFamily: 'var(--mono)', fontSize: 11 }}>
                    {alert.mitre_techniques.join(', ')}
                  </span>
                </div>
              )}
              {alert.anomaly_score > 0 && (
                <div><span style={{ color: 'var(--text-muted)' }}>ML Score: </span>
                  <span style={{ color: '#4ade80', fontWeight: 600 }}>{alert.anomaly_score?.toFixed(3)}</span>
                </div>
              )}
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4, fontFamily: 'var(--mono)' }}>
                ID: {alert.alert_id?.slice(0, 16)}
              </div>
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
                {alert.chain_steps.map((step, i) => (
                  <div key={i} style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 2 }}>
                    {i + 1}. [{step.step}] {step.message?.slice(0, 60)}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* AI inline panel */}
          <AIInlinePanel alertId={alert.alert_id} />
        </div>
      )}
    </div>
  )
}

export default function AlertFeedV4({ alerts }) {
  const [filter, setFilter]     = useState('all')
  const [typeFilter, setTypeFilter] = useState('all')

  const filtered = alerts
    .filter(a => filter === 'all' || a.severity === filter)
    .filter(a => typeFilter === 'all' || a.alert_type === typeFilter)
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9))

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
        {['all','critical','high','medium','low'].map(s => (
          <button key={s} onClick={() => setFilter(s)} style={{
            padding: '4px 12px', borderRadius: 4, border: '1px solid var(--border)',
            background: filter === s ? 'var(--bg-card-hover)' : 'transparent',
            color: filter === s ? 'var(--text-primary)' : 'var(--text-muted)',
            cursor: 'pointer', fontSize: 12, textTransform: 'capitalize',
          }}>{s}</button>
        ))}
        <div style={{ width: 1, background: 'var(--border)', margin: '0 4px' }} />
        {['all','sigma','correlation','ml'].map(t => (
          <button key={t} onClick={() => setTypeFilter(t)} style={{
            padding: '4px 12px', borderRadius: 4, border: '1px solid var(--border)',
            background: typeFilter === t ? 'var(--bg-card-hover)' : 'transparent',
            color: typeFilter === t ? 'var(--text-primary)' : 'var(--text-muted)',
            cursor: 'pointer', fontSize: 12, textTransform: 'capitalize',
          }}>{t}</button>
        ))}
        <span style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-muted)', alignSelf: 'center' }}>
          {filtered.length} alerts
        </span>
      </div>
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {filtered.length === 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center',
                        justifyContent: 'center', height: '60%', color: 'var(--text-muted)' }}>
            <AlertTriangle size={32} style={{ marginBottom: 12, opacity: 0.3 }} />
            <div style={{ fontSize: 14 }}>No alerts yet</div>
            <div style={{ fontSize: 12, marginTop: 6 }}>
              Run: <code style={{ fontFamily: 'var(--mono)', color: 'var(--accent-cyan)' }}>bash examples/send_kill_chain.sh</code>
            </div>
          </div>
        ) : filtered.map(a => <AlertCard key={a.alert_id} alert={a} />)}
      </div>
    </div>
  )
}
