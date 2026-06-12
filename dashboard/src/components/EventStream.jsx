import { useState } from 'react'
import { Activity } from 'lucide-react'

function sev(s) {
  if (!s) return 'var(--text-muted)'
  const m = { emerg:'var(--sev-critical)', alert:'var(--sev-critical)', crit:'var(--sev-critical)',
               err:'var(--sev-high)', warning:'var(--sev-medium)', notice:'var(--sev-low)',
               info:'var(--text-muted)', debug:'var(--text-muted)' }
  return m[s.toLowerCase()] || 'var(--text-muted)'
}

function formatTs(ts) {
  try {
    return new Date(ts).toLocaleTimeString('en-US', { hour12: false })
  } catch { return ts?.slice(11, 19) || '' }
}

export default function EventStream({ events }) {
  const [search, setSearch] = useState('')
  const [showAnomalous, setShowAnomalous] = useState(false)

  const filtered = events
    .filter(e => !search || e.message?.toLowerCase().includes(search.toLowerCase())
                          || e.host?.toLowerCase().includes(search.toLowerCase())
                          || e.source_ip?.includes(search))
    .filter(e => !showAnomalous || (e.anomaly_score != null && e.anomaly_score >= 0.62))

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Controls */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 12, alignItems: 'center' }}>
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search host, IP, message..."
          style={{
            flex: 1, padding: '6px 12px',
            background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 4, color: 'var(--text-primary)', fontSize: 12,
            outline: 'none',
          }}
        />
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12,
                        color: 'var(--text-secondary)', cursor: 'pointer', whiteSpace: 'nowrap' }}>
          <input type="checkbox" checked={showAnomalous}
                 onChange={e => setShowAnomalous(e.target.checked)} />
          ML anomalous only
        </label>
        <span style={{ fontSize: 12, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
          {filtered.length} / {events.length}
        </span>
      </div>

      {/* Table header */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '70px 90px 130px 110px 80px 80px 1fr 70px',
        gap: 8, padding: '6px 10px',
        background: 'var(--bg-secondary)', borderRadius: '4px 4px 0 0',
        fontSize: 10, color: 'var(--text-muted)', fontWeight: 600,
        letterSpacing: '0.5px', textTransform: 'uppercase',
      }}>
        <span>Time</span><span>Format</span><span>Source IP</span>
        <span>Host</span><span>Program</span><span>Severity</span>
        <span>Message</span><span>ML Score</span>
      </div>

      {/* Rows */}
      <div style={{ flex: 1, overflowY: 'auto', background: 'var(--bg-card)',
                    border: '1px solid var(--border)', borderTop: 'none', borderRadius: '0 0 4px 4px' }}>
        {filtered.length === 0 ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center',
                        height: 200, color: 'var(--text-muted)', gap: 8 }}>
            <Activity size={16} />
            <span>Waiting for events...</span>
          </div>
        ) : (
          filtered.map((event, i) => {
            const hasAlert  = event.alert_count > 0 || event.sigma_matches?.length > 0 || event.chain_alerts?.length > 0
            const anomalous = event.is_anomalous || (event.anomaly_score >= 0.62)
            return (
              <div
                key={event.event_id || i}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '70px 90px 130px 110px 80px 80px 1fr 70px',
                  gap: 8, padding: '5px 10px',
                  borderBottom: '1px solid #1e293b',
                  background: hasAlert ? '#1a1232' : anomalous ? '#0a1f0a' : 'transparent',
                  fontSize: 11, fontFamily: 'var(--mono)',
                  alignItems: 'center',
                }}
              >
                <span style={{ color: 'var(--text-muted)' }}>{formatTs(event.timestamp)}</span>
                <span style={{ color: 'var(--text-secondary)', fontSize: 10 }}>{event.log_source}</span>
                <span style={{ color: 'var(--accent-cyan)' }}>{event.source_ip || '—'}</span>
                <span style={{ color: 'var(--text-secondary)' }}>{event.host}</span>
                <span style={{ color: 'var(--text-primary)' }}>{event.program || '—'}</span>
                <span style={{ color: sev(event.severity) }}>{event.severity || '—'}</span>
                <span style={{
                  color: hasAlert ? '#c4b5fd' : 'var(--text-secondary)',
                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                }} title={event.message}>
                  {event.sigma_matches?.length > 0 && (
                    <span style={{ color: '#a78bfa', marginRight: 4 }}>⚡</span>
                  )}
                  {event.chain_alerts?.length > 0 && (
                    <span style={{ color: '#38bdf8', marginRight: 4 }}>🔗</span>
                  )}
                  {event.message}
                </span>
                <span style={{
                  color: anomalous ? '#4ade80' : 'var(--text-muted)',
                  fontWeight: anomalous ? 700 : 400,
                }}>
                  {event.anomaly_score != null ? event.anomaly_score.toFixed(3) : '—'}
                </span>
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}
