import { Activity, Zap, Link, Brain, Bell, Copy } from 'lucide-react'

function Stat({ icon: Icon, label, value, color }) {
  const num = parseFloat(value) || 0
  const isZero = num === 0
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '0 18px', borderRight: '1px solid var(--border)' }}>
      <div style={{ width: 30, height: 30, borderRadius: 7, background: `${color}${isZero ? '11' : '18'}`, border: `1px solid ${color}${isZero ? '22' : '33'}`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
        <Icon size={13} color={isZero ? `${color}44` : color} />
      </div>
      <div>
        <div style={{ fontSize: 17, fontWeight: 700, color: isZero ? '#475569' : color, lineHeight: 1 }}>
          {typeof value === 'number' ? value.toLocaleString() : value}
        </div>
        <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginTop: 2 }}>{label}</div>
      </div>
    </div>
  )
}

export default function StatsBar({ stats = {}, alertCount = 0 }) {
  // Correct keys from pipeline.py: events_processed, sigma_hits, chain_alerts,
  // ml_anomalies, deduped, events_per_sec, ml_avg_score
  const total   = stats.events_processed ?? 0
  const sigma   = stats.sigma_hits       ?? 0
  const chain   = stats.chain_alerts     ?? 0
  const ml      = stats.ml_anomalies     ?? 0
  const deduped = stats.deduped          ?? 0
  const eps     = stats.events_per_sec   ?? 0

  return (
    <div style={{ display: 'flex', alignItems: 'center', background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)', height: 54, overflowX: 'auto' }}>
      <Stat icon={Activity} label="Events/sec"     value={eps.toFixed(1)} color="#06b6d4" />
      <Stat icon={Zap}      label="Sigma Hits"     value={sigma}          color="#a78bfa" />
      <Stat icon={Link}     label="Chain Alerts"   value={chain}          color="#38bdf8" />
      <Stat icon={Brain}    label="ML Anomalies"   value={ml}             color="#4ade80" />
      <Stat icon={Bell}     label="Alerts"         value={alertCount}     color="#f97316" />
      <Stat icon={Copy}     label="Deduped"        value={deduped}        color="#6b7280" />
      <div style={{ marginLeft: 'auto', padding: '0 18px', fontSize: 11, color: '#475569', whiteSpace: 'nowrap' }}>
        {total > 0
          ? <span style={{ color: '#334155' }}>{total.toLocaleString()} events ingested · ML avg {(stats.ml_avg_score ?? 0).toFixed(3)}</span>
          : <span>Run: <code style={{ fontFamily: 'var(--mono)', color: '#06b6d4' }}>bash examples/send_kill_chain.sh</code></span>
        }
      </div>
    </div>
  )
}
