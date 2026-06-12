import { Zap, AlertTriangle, Link, Brain, Copy, TrendingUp } from 'lucide-react'

function Stat({ icon: Icon, label, value, color = 'var(--text-primary)', dim = false }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 8,
      padding: '8px 16px',
      borderRight: '1px solid var(--border)',
    }}>
      <Icon size={14} color={dim ? 'var(--text-muted)' : color} />
      <div>
        <div style={{ fontSize: 18, fontWeight: 700, color: dim ? 'var(--text-muted)' : color, lineHeight: 1 }}>
          {value}
        </div>
        <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>{label}</div>
      </div>
    </div>
  )
}

export default function StatsBar({ stats, alertCount }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center',
      background: 'var(--bg-secondary)',
      borderBottom: '1px solid var(--border)',
      overflowX: 'auto',
    }}>
      <Stat icon={TrendingUp} label="EVENTS/SEC" value={stats.events_per_sec?.toFixed(1) ?? '0.0'} color="var(--accent-cyan)" />
      <Stat icon={Zap}         label="SIGMA HITS"   value={stats.sigma_hits ?? 0}     color="#a78bfa" />
      <Stat icon={Link}        label="CHAIN ALERTS" value={stats.chain_alerts ?? 0}   color="#38bdf8" />
      <Stat icon={Brain}       label="ML ANOMALIES" value={stats.ml_anomalies ?? 0}   color="#4ade80" />
      <Stat icon={AlertTriangle} label="ALERTS"     value={alertCount}                color="var(--sev-high)" />
      <Stat icon={Copy}        label="DEDUPED"      value={stats.deduped ?? 0}        dim />
      <div style={{ padding: '8px 16px', marginLeft: 'auto' }}>
        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          {stats.events_processed?.toLocaleString() ?? 0} total events ·{' '}
          {stats.tracked_sources ?? 0} sources ·{' '}
          ML avg {stats.ml_avg_score?.toFixed(3) ?? '0.000'}
        </div>
      </div>
    </div>
  )
}
