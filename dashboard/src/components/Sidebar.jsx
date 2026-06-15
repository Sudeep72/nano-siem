import { Shield, Bell, Activity, BookOpen, Target, Brain } from 'lucide-react'

const ICONS = {
  'AI Analyst': Brain,
  'Alerts': Bell,
  'Events': Activity,
  'Rules': BookOpen,
  'ATT&CK Coverage': Target,
}

export default function Sidebar({ activeTab, onTab, tabs, connected, health }) {
  return (
    <div style={{
      width: 220, background: 'var(--bg-secondary)',
      borderRight: '1px solid var(--border)',
      display: 'flex', flexDirection: 'column',
      padding: '16px 0',
    }}>
      {/* Logo */}
      <div style={{ padding: '8px 20px 24px', display: 'flex', alignItems: 'center', gap: 10 }}>
        <Shield size={22} color="var(--accent-cyan)" />
        <div>
          <div style={{ fontWeight: 700, fontSize: 14, color: 'var(--text-primary)' }}>NanoSIEM</div>
          <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>Detection Platform</div>
        </div>
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, padding: '0 10px' }}>
        {tabs.map(tab => {
          const Icon = ICONS[tab] || Bell
          const active = activeTab === tab
          return (
            <button
              key={tab}
              onClick={() => onTab(tab)}
              style={{
                width: '100%', display: 'flex', alignItems: 'center', gap: 10,
                padding: '9px 12px', borderRadius: 6, border: 'none', cursor: 'pointer',
                background: active ? 'var(--bg-card)' : 'transparent',
                color: active ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                fontSize: 13, fontWeight: active ? 600 : 400,
                marginBottom: 2,
                transition: 'all 0.15s',
              }}
            >
              <Icon size={16} />
              {tab}
            </button>
          )
        })}
      </nav>

      {/* Health status */}
      {health && (
        <div style={{ padding: '16px 16px 0', borderTop: '1px solid var(--border)', marginTop: 8 }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8 }}>PIPELINE</div>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.8 }}>
            <div>Rules: <span style={{ color: 'var(--text-primary)' }}>{health.rules_loaded}</span></div>
            <div>Uptime: <span style={{ color: 'var(--text-primary)' }}>
              {Math.floor(health.uptime_seconds / 60)}m {Math.floor(health.uptime_seconds % 60)}s
            </span></div>
            <div>Version: <span style={{ color: 'var(--accent-cyan)' }}>{health.version}</span></div>
          </div>
        </div>
      )}
    </div>
  )
}
