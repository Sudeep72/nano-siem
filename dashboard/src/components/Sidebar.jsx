import { Bell, Activity, BookOpen, Target, Brain, Globe, FolderOpen, Network, Play, Shield } from 'lucide-react'

const ICONS = {
  'Alerts': Bell,
  'Events': Activity,
  'Rules': BookOpen,
  'ATT&CK Coverage': Target,
  'AI Analyst': Brain,
  'Threat Map': Globe,
  'Incidents': FolderOpen,
  'Knowledge Graph': Network,
  'Replay': Play,
}

const GROUPS = [
  { label: 'Detection', tabs: ['Alerts', 'Events', 'Rules', 'ATT&CK Coverage'] },
  { label: 'AI & Analysis', tabs: ['AI Analyst', 'Knowledge Graph', 'Replay'] },
  { label: 'Operations', tabs: ['Threat Map', 'Incidents'] },
]

export default function Sidebar({ activeTab, onTab, tabs, connected, health }) {
  return (
    <div style={{
      width: 200,
      flexShrink: 0,
      background: '#0a0f1e',
      borderRight: '1px solid var(--border)',
      display: 'flex',
      flexDirection: 'column',
      overflow: 'hidden',
    }}>
      {/* Logo */}
      <div style={{
        padding: '16px 16px 12px',
        borderBottom: '1px solid var(--border)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
          <div style={{
            width: 32, height: 32, borderRadius: 8,
            background: 'linear-gradient(135deg, #06b6d4, #2563eb)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            flexShrink: 0,
          }}>
            <Shield size={16} color="#fff" />
          </div>
          <div>
            <div style={{ fontWeight: 800, fontSize: 15, color: 'var(--text-primary)', letterSpacing: '-0.3px' }}>
              NanoSIEM
            </div>
            <div style={{ fontSize: 10, color: 'var(--accent-cyan)', fontWeight: 500 }}>
              Analyst Operations
            </div>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, overflowY: 'auto', padding: '8px 8px' }}>
        {GROUPS.map(group => (
          <div key={group.label} style={{ marginBottom: 4 }}>
            <div style={{
              fontSize: 9, fontWeight: 700, color: 'var(--text-muted)',
              textTransform: 'uppercase', letterSpacing: '0.8px',
              padding: '8px 8px 4px',
            }}>
              {group.label}
            </div>
            {group.tabs.filter(t => tabs.includes(t)).map(tab => {
              const Icon = ICONS[tab] || Bell
              const active = activeTab === tab
              return (
                <button
                  key={tab}
                  onClick={() => onTab(tab)}
                  style={{
                    width: '100%', display: 'flex', alignItems: 'center', gap: 9,
                    padding: '7px 10px', borderRadius: 7, border: 'none',
                    background: active ? '#06b6d411' : 'transparent',
                    color: active ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                    cursor: 'pointer', textAlign: 'left',
                    fontWeight: active ? 600 : 400, fontSize: 12,
                    transition: 'all 0.1s',
                    borderLeft: active ? '2px solid var(--accent-cyan)' : '2px solid transparent',
                  }}
                >
                  <Icon size={14} style={{ flexShrink: 0 }} />
                  {tab}
                </button>
              )
            })}
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div style={{
        borderTop: '1px solid var(--border)',
        padding: '10px 14px',
        fontSize: 11,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
          <div style={{
            width: 6, height: 6, borderRadius: '50%',
            background: connected ? '#22c55e' : '#ef4444',
            boxShadow: connected ? '0 0 6px #22c55e88' : 'none',
            flexShrink: 0,
            animation: connected ? 'pulse-dot 2s ease infinite' : 'none',
          }} />
          <span style={{ color: connected ? '#86efac' : '#fca5a5', fontWeight: 500 }}>
            {connected ? 'Live' : 'Disconnected'}
          </span>
        </div>
        {health && (
          <div style={{ color: 'var(--text-muted)', lineHeight: 1.7 }}>
            <div>Rules: <span style={{ color: 'var(--text-secondary)' }}>{health.rules_loaded ?? '—'}</span></div>
            <div>Uptime: <span style={{ color: 'var(--text-secondary)' }}>{health.uptime_seconds != null ? `${Math.round(health.uptime_seconds)}s` : '—'}</span></div>
            <div>Version: <span style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>{health.version ?? '—'}</span></div>
          </div>
        )}
      </div>
    </div>
  )
}
