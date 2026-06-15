import { useState } from 'react'
import { useWebSocket } from './hooks/useWebSocket'
import { useHealth } from './hooks/useApi'
import StatsBar from './components/StatsBar'
import AlertFeedV4 from './components/AlertFeedV4'
import EventStream from './components/EventStream'
import RulesPanel from './components/RulesPanel'
import CoveragePanel from './components/CoveragePanel'
import AIAnalyst from './components/AIAnalyst'
import Sidebar from './components/Sidebar'

const TABS = ['Alerts', 'Events', 'Rules', 'ATT&CK Coverage', 'AI Analyst']

export default function App() {
  const [activeTab, setActiveTab] = useState('Alerts')
  const { connected, events, alerts, stats } = useWebSocket()
  const health = useHealth()

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
      <Sidebar activeTab={activeTab} onTab={setActiveTab} tabs={TABS} connected={connected} health={health} />

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {/* Top bar */}
        <div style={{
          padding: '12px 20px',
          borderBottom: '1px solid var(--border)',
          background: 'var(--bg-secondary)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{ fontSize: 18, fontWeight: 700, color: 'var(--accent-cyan)' }}>NanoSIEM</span>
            <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>v4.0 · AI Reasoning Edition</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{
              width: 8, height: 8, borderRadius: '50%',
              background: connected ? 'var(--green)' : 'var(--red)',
              boxShadow: connected ? '0 0 6px var(--green)' : 'none',
            }} />
            <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              {connected ? 'Live' : 'Disconnected'}
            </span>
          </div>
        </div>

        <StatsBar stats={stats} alertCount={alerts.length} />

        <div style={{ flex: 1, overflow: 'hidden', padding: '16px 20px' }}>
          {activeTab === 'Alerts'          && <AlertFeedV4 alerts={alerts} />}
          {activeTab === 'Events'          && <EventStream events={events} />}
          {activeTab === 'Rules'           && <RulesPanel />}
          {activeTab === 'ATT&CK Coverage' && <CoveragePanel />}
          {activeTab === 'AI Analyst'      && <AIAnalyst alerts={alerts} />}
        </div>
      </div>
    </div>
  )
}
