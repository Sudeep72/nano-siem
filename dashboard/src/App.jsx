import { useState } from 'react'
import { useWebSocket } from './hooks/useWebSocket'
import { useHealth } from './hooks/useApi'
import StatsBar from './components/StatsBar'
import AlertFeedV5 from './components/AlertFeedV5'
import EventStream from './components/EventStream'
import RulesPanel from './components/RulesPanel'
import CoveragePanel from './components/CoveragePanel'
import AIAnalyst from './components/AIAnalyst'
import ThreatMap from './components/ThreatMap'
import IncidentPanel from './components/IncidentPanel'
import KnowledgeGraphPanel from './components/KnowledgeGraphPanel'
import ReplayPanel from './components/ReplayPanel'
import Sidebar from './components/Sidebar'

const TABS = [
  'Alerts', 'Events', 'Rules', 'ATT&CK Coverage', 'AI Analyst',
  'Threat Map', 'Incidents', 'Knowledge Graph', 'Replay',
]

export default function App() {
  const [activeTab, setActiveTab] = useState('Alerts')
  const { connected, events, alerts, stats } = useWebSocket()
  const health = useHealth()

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden', background: 'var(--bg-primary)' }}>
      <Sidebar
        activeTab={activeTab}
        onTab={setActiveTab}
        tabs={TABS}
        connected={connected}
        health={health}
      />

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', minWidth: 0 }}>
        <StatsBar stats={stats} alertCount={alerts.length} />

        <div style={{
          flex: 1, overflow: 'hidden',
          padding: '16px 20px',
        }}>
          {activeTab === 'Alerts'          && <AlertFeedV5 alerts={alerts} />}
          {activeTab === 'Events'          && <EventStream events={events} />}
          {activeTab === 'Rules'           && <RulesPanel />}
          {activeTab === 'ATT&CK Coverage' && <CoveragePanel />}
          {activeTab === 'AI Analyst'      && <AIAnalyst alerts={alerts} />}
          {activeTab === 'Threat Map'      && <ThreatMap alerts={alerts} />}
          {activeTab === 'Incidents'       && <IncidentPanel alerts={alerts} />}
          {activeTab === 'Knowledge Graph' && <KnowledgeGraphPanel />}
          {activeTab === 'Replay'          && <ReplayPanel alerts={alerts} />}
        </div>
      </div>
    </div>
  )
}
