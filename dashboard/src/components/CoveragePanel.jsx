import { useCoverage } from '../hooks/useApi'
import { Target, ExternalLink } from 'lucide-react'

const TACTIC_ORDER = [
  'Initial Access','Execution','Persistence','Privilege Escalation',
  'Defense Evasion','Credential Access','Discovery','Lateral Movement',
  'Collection','Command and Control','Exfiltration','Impact',
]

const TACTIC_COLOR = {
  'Initial Access':          '#f97316',
  'Execution':               '#ef4444',
  'Persistence':             '#a78bfa',
  'Privilege Escalation':    '#f43f5e',
  'Defense Evasion':         '#6366f1',
  'Credential Access':       '#ec4899',
  'Discovery':               '#eab308',
  'Lateral Movement':        '#14b8a6',
  'Collection':              '#06b6d4',
  'Command and Control':     '#3b82f6',
  'Exfiltration':            '#8b5cf6',
  'Impact':                  '#ef4444',
}

function CoverageBar({ percent }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
      <div style={{
        flex: 1, height: 8, background: 'var(--bg-card)',
        borderRadius: 4, overflow: 'hidden', border: '1px solid var(--border)',
      }}>
        <div style={{
          height: '100%', borderRadius: 4,
          width: `${percent}%`,
          background: 'linear-gradient(90deg, var(--accent-cyan), #3b82f6)',
          transition: 'width 0.5s ease',
        }} />
      </div>
      <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--accent-cyan)', minWidth: 45 }}>
        {percent?.toFixed(1)}%
      </span>
    </div>
  )
}

export default function CoveragePanel() {
  const coverage = useCoverage()

  if (!coverage) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center',
                  height: '60%', color: 'var(--text-muted)', gap: 8 }}>
      <Target size={16} />
      <span>Loading coverage data...</span>
    </div>
  )

  const orderedTactics = [
    ...TACTIC_ORDER.filter(t => coverage.tactics[t]),
    ...Object.keys(coverage.tactics).filter(t => !TACTIC_ORDER.includes(t)),
  ]

  return (
    <div style={{ height: '100%', overflowY: 'auto' }}>

      {/* Summary header */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
          <Target size={16} color="var(--accent-cyan)" />
          <h2 style={{ fontSize: 14, fontWeight: 600 }}>MITRE ATT&CK Coverage</h2>
        </div>

        <CoverageBar percent={coverage.coverage_percent} />

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
          {[
            { label: 'Rules', value: coverage.total_rules, color: '#a78bfa' },
            { label: 'Chains', value: coverage.total_chains, color: '#38bdf8' },
            { label: 'Techniques Covered', value: coverage.techniques_covered, color: 'var(--green)' },
            { label: 'Known Techniques', value: coverage.techniques_known, color: 'var(--text-muted)' },
          ].map(s => (
            <div key={s.label} style={{
              background: 'var(--bg-secondary)', borderRadius: 6,
              padding: '10px 14px', border: '1px solid var(--border)',
            }}>
              <div style={{ fontSize: 22, fontWeight: 700, color: s.color }}>{s.value}</div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{s.label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Tactic breakdown */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: 12 }}>
        {orderedTactics.map(tactic => {
          const entries = coverage.tactics[tactic] || []
          const color = TACTIC_COLOR[tactic] || 'var(--accent-cyan)'
          return (
            <div key={tactic} className="card">
              <div style={{
                display: 'flex', alignItems: 'center', gap: 8,
                marginBottom: 10, paddingBottom: 8,
                borderBottom: '1px solid var(--border)',
              }}>
                <div style={{
                  width: 10, height: 10, borderRadius: '50%',
                  background: color, flexShrink: 0,
                }} />
                <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)' }}>
                  {tactic}
                </span>
                <span style={{
                  marginLeft: 'auto', fontSize: 11,
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                  borderRadius: 10, padding: '1px 8px',
                  color: 'var(--text-secondary)',
                }}>
                  {entries.length}
                </span>
              </div>

              {entries.map(entry => (
                <div key={entry.technique_id} style={{
                  display: 'flex', gap: 8, marginBottom: 6,
                  alignItems: 'flex-start',
                }}>
                  <a
                    href={`https://attack.mitre.org/techniques/${entry.technique_id.replace('.','/')}`}
                    target="_blank" rel="noreferrer"
                    style={{
                      fontSize: 10, fontFamily: 'var(--mono)',
                      color, textDecoration: 'none', flexShrink: 0,
                      background: `${color}11`,
                      border: `1px solid ${color}44`,
                      borderRadius: 3, padding: '1px 5px',
                      display: 'flex', alignItems: 'center', gap: 3,
                    }}
                  >
                    {entry.technique_id}
                    <ExternalLink size={8} />
                  </a>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 12, color: 'var(--text-primary)' }}>
                      {entry.technique_name}
                    </div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
                      {[
                        ...entry.covered_by_rules.map(r => `Rule: ${r}`),
                        ...entry.covered_by_chains.map(c => `Chain: ${c}`),
                      ].join(' · ')}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )
        })}
      </div>
    </div>
  )
}
