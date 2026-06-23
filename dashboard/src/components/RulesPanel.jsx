import { useRules, useChains } from '../hooks/useApi'
import { BookOpen, Link, Shield } from 'lucide-react'

const LEVEL_COLOR = {
  critical: 'var(--sev-critical)', high: 'var(--sev-high)',
  medium: 'var(--sev-medium)', low: 'var(--sev-low)',
  informational: 'var(--text-muted)',
}

export default function RulesPanel() {
  const { rules, loading } = useRules()
  const chains = useChains()

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center',
                  height: '60%', color: 'var(--text-muted)' }}>
      Loading rules...
    </div>
  )

  return (
    <div style={{ height: '100%', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 20 }}>

      {/* Sigma Rules */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
          <BookOpen size={16} color="var(--accent-cyan)" />
          <h2 style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>
            Sigma Rules
          </h2>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>({rules.length} loaded)</span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {rules.map(rule => (
            <div key={rule.id || rule.title} className="card" style={{ padding: '10px 14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <Shield size={12} color={LEVEL_COLOR[rule.level] || 'var(--text-muted)'} />
                <span className={`badge badge-${rule.level}`}>{rule.level?.toUpperCase()}</span>
                <span style={{ flex: 1, fontWeight: 600, fontSize: 13 }}>{rule.title}</span>
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{rule.status}</span>
                <span style={{ fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                  {rule.source_file}
                </span>
              </div>
              {(rule.mitre_techniques?.length > 0 || rule.description) && (
                <div style={{ marginTop: 6, paddingLeft: 22 }}>
                  {rule.description && (
                    <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 4 }}>
                      {rule.description.slice(0, 120)}{rule.description.length > 120 ? '…' : ''}
                    </div>
                  )}
                  {rule.mitre_techniques?.length > 0 && (
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                      {rule.mitre_techniques.map(t => (
                        <a
                          key={t}
                          href={`https://attack.mitre.org/techniques/${t.replace('attack.','').toUpperCase().replace('.','/').replace('T','T')}`}
                          target="_blank"
                          rel="noreferrer"
                          style={{
                            fontSize: 10, fontFamily: 'var(--mono)',
                            color: 'var(--accent-cyan)',
                            textDecoration: 'none',
                            background: '#0c4a6e22',
                            padding: '1px 6px', borderRadius: 3,
                            border: '1px solid #0c4a6e',
                          }}
                        >
                          {t.replace('attack.', '').toUpperCase()}
                        </a>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Correlation Chains */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
          <Link size={16} color="var(--accent-cyan)" />
          <h2 style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>
            Correlation Chains
          </h2>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>({chains.length} built-in)</span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {chains.map(chain => (
            <div key={chain.id} className="card" style={{ padding: '10px 14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span className={`badge badge-${chain.severity}`}>{chain.severity?.toUpperCase()}</span>
                <span style={{ flex: 1, fontWeight: 600, fontSize: 13 }}>{chain.title}</span>
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{chain.window_seconds}s window</span>
              </div>
              <div style={{ marginTop: 6, paddingLeft: 4 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                  {chain.steps?.map((step, i) => (
                    <span key={i} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                      <span style={{
                        fontSize: 10, background: 'var(--bg-secondary)',
                        border: '1px solid var(--border)',
                        borderRadius: 3, padding: '1px 6px',
                        color: 'var(--text-secondary)', fontFamily: 'var(--mono)',
                      }}>{step}</span>
                      {i < chain.steps.length - 1 && (
                        <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>→</span>
                      )}
                    </span>
                  ))}
                </div>
                {chain.mitre_tactic && (
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                    {chain.mitre_tactic}
                    {chain.mitre_techniques?.length > 0 && (
                      <span style={{ fontFamily: 'var(--mono)', color: 'var(--accent-cyan)', marginLeft: 8 }}>
                        {chain.mitre_techniques.join(' · ')}
                      </span>
                    )}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
