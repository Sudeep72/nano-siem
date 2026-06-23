import { useState } from 'react'
import { Play, Clock, ChevronRight, ChevronLeft, Brain, CheckCircle } from 'lucide-react'

const API = 'http://localhost:8000'

const STEP_COLORS = { brute: '#ef4444', login: '#f97316', scan: '#eab308', priv: '#a78bfa', shell: '#ef4444', lateral: '#38bdf8' }

function stepColor(name) {
  const n = name.toLowerCase()
  if (n.includes('brute')) return STEP_COLORS.brute
  if (n.includes('login') || n.includes('success')) return STEP_COLORS.login
  if (n.includes('scan')) return STEP_COLORS.scan
  if (n.includes('priv') || n.includes('sudo')) return STEP_COLORS.priv
  if (n.includes('shell') || n.includes('reverse')) return STEP_COLORS.shell
  return '#06b6d4'
}

export default function ReplayPanel({ alerts }) {
  const [selectedAlertId, setSelectedAlertId] = useState('')
  const [session, setSession] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [currentStep, setCurrentStep] = useState(0)
  const [aiLoading, setAiLoading] = useState(false)
  const [aiStep, setAiStep] = useState(null)

  const corrAlerts = alerts.filter(a => a.alert_type === 'correlation' && a.chain_steps?.length > 0)

  const runReplay = async () => {
    if (!selectedAlertId) return
    setLoading(true); setError(null); setSession(null); setCurrentStep(0); setAiStep(null)
    try {
      const res = await fetch(`${API}/api/replay`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ alert_id: selectedAlertId, period: 'none' }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`)
      setSession(data)
    } catch(e) { setError(e.message) }
    finally { setLoading(false) }
  }

  const explainStep = async (stepIndex) => {
    setAiLoading(true); setAiStep(stepIndex)
    try {
      const res = await fetch(`${API}/api/ai/explain`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ alert_id: selectedAlertId }),
      })
      const data = await res.json()
      if (data.content) {
        setSession(prev => ({
          ...prev,
          steps: prev.steps.map((s, i) => i === stepIndex ? { ...s, commentary: data.content } : s)
        }))
      }
    } catch(e) { console.error(e) }
    finally { setAiLoading(false) }
  }

  const step = session?.steps[currentStep]

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Controls */}
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: '16px 20px', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
          <div style={{ width: 32, height: 32, borderRadius: 8, background: '#06b6d422', border: '1px solid #06b6d444', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Play size={14} color="var(--accent-cyan)" />
          </div>
          <div>
            <div style={{ fontWeight: 700, fontSize: 15, color: 'var(--text-primary)' }}>Attack Replay</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Step through correlation alert chains</div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <select value={selectedAlertId} onChange={e => setSelectedAlertId(e.target.value)}
            style={{ flex: 1, padding: '8px 12px', fontSize: 12, borderRadius: 6, background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: corrAlerts.length ? 'var(--text-primary)' : 'var(--text-muted)' }}>
            <option value="">{corrAlerts.length ? 'Select a correlation alert...' : 'No correlation alerts — run kill chain first'}</option>
            {corrAlerts.map(a => <option key={a.alert_id} value={a.alert_id}>[{a.severity?.toUpperCase()}] {a.title} ({a.chain_steps?.length} steps)</option>)}
          </select>
          <button onClick={runReplay} disabled={!selectedAlertId || loading}
            style={{ padding: '8px 20px', borderRadius: 6, fontSize: 13, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6, background: selectedAlertId && !loading ? 'var(--accent-cyan)' : 'var(--bg-secondary)', border: '1px solid', borderColor: selectedAlertId && !loading ? 'var(--accent-cyan)' : 'var(--border)', color: selectedAlertId && !loading ? '#0a0f1e' : 'var(--text-muted)', cursor: selectedAlertId && !loading ? 'pointer' : 'not-allowed' }}>
            <Play size={13} />{loading ? 'Loading...' : 'Replay'}
          </button>
        </div>
        {error && <div style={{ marginTop: 10, padding: '8px 12px', borderRadius: 6, fontSize: 12, background: '#7f1d1d22', border: '1px solid #7f1d1d66', color: '#fca5a5' }}>{error}</div>}
      </div>

      {session && (
        <>
          {/* Session header */}
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: '12px 18px', display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap', flexShrink: 0 }}>
            <span className={`badge badge-${session.severity}`}>{session.severity?.toUpperCase()}</span>
            <span style={{ fontWeight: 700, fontSize: 14, color: 'var(--text-primary)' }}>{session.chain_title}</span>
            <div style={{ display: 'flex', gap: 16, marginLeft: 'auto', fontSize: 11, color: 'var(--text-muted)' }}>
              <span>Source: <span style={{ color: 'var(--accent-cyan)', fontFamily: 'var(--mono)' }}>{session.source_key}</span></span>
              <span>Duration: <span style={{ color: 'var(--text-secondary)' }}>{Math.round(session.duration_seconds)}s</span></span>
              <span>Steps: <span style={{ color: 'var(--text-secondary)' }}>{session.step_count}</span></span>
              {session.mitre_techniques?.length > 0 && <span style={{ fontFamily: 'var(--mono)', color: 'var(--accent-cyan)' }}>{session.mitre_techniques.join(' · ')}</span>}
            </div>
          </div>

          <div style={{ flex: 1, display: 'flex', gap: 14, overflow: 'hidden', minHeight: 0 }}>
            {/* Timeline */}
            <div style={{ width: 210, flexShrink: 0, background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: '14px 0', overflowY: 'auto' }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.8px', textTransform: 'uppercase', padding: '0 16px', marginBottom: 10 }}>Attack Chain</div>
              {session.steps.map((s, i) => {
                const active = currentStep === i
                const color = stepColor(s.step_name)
                return (
                  <button key={i} onClick={() => setCurrentStep(i)}
                    style={{ width: '100%', textAlign: 'left', padding: '10px 16px', border: 'none', cursor: 'pointer', background: active ? `${color}15` : 'transparent', borderLeft: `3px solid ${active ? color : 'transparent'}` }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <div style={{ width: 22, height: 22, borderRadius: '50%', flexShrink: 0, background: active ? color : 'var(--bg-secondary)', border: `2px solid ${active ? color : 'var(--border)'}`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, fontWeight: 700, color: active ? '#fff' : 'var(--text-muted)' }}>
                        {s.commentary ? <CheckCircle size={11} color="#fff" /> : i + 1}
                      </div>
                      <div>
                        <div style={{ fontSize: 12, fontWeight: active ? 600 : 400, color: active ? 'var(--text-primary)' : 'var(--text-secondary)' }}>{s.step_name.replace(/_/g, ' ')}</div>
                        {s.timestamp && <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 1 }}>{new Date(s.timestamp * 1000).toLocaleTimeString('en-US', { hour12: false })}</div>}
                      </div>
                    </div>
                    {i < session.step_count - 1 && <div style={{ width: 2, height: 8, background: 'var(--border)', marginLeft: 27, marginTop: 4 }} />}
                  </button>
                )
              })}
            </div>

            {/* Step detail */}
            {step && (
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 12, overflow: 'hidden', minHeight: 0 }}>
                <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: '14px 18px', flexShrink: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
                    <div style={{ width: 28, height: 28, borderRadius: '50%', background: `${stepColor(step.step_name)}22`, border: `2px solid ${stepColor(step.step_name)}`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, fontWeight: 700, color: stepColor(step.step_name) }}>{currentStep + 1}</div>
                    <div>
                      <div style={{ fontWeight: 700, fontSize: 14, color: stepColor(step.step_name) }}>{step.step_name.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Step {currentStep + 1} of {session.step_count}{step.timestamp && ` · ${new Date(step.timestamp * 1000).toLocaleTimeString('en-US', { hour12: false })}`}</div>
                    </div>
                    <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
                      <button onClick={() => setCurrentStep(s => Math.max(0, s - 1))} disabled={currentStep === 0}
                        style={{ padding: '5px 12px', borderRadius: 5, fontSize: 12, background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: currentStep === 0 ? 'var(--text-muted)' : 'var(--text-secondary)', cursor: currentStep === 0 ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', gap: 4 }}>
                        <ChevronLeft size={12} /> Prev
                      </button>
                      <button onClick={() => setCurrentStep(s => Math.min(session.step_count - 1, s + 1))} disabled={currentStep === session.step_count - 1}
                        style={{ padding: '5px 12px', borderRadius: 5, fontSize: 12, background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: currentStep === session.step_count - 1 ? 'var(--text-muted)' : 'var(--text-secondary)', cursor: currentStep === session.step_count - 1 ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', gap: 4 }}>
                        Next <ChevronRight size={12} />
                      </button>
                    </div>
                  </div>
                  <div style={{ fontFamily: 'var(--mono)', fontSize: 12, color: '#a3e635', background: '#0a0f1e', padding: '10px 14px', borderRadius: 6, border: '1px solid #1e293b', wordBreak: 'break-all' }}>
                    <span style={{ color: '#475569', marginRight: 8 }}>$</span>{step.message}
                  </div>
                </div>

                <div style={{ flex: 1, background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: '14px 18px', overflowY: 'auto' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                    <Brain size={14} color="var(--accent-cyan)" />
                    <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)' }}>AI Analysis</span>
                    {!step.commentary && (
                      <button onClick={() => explainStep(currentStep)} disabled={aiLoading && aiStep === currentStep}
                        style={{ marginLeft: 'auto', padding: '4px 12px', borderRadius: 5, fontSize: 11, fontWeight: 600, background: '#06b6d422', border: '1px solid #06b6d444', color: 'var(--accent-cyan)', cursor: 'pointer' }}>
                        {aiLoading && aiStep === currentStep ? 'Analyzing... (may take several minutes)' : '✦ Explain this step'}
                      </button>
                    )}
                  </div>
                  {step.commentary ? (
                    <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.7 }}>
                      {step.commentary.split('\n').map((line, i) => {
                        if (line.startsWith('## ') || line.startsWith('### ')) return <div key={i} style={{ fontWeight: 700, color: 'var(--text-primary)', margin: '10px 0 4px' }}>{line.replace(/^#+\s/, '')}</div>
                        if (line.startsWith('- ') || line.startsWith('* ')) return <div key={i} style={{ display: 'flex', gap: 6, margin: '2px 0 2px 8px' }}><span style={{ color: 'var(--accent-cyan)' }}>•</span><span>{line.slice(2)}</span></div>
                        if (line === '') return <div key={i} style={{ height: 5 }} />
                        return <div key={i}>{line}</div>
                      })}
                    </div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: 120, color: 'var(--text-muted)', gap: 8 }}>
                      <Brain size={24} style={{ opacity: 0.2 }} />
                      <div style={{ fontSize: 13 }}>Click "Explain this step" for AI analysis</div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Powered by Gemini — may take up to several minutes</div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </>
      )}

      {!session && !loading && (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', gap: 10 }}>
          <Play size={36} style={{ opacity: 0.15 }} />
          <div style={{ fontSize: 14, fontWeight: 500 }}>No replay session</div>
          <div style={{ fontSize: 12 }}>Select a correlation alert and click Replay</div>
        </div>
      )}
    </div>
  )
}
