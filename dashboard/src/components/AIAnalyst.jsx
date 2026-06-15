import { useState } from 'react'
import { Brain, FileText, Shield, Zap, BookOpen, Users, Loader, AlertCircle, CheckCircle } from 'lucide-react'

const API = 'http://localhost:8000'

const TASKS = [
  { id: 'summary',   label: 'Incident Summary',     icon: FileText,  desc: 'Summarize all recent alerts as a structured incident report', multi: true },
  { id: 'report',    label: 'Executive Report',      icon: Users,     desc: 'Generate a non-technical report for CISO / leadership', multi: true },
  { id: 'narrative', label: 'Threat Narrative',      icon: BookOpen,  desc: 'Tell the attack story from attacker + defender perspectives', multi: true },
]

const SINGLE_TASKS = [
  { id: 'explain',   label: 'Analyst Explanation',   icon: Brain,     desc: 'Explain this alert to an L1/L2 SOC analyst' },
  { id: 'recommend', label: 'Recommended Actions',   icon: Shield,    desc: 'Get a prioritized action plan for this alert' },
  { id: 'mitre',     label: 'MITRE ATT&CK Context',  icon: Zap,       desc: 'Explain the ATT&CK technique in context of this alert' },
]

function MarkdownText({ content }) {
  // Simple Markdown renderer — bold, headers, bullets, code
  const lines = content.split('\n')
  return (
    <div style={{ lineHeight: 1.7, color: 'var(--text-primary)' }}>
      {lines.map((line, i) => {
        if (line.startsWith('### ')) return <h3 key={i} style={{ fontSize: 14, fontWeight: 700, color: 'var(--accent-cyan)', margin: '16px 0 6px' }}>{line.slice(4)}</h3>
        if (line.startsWith('## '))  return <h2 key={i} style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', margin: '20px 0 8px', borderBottom: '1px solid var(--border)', paddingBottom: 4 }}>{line.slice(3)}</h2>
        if (line.startsWith('# '))   return <h1 key={i} style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)', margin: '20px 0 10px' }}>{line.slice(2)}</h1>
        if (line.startsWith('- ') || line.startsWith('* ')) return (
          <div key={i} style={{ display: 'flex', gap: 8, margin: '3px 0 3px 12px' }}>
            <span style={{ color: 'var(--accent-cyan)', flexShrink: 0, marginTop: 2 }}>•</span>
            <span style={{ fontSize: 13 }}>{renderInline(line.slice(2))}</span>
          </div>
        )
        if (line.match(/^\d+\. /)) return (
          <div key={i} style={{ display: 'flex', gap: 8, margin: '3px 0 3px 12px' }}>
            <span style={{ color: 'var(--accent-cyan)', flexShrink: 0, minWidth: 20 }}>{line.match(/^(\d+)\./)[1]}.</span>
            <span style={{ fontSize: 13 }}>{renderInline(line.replace(/^\d+\.\s/, ''))}</span>
          </div>
        )
        if (line === '' || line === '---') return <div key={i} style={{ height: line === '---' ? 1 : 8, background: line === '---' ? 'var(--border)' : 'transparent', margin: line === '---' ? '12px 0' : 0 }} />
        return <p key={i} style={{ fontSize: 13, margin: '4px 0', color: 'var(--text-secondary)' }}>{renderInline(line)}</p>
      })}
    </div>
  )
}

function renderInline(text) {
  // Handle **bold** and `code`
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/)
  return parts.map((part, i) => {
    if (part.startsWith('**') && part.endsWith('**'))
      return <strong key={i} style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{part.slice(2,-2)}</strong>
    if (part.startsWith('`') && part.endsWith('`'))
      return <code key={i} style={{ fontFamily: 'var(--mono)', fontSize: 11, background: 'var(--bg-primary)', padding: '1px 5px', borderRadius: 3, color: 'var(--accent-cyan)' }}>{part.slice(1,-1)}</code>
    return part
  })
}

function TaskCard({ task, onRun, loading, selected, onSelect }) {
  const Icon = task.icon
  const active = selected === task.id
  return (
    <button
      onClick={() => { onSelect(task.id); onRun(task.id, task.multi) }}
      disabled={loading}
      style={{
        display: 'flex', alignItems: 'flex-start', gap: 10,
        padding: '12px 14px', borderRadius: 6, border: '1px solid',
        borderColor: active ? 'var(--accent-cyan)' : 'var(--border)',
        background: active ? '#0c4a6e22' : 'var(--bg-card)',
        color: 'var(--text-primary)', cursor: loading ? 'not-allowed' : 'pointer',
        textAlign: 'left', width: '100%', opacity: loading ? 0.6 : 1,
        transition: 'all 0.15s',
      }}
    >
      <Icon size={16} color={active ? 'var(--accent-cyan)' : 'var(--text-muted)'} style={{ flexShrink: 0, marginTop: 1 }} />
      <div>
        <div style={{ fontSize: 13, fontWeight: 600 }}>{task.label}</div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{task.desc}</div>
      </div>
    </button>
  )
}

export default function AIAnalyst({ alerts }) {
  const [selectedTask, setSelectedTask] = useState(null)
  const [selectedAlertId, setSelectedAlertId] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const runTask = async (taskId, isMulti) => {
    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const body = isMulti
        ? { alert_ids: alerts.slice(0, 10).map(a => a.alert_id) }
        : { alert_id: selectedAlertId || alerts[0]?.alert_id }

      if (!isMulti && !body.alert_id) {
        setError('No alert selected. Select an alert ID from the dropdown below.')
        setLoading(false)
        return
      }

      const res = await fetch(`${API}/api/ai/${taskId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`)
      if (data.error) throw new Error(data.error)
      setResult(data)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ height: '100%', display: 'flex', gap: 16, overflow: 'hidden' }}>

      {/* Left panel — task selector */}
      <div style={{ width: 260, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 8, overflowY: 'auto' }}>

        {/* AI status banner */}
        <div style={{
          padding: '10px 12px', borderRadius: 6,
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          marginBottom: 4,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
            <Brain size={14} color="var(--accent-cyan)" />
            <span style={{ fontSize: 12, fontWeight: 600 }}>AI Reasoning Engine</span>
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            Powered by Gemini 1.5 Flash<br/>
            Detection: Sigma · Correlation · ML<br/>
            AI: Explanation only
          </div>
        </div>

        {/* Multi-alert tasks */}
        <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600, letterSpacing: '0.5px', textTransform: 'uppercase', marginTop: 4 }}>
          All Alerts
        </div>
        {TASKS.map(task => (
          <TaskCard key={task.id} task={task} onRun={runTask} loading={loading}
                    selected={selectedTask} onSelect={setSelectedTask} />
        ))}

        {/* Single-alert tasks */}
        <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600, letterSpacing: '0.5px', textTransform: 'uppercase', marginTop: 8 }}>
          Single Alert
        </div>

        {/* Alert selector */}
        <select
          value={selectedAlertId}
          onChange={e => setSelectedAlertId(e.target.value)}
          style={{
            padding: '6px 8px', borderRadius: 4,
            background: 'var(--bg-card)', border: '1px solid var(--border)',
            color: 'var(--text-primary)', fontSize: 11, width: '100%',
          }}
        >
          <option value="">Select alert...</option>
          {alerts.slice(0, 20).map(a => (
            <option key={a.alert_id} value={a.alert_id}>
              [{a.severity?.toUpperCase()}] {a.title?.slice(0, 35)}
            </option>
          ))}
        </select>

        {SINGLE_TASKS.map(task => (
          <TaskCard key={task.id} task={task} onRun={runTask} loading={loading}
                    selected={selectedTask} onSelect={setSelectedTask} />
        ))}
      </div>

      {/* Right panel — result */}
      <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        {loading && (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center',
                        justifyContent: 'center', height: '60%', gap: 12 }}>
            <Loader size={28} color="var(--accent-cyan)" style={{ animation: 'spin 1s linear infinite' }} />
            <div style={{ color: 'var(--text-secondary)', fontSize: 13 }}>Gemini is reasoning...</div>
            <style>{`@keyframes spin { from { transform: rotate(0deg) } to { transform: rotate(360deg) } }`}</style>
          </div>
        )}

        {error && !loading && (
          <div style={{
            padding: 16, borderRadius: 6,
            background: '#7f1d1d22', border: '1px solid var(--sev-critical)',
            display: 'flex', gap: 10, alignItems: 'flex-start',
          }}>
            <AlertCircle size={16} color="var(--sev-critical)" style={{ flexShrink: 0, marginTop: 1 }} />
            <div>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--sev-critical)', marginBottom: 4 }}>
                AI Reasoning Error
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{error}</div>
              {error.includes('API key') && (
                <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-muted)' }}>
                  Set your API key: <code style={{ color: 'var(--accent-cyan)' }}>
                    export GEMINI_API_KEY=your_key_here
                  </code><br />
                  Get a free key at: <a href="https://aistudio.google.com/app/apikey"
                    target="_blank" rel="noreferrer" style={{ color: 'var(--accent-cyan)' }}>
                    aistudio.google.com
                  </a>
                </div>
              )}
            </div>
          </div>
        )}

        {result && !loading && (
          <div style={{ flex: 1, overflowY: 'auto' }}>
            {/* Result header */}
            <div style={{
              display: 'flex', alignItems: 'center', gap: 8,
              marginBottom: 16, paddingBottom: 10,
              borderBottom: '1px solid var(--border)',
            }}>
              <CheckCircle size={14} color="var(--green)" />
              <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', textTransform: 'capitalize' }}>
                {result.task?.replace('_', ' ')}
              </span>
              <span style={{ fontSize: 10, color: 'var(--text-muted)', marginLeft: 'auto' }}>
                {result.model} · {result.output_tokens} tokens · {result.elapsed_seconds}s
                {result.cached && ' · cached'}
              </span>
            </div>

            {/* AI content */}
            <div style={{ padding: '0 4px' }}>
              <MarkdownText content={result.content} />
            </div>
          </div>
        )}

        {!loading && !error && !result && (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center',
                        justifyContent: 'center', height: '60%', color: 'var(--text-muted)', gap: 10 }}>
            <Brain size={36} style={{ opacity: 0.2 }} />
            <div style={{ fontSize: 14 }}>Select a reasoning task</div>
            <div style={{ fontSize: 12, textAlign: 'center', maxWidth: 280 }}>
              AI reasoning operates only on alerts already generated by the detection engine.
              Gemini never makes detection decisions.
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
