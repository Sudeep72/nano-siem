import { useState } from 'react'
import { Brain, FileText, Shield, Zap, BookOpen, Users, AlertCircle, CheckCircle, Sparkles } from 'lucide-react'

const API = 'http://localhost:8000'

const TASKS = [
  { id: 'summary',   label: 'Incident Summary',   icon: FileText, desc: 'Structured incident report from all recent alerts', multi: true,  color: '#06b6d4' },
  { id: 'report',    label: 'Executive Report',    icon: Users,    desc: 'Non-technical CISO/leadership briefing',             multi: true,  color: '#a78bfa' },
  { id: 'narrative', label: 'Threat Narrative',    icon: BookOpen, desc: 'Attack story from attacker + defender perspectives', multi: true,  color: '#f97316' },
]
const SINGLE_TASKS = [
  { id: 'explain',   label: 'Analyst Explanation', icon: Brain,   desc: 'Explain this alert to an L1/L2 SOC analyst',         color: '#4ade80' },
  { id: 'recommend', label: 'Recommended Actions', icon: Shield,  desc: 'Prioritized Immediate / Investigate / Remediate plan', color: '#eab308' },
  { id: 'mitre',     label: 'ATT&CK Context',      icon: Zap,     desc: "Explain the technique using this alert's evidence",   color: '#ef4444' },
]

function MarkdownRenderer({ content }) {
  return (
    <div style={{ lineHeight: 1.75, color: 'var(--text-secondary)', fontSize: 13 }}>
      {content.split('\n').map((line, i) => {
        if (line.startsWith('### '))
          return <h3 key={i} style={{ fontSize: 13, fontWeight: 700, color: 'var(--accent-cyan)', margin: '14px 0 5px' }}>{line.slice(4)}</h3>
        if (line.startsWith('## '))
          return <h2 key={i} style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', margin: '18px 0 7px', paddingBottom: 5, borderBottom: '1px solid var(--border)' }}>{line.slice(3)}</h2>
        if (line.startsWith('- ') || line.startsWith('* '))
          return <div key={i} style={{ display: 'flex', gap: 8, margin: '4px 0 4px 8px' }}><span style={{ color: 'var(--accent-cyan)', flexShrink: 0 }}>•</span><span>{renderInline(line.slice(2))}</span></div>
        if (/^\d+\. /.test(line)) {
          const m = line.match(/^(\d+)\. (.+)/)
          if (m) return <div key={i} style={{ display: 'flex', gap: 10, margin: '4px 0 4px 8px' }}><span style={{ color: 'var(--accent-cyan)', minWidth: 18, fontWeight: 600 }}>{m[1]}.</span><span>{renderInline(m[2])}</span></div>
        }
        if (line === '' || line === '---')
          return <div key={i} style={{ height: line === '---' ? 1 : 7, background: line === '---' ? 'var(--border)' : 'transparent', margin: line === '---' ? '10px 0' : 0 }} />
        return <p key={i} style={{ margin: '3px 0', color: 'var(--text-secondary)' }}>{renderInline(line)}</p>
      })}
    </div>
  )
}

function renderInline(text) {
  return text.split(/(\*\*[^*]+\*\*|`[^`]+`)/).map((p, i) => {
    if (p.startsWith('**') && p.endsWith('**')) return <strong key={i} style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{p.slice(2,-2)}</strong>
    if (p.startsWith('`') && p.endsWith('`')) return <code key={i} style={{ fontFamily: 'var(--mono)', fontSize: 11, background: 'var(--bg-secondary)', padding: '1px 6px', borderRadius: 4, color: 'var(--accent-cyan)', border: '1px solid var(--border)' }}>{p.slice(1,-1)}</code>
    return p
  })
}

function TaskButton({ task, onRun, loading, active }) {
  const Icon = task.icon
  return (
    <button onClick={() => onRun(task.id, task.multi)} disabled={loading}
      style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '10px 12px', borderRadius: 7, border: `1px solid ${active ? task.color + '66' : 'var(--border)'}`, background: active ? task.color + '11' : 'var(--bg-secondary)', color: 'var(--text-primary)', cursor: loading ? 'not-allowed' : 'pointer', textAlign: 'left', width: '100%', opacity: loading ? 0.6 : 1, transition: 'all 0.15s' }}>
      <div style={{ width: 28, height: 28, borderRadius: 6, flexShrink: 0, background: `${task.color}22`, border: `1px solid ${task.color}44`, display: 'flex', alignItems: 'center', justifyContent: 'center', marginTop: 1 }}>
        <Icon size={13} color={task.color} />
      </div>
      <div style={{ minWidth: 0 }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: active ? task.color : 'var(--text-primary)' }}>{task.label}</div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2, lineHeight: 1.4 }}>{task.desc}</div>
      </div>
    </button>
  )
}

export default function AIAnalyst({ alerts }) {
  const [activeTask, setActiveTask] = useState(null)
  const [alertId, setAlertId] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const runTask = async (taskId, isMulti) => {
    setActiveTask(taskId); setLoading(true); setError(null); setResult(null)
    try {
      const body = isMulti
        ? { alert_ids: alerts.slice(0, 10).map(a => a.alert_id) }
        : { alert_id: alertId || alerts[0]?.alert_id }
      if (!isMulti && !body.alert_id) { setError('No alert selected.'); setLoading(false); return }
      const res = await fetch(`${API}/api/ai/${taskId}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`)
      if (data.error) throw new Error(data.error)
      setResult(data)
    } catch(e) { setError(e.message) }
    finally { setLoading(false) }
  }

  const taskCfg = [...TASKS, ...SINGLE_TASKS].find(t => t.id === activeTask)

  return (
    <div style={{ height: '100%', display: 'flex', gap: 16, overflow: 'hidden' }}>
      {/* Sidebar */}
      <div style={{ width: 240, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 6, overflowY: 'auto' }}>
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: '12px 14px', marginBottom: 6 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            <div style={{ width: 28, height: 28, borderRadius: 6, background: '#06b6d422', border: '1px solid #06b6d444', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Sparkles size={13} color="var(--accent-cyan)" />
            </div>
            <div>
              <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)' }}>AI Reasoning Engine</div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>Gemini 2.5 Flash</div>
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 3, fontSize: 11, color: 'var(--text-muted)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}><span style={{ width: 6, height: 6, borderRadius: '50%', background: '#4ade80' }} />Detection: Sigma · Correlation · ML</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}><span style={{ width: 6, height: 6, borderRadius: '50%', background: '#06b6d4' }} />AI: Explanation only</div>
          </div>
        </div>

        <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.8px', textTransform: 'uppercase', padding: '0 2px', marginBottom: 2 }}>All Alerts</div>
        {TASKS.map(t => <TaskButton key={t.id} task={t} onRun={runTask} loading={loading} active={activeTask === t.id} />)}

        <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.8px', textTransform: 'uppercase', padding: '6px 2px 2px', marginTop: 4 }}>Single Alert</div>
        <select value={alertId} onChange={e => setAlertId(e.target.value)}
          style={{ padding: '7px 10px', fontSize: 11, borderRadius: 6, background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: alertId ? 'var(--text-primary)' : 'var(--text-muted)' }}>
          <option value="">Select alert...</option>
          {alerts.slice(0, 20).map(a => <option key={a.alert_id} value={a.alert_id}>[{a.severity?.toUpperCase()?.slice(0,4)}] {a.title?.slice(0, 32)}</option>)}
        </select>
        {SINGLE_TASKS.map(t => <TaskButton key={t.id} task={t} onRun={runTask} loading={loading} active={activeTask === t.id} />)}
      </div>

      {/* Result panel */}
      <div style={{ flex: 1, background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {(result || loading || error) && (
          <div style={{ padding: '12px 18px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 10, background: 'var(--bg-secondary)', flexShrink: 0 }}>
            {taskCfg && (
              <>
                <div style={{ width: 24, height: 24, borderRadius: 5, background: `${taskCfg.color}22`, border: `1px solid ${taskCfg.color}44`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <taskCfg.icon size={12} color={taskCfg.color} />
                </div>
                <span style={{ fontSize: 13, fontWeight: 600, color: taskCfg.color }}>{taskCfg.label}</span>
              </>
            )}
            {result && !loading && (
              <div style={{ marginLeft: 'auto', display: 'flex', gap: 10, fontSize: 11, color: 'var(--text-muted)' }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}><CheckCircle size={11} color="#4ade80" />{result.output_tokens} tokens</span>
                <span>{result.elapsed_seconds}s</span>
                {result.cached && <span style={{ color: '#06b6d4' }}>cached</span>}
              </div>
            )}
          </div>
        )}

        <div style={{ flex: 1, overflowY: 'auto', padding: '18px 22px' }}>
          {loading && (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '60%', gap: 16 }}>
              <div style={{ width: 48, height: 48, borderRadius: '50%', border: '3px solid var(--border)', borderTop: `3px solid ${taskCfg?.color || 'var(--accent-cyan)'}`, animation: 'spin 0.8s linear infinite' }} />
              <div style={{ color: 'var(--text-primary)', fontSize: 14, fontWeight: 500 }}>Gemini is reasoning...</div>
              <div style={{ color: 'var(--text-muted)', fontSize: 12, textAlign: 'center', maxWidth: 260 }}>This may take up to several minutes depending on the complexity of the request</div>
              <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
            </div>
          )}
          {error && !loading && (
            <div style={{ padding: '14px 16px', borderRadius: 8, background: '#7f1d1d22', border: '1px solid #7f1d1d66', display: 'flex', gap: 10 }}>
              <AlertCircle size={16} color="#ef4444" style={{ flexShrink: 0, marginTop: 1 }} />
              <div>
                <div style={{ fontSize: 13, fontWeight: 600, color: '#fca5a5', marginBottom: 4 }}>Reasoning Failed</div>
                <div style={{ fontSize: 12, color: '#fca5a5', opacity: 0.8 }}>{error}</div>
                {error.includes('API key') && (
                  <div style={{ marginTop: 10, fontSize: 11, color: 'var(--text-muted)' }}>
                    Set your key: <code style={{ fontFamily: 'var(--mono)', color: 'var(--accent-cyan)', background: 'var(--bg-secondary)', padding: '2px 6px', borderRadius: 3 }}>export GEMINI_API_KEY=your_key</code>
                  </div>
                )}
              </div>
            </div>
          )}
          {result && !loading && <MarkdownRenderer content={result.content} />}
          {!loading && !error && !result && (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '70%', color: 'var(--text-muted)', gap: 12 }}>
              <div style={{ width: 56, height: 56, borderRadius: '50%', background: '#06b6d411', border: '1px solid #06b6d422', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Brain size={24} color="#06b6d444" />
              </div>
              <div style={{ fontSize: 14, fontWeight: 500, color: 'var(--text-secondary)' }}>Select a reasoning task</div>
              <div style={{ fontSize: 12, textAlign: 'center', maxWidth: 300, lineHeight: 1.6 }}>AI reasoning only operates on alerts already generated by the detection engine</div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
