import { useState, useEffect, useCallback } from 'react'
import { Shield, User, MessageSquare, ChevronDown, ChevronRight, Plus, Clock, RefreshCw, X, Check } from 'lucide-react'

const API = 'http://localhost:8000'

const STATE_CFG = {
  new:       { color: '#ef4444', bg: '#7f1d1d22', border: '#7f1d1d66', label: 'New' },
  triaging:  { color: '#f97316', bg: '#7c2d1222', border: '#7c2d1266', label: 'Triaging' },
  contained: { color: '#eab308', bg: '#71350422', border: '#71350466', label: 'Contained' },
  closed:    { color: '#22c55e', bg: '#14532d22', border: '#14532d66', label: 'Closed' },
  dismissed: { color: '#6b7280', bg: '#1f293722', border: '#1f293766', label: 'Dismissed' },
}
const TRANSITIONS = {
  new: ['triaging','dismissed'], triaging: ['contained','dismissed'],
  contained: ['closed','triaging'], dismissed: [], closed: [],
}
const DISP_CFG = {
  true_positive:        { color: '#ef4444', label: 'True Positive' },
  false_positive:       { color: '#f97316', label: 'False Positive' },
  benign_true_positive: { color: '#eab308', label: 'Benign TP' },
  undetermined:         { color: '#6b7280', label: 'Undetermined' },
}

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, informational: 0 }

function timeAgo(ts) {
  const d = Date.now() / 1000 - ts
  if (d < 60) return `${Math.floor(d)}s ago`
  if (d < 3600) return `${Math.floor(d/60)}m ago`
  return `${Math.floor(d/3600)}h ago`
}

// Professional alert selector — checkboxes with severity color coding
function AlertSelector({ alerts, selected, onChange }) {
  const [search, setSearch] = useState('')
  const [sevFilter, setSevFilter] = useState('all')

  const filtered = alerts.filter(a => {
    const matchSev = sevFilter === 'all' || a.severity === sevFilter
    const matchSearch = !search || a.title?.toLowerCase().includes(search.toLowerCase()) || a.source_key?.includes(search)
    return matchSev && matchSearch
  }).sort((a, b) => (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0))

  const toggle = (id) => {
    if (selected.includes(id)) onChange(selected.filter(x => x !== id))
    else onChange([...selected, id])
  }

  const toggleAll = () => {
    if (selected.length === filtered.length) onChange([])
    else onChange(filtered.map(a => a.alert_id))
  }

  const SEV_COLORS = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#4ade80' }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {/* Search + filter row */}
      <div style={{ display: 'flex', gap: 6 }}>
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search alerts..."
          style={{ flex: 1, padding: '6px 10px', fontSize: 12, borderRadius: 6, background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
        />
        {['all','critical','high','medium','low'].map(s => (
          <button key={s} onClick={() => setSevFilter(s)} style={{
            padding: '4px 8px', borderRadius: 5, fontSize: 10, fontWeight: 600,
            border: '1px solid',
            borderColor: sevFilter === s ? (SEV_COLORS[s] || 'var(--accent-cyan)') : 'var(--border)',
            background: sevFilter === s ? `${SEV_COLORS[s] || '#06b6d4'}22` : 'transparent',
            color: sevFilter === s ? (SEV_COLORS[s] || 'var(--accent-cyan)') : 'var(--text-muted)',
            cursor: 'pointer', textTransform: 'capitalize',
          }}>{s}</button>
        ))}
      </div>

      {/* Select all bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '5px 10px', background: 'var(--bg-secondary)', borderRadius: 6, border: '1px solid var(--border)' }}>
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          {filtered.length} alert(s) · {selected.length} selected
        </span>
        <button onClick={toggleAll} style={{ fontSize: 11, color: 'var(--accent-cyan)', background: 'none', border: 'none', cursor: 'pointer', fontWeight: 600 }}>
          {selected.length === filtered.length && filtered.length > 0 ? 'Deselect all' : 'Select all'}
        </button>
      </div>

      {/* Alert list */}
      <div style={{ maxHeight: 220, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 3 }}>
        {filtered.length === 0 ? (
          <div style={{ padding: '20px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>No alerts match</div>
        ) : filtered.map(a => {
          const isSelected = selected.includes(a.alert_id)
          const sevColor = SEV_COLORS[a.severity] || '#94a3b8'
          return (
            <div
              key={a.alert_id}
              onClick={() => toggle(a.alert_id)}
              style={{
                display: 'flex', alignItems: 'center', gap: 10,
                padding: '7px 10px', borderRadius: 6, cursor: 'pointer',
                background: isSelected ? '#06b6d411' : 'var(--bg-secondary)',
                border: `1px solid ${isSelected ? '#06b6d444' : 'var(--border)'}`,
                transition: 'all 0.1s',
              }}
            >
              {/* Checkbox */}
              <div style={{
                width: 16, height: 16, borderRadius: 4, flexShrink: 0,
                border: `2px solid ${isSelected ? 'var(--accent-cyan)' : 'var(--border)'}`,
                background: isSelected ? 'var(--accent-cyan)' : 'transparent',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                {isSelected && <Check size={10} color="#0a0f1e" strokeWidth={3} />}
              </div>

              {/* Severity bar */}
              <div style={{ width: 3, height: 28, borderRadius: 2, background: sevColor, flexShrink: 0 }} />

              {/* Content */}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 12, fontWeight: isSelected ? 600 : 400, color: isSelected ? 'var(--text-primary)' : 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {a.title}
                </div>
                <div style={{ display: 'flex', gap: 8, marginTop: 2, fontSize: 10, color: 'var(--text-muted)' }}>
                  <span style={{ color: sevColor, fontWeight: 600 }}>{a.severity?.toUpperCase()}</span>
                  <span className={`badge badge-${a.alert_type}`} style={{ fontSize: 9, padding: '0 4px' }}>{a.alert_type?.toUpperCase()}</span>
                  {a.source_key && <span style={{ fontFamily: 'var(--mono)' }}>{a.source_key}</span>}
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function IncidentCard({ incident, onUpdate }) {
  const [expanded, setExpanded] = useState(false)
  const [owner, setOwner] = useState(incident.owner || '')
  const [noteAuthor, setNoteAuthor] = useState('')
  const [noteContent, setNoteContent] = useState('')
  const [disposition, setDisposition] = useState(incident.disposition || '')
  const [saving, setSaving] = useState(false)

  const cfg = STATE_CFG[incident.state] || STATE_CFG.new
  const transitions = TRANSITIONS[incident.state] || []

  const patch = async (body) => {
    setSaving(true)
    try {
      const res = await fetch(`${API}/api/incidents/${incident.incident_id}`, {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      })
      if (res.ok) onUpdate(await res.json())
    } finally { setSaving(false) }
  }

  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderLeft: `3px solid ${cfg.color}`, borderRadius: 8, marginBottom: 8, overflow: 'hidden' }}>
      <div onClick={() => setExpanded(e => !e)} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px', cursor: 'pointer' }}>
        <span style={{ fontSize: 10, fontWeight: 700, padding: '3px 8px', borderRadius: 20, background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.border}`, textTransform: 'uppercase', letterSpacing: '0.5px', flexShrink: 0 }}>{cfg.label}</span>
        <span className={`badge badge-${incident.severity}`}>{incident.severity?.toUpperCase()}</span>
        <span style={{ flex: 1, fontWeight: 600, fontSize: 13, color: 'var(--text-primary)' }}>{incident.title}</span>
        <div style={{ display: 'flex', gap: 12, fontSize: 11, color: 'var(--text-muted)' }}>
          {incident.owner && <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}><User size={10} />{incident.owner}</span>}
          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}><Clock size={10} />{timeAgo(incident.created_at)}</span>
          <span style={{ fontFamily: 'var(--mono)', fontSize: 10, color: '#475569' }}>#{incident.incident_id}</span>
        </div>
        {expanded ? <ChevronDown size={14} color="var(--text-muted)" /> : <ChevronRight size={14} color="var(--text-muted)" />}
      </div>

      {expanded && (
        <div style={{ borderTop: '1px solid var(--border)', padding: 16 }}>
          <div style={{ display: 'flex', gap: 24, fontSize: 12, marginBottom: 16, flexWrap: 'wrap' }}>
            {incident.source_ips?.length > 0 && <div><div style={{ color: 'var(--text-muted)', fontSize: 10, textTransform: 'uppercase', marginBottom: 2 }}>Source IPs</div><div style={{ fontFamily: 'var(--mono)', color: 'var(--accent-cyan)' }}>{incident.source_ips.join(', ')}</div></div>}
            {incident.mitre_tactic && <div><div style={{ color: 'var(--text-muted)', fontSize: 10, textTransform: 'uppercase', marginBottom: 2 }}>Tactic</div><div style={{ color: 'var(--text-primary)' }}>{incident.mitre_tactic}</div></div>}
            {incident.mitre_techniques?.length > 0 && <div><div style={{ color: 'var(--text-muted)', fontSize: 10, textTransform: 'uppercase', marginBottom: 2 }}>Techniques</div><div style={{ fontFamily: 'var(--mono)', color: 'var(--accent-cyan)', fontSize: 11 }}>{incident.mitre_techniques.join(' · ')}</div></div>}
            <div><div style={{ color: 'var(--text-muted)', fontSize: 10, textTransform: 'uppercase', marginBottom: 2 }}>Alerts</div><div style={{ color: 'var(--text-primary)' }}>{incident.alert_ids?.length}</div></div>
            {incident.disposition && <div><div style={{ color: 'var(--text-muted)', fontSize: 10, textTransform: 'uppercase', marginBottom: 2 }}>Disposition</div><div style={{ color: DISP_CFG[incident.disposition]?.color || 'var(--text-primary)', fontWeight: 600 }}>{DISP_CFG[incident.disposition]?.label}{incident.is_false_positive && <span style={{ color: 'var(--text-muted)', fontWeight: 400, marginLeft: 6, fontSize: 10 }}>→ ML retrain queued</span>}</div></div>}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {transitions.length > 0 && (
                <div>
                  <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 6 }}>Transition</div>
                  <div style={{ display: 'flex', gap: 6 }}>
                    {transitions.map(s => { const c = STATE_CFG[s]; return <button key={s} onClick={() => patch({ state: s })} disabled={saving} style={{ padding: '5px 14px', borderRadius: 6, fontSize: 12, fontWeight: 600, background: c.bg, border: `1px solid ${c.border}`, color: c.color, cursor: 'pointer' }}>{c.label}</button> })}
                  </div>
                </div>
              )}
              <div>
                <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 6 }}>Owner</div>
                <div style={{ display: 'flex', gap: 6 }}>
                  <input value={owner} onChange={e => setOwner(e.target.value)} placeholder="Analyst name..." style={{ flex: 1, padding: '6px 10px', fontSize: 12, borderRadius: 6 }} />
                  <button onClick={() => patch({ owner })} disabled={saving || !owner} style={{ padding: '6px 12px', borderRadius: 6, fontSize: 12, fontWeight: 600, background: owner ? 'var(--bg-secondary)' : 'transparent', border: '1px solid var(--border)', color: owner ? 'var(--text-primary)' : 'var(--text-muted)', cursor: owner ? 'pointer' : 'not-allowed' }}>Set</button>
                </div>
              </div>
              <div>
                <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 6 }}>Disposition</div>
                <div style={{ display: 'flex', gap: 6 }}>
                  <select value={disposition} onChange={e => setDisposition(e.target.value)} style={{ flex: 1, padding: '6px 10px', fontSize: 12, borderRadius: 6 }}>
                    <option value="">Select...</option>
                    <option value="true_positive">True Positive</option>
                    <option value="false_positive">False Positive (→ ML retrain)</option>
                    <option value="benign_true_positive">Benign TP</option>
                    <option value="undetermined">Undetermined</option>
                  </select>
                  <button onClick={() => patch({ disposition, fp_fingerprints: disposition === 'false_positive' ? incident.alert_ids : [] })} disabled={saving || !disposition} style={{ padding: '6px 12px', borderRadius: 6, fontSize: 12, fontWeight: 600, background: disposition === 'false_positive' ? '#7f1d1d33' : 'var(--bg-secondary)', border: `1px solid ${disposition === 'false_positive' ? '#7f1d1d' : 'var(--border)'}`, color: disposition === 'false_positive' ? '#fca5a5' : 'var(--text-secondary)', cursor: disposition ? 'pointer' : 'not-allowed' }}>Set</button>
                </div>
              </div>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Notes ({incident.notes?.length || 0})</div>
              {incident.notes?.length > 0 && (
                <div style={{ maxHeight: 90, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {incident.notes.map((note, i) => (
                    <div key={i} style={{ padding: '6px 10px', background: 'var(--bg-secondary)', borderRadius: 6, border: '1px solid var(--border)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                        <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--accent-cyan)' }}>{note.author}</span>
                        <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{timeAgo(note.timestamp)}</span>
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{note.content}</div>
                    </div>
                  ))}
                </div>
              )}
              <input value={noteAuthor} onChange={e => setNoteAuthor(e.target.value)} placeholder="Your name" style={{ padding: '6px 10px', fontSize: 12, borderRadius: 6 }} />
              <textarea value={noteContent} onChange={e => setNoteContent(e.target.value)} placeholder="Add a note..." rows={2} style={{ padding: '6px 10px', fontSize: 12, borderRadius: 6, resize: 'none', fontFamily: 'inherit' }} />
              <button onClick={() => { patch({ note_author: noteAuthor, note_content: noteContent }); setNoteContent('') }} disabled={saving || !noteAuthor || !noteContent} style={{ padding: '6px 12px', borderRadius: 6, fontSize: 12, fontWeight: 600, background: (noteAuthor && noteContent) ? '#06b6d422' : 'transparent', border: `1px solid ${(noteAuthor && noteContent) ? '#06b6d444' : 'var(--border)'}`, color: (noteAuthor && noteContent) ? 'var(--accent-cyan)' : 'var(--text-muted)', cursor: (noteAuthor && noteContent) ? 'pointer' : 'not-allowed', display: 'flex', alignItems: 'center', gap: 6, justifyContent: 'center' }}>
                <MessageSquare size={12} /> Add Note
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default function IncidentPanel({ alerts }) {
  const [incidents, setIncidents] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('all')
  const [selectedAlerts, setSelectedAlerts] = useState([])
  const [title, setTitle] = useState('')
  const [creating, setCreating] = useState(false)
  const [showCreate, setShowCreate] = useState(false)

  const fetchIncidents = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/incidents`)
      const data = await res.json()
      setIncidents(data.incidents || [])
    } catch {}
    setLoading(false)
  }, [])

  useEffect(() => { fetchIncidents() }, [])

  const createIncident = async () => {
    if (!selectedAlerts.length) return
    setCreating(true)
    try {
      const res = await fetch(`${API}/api/incidents`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ alert_ids: selectedAlerts, title: title || undefined }),
      })
      if (res.ok) { setSelectedAlerts([]); setTitle(''); setShowCreate(false); await fetchIncidents() }
    } finally { setCreating(false) }
  }

  const createFromAll = async () => {
    const critHigh = alerts.filter(a => ['critical','high'].includes(a.severity) && a.alert_type === 'correlation')
    const ids = critHigh.length ? critHigh.map(a => a.alert_id) : alerts.slice(0, 5).map(a => a.alert_id)
    if (!ids.length) return
    setCreating(true)
    try {
      const res = await fetch(`${API}/api/incidents`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ alert_ids: ids, title: critHigh.length ? 'Active Intrusion — Kill Chain Detected' : 'Alert Cluster' }),
      })
      if (res.ok) await fetchIncidents()
    } finally { setCreating(false) }
  }

  const updateIncident = (updated) => setIncidents(prev => prev.map(i => i.incident_id === updated.incident_id ? updated : i))
  const filtered = filter === 'all' ? incidents : incidents.filter(i => i.state === filter)
  const counts = incidents.reduce((acc, i) => { acc[i.state] = (acc[i.state] || 0) + 1; return acc }, {})

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
        <div style={{ width: 32, height: 32, borderRadius: 8, background: '#06b6d422', border: '1px solid #06b6d444', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Shield size={14} color="var(--accent-cyan)" />
        </div>
        <div>
          <div style={{ fontWeight: 700, fontSize: 15, color: 'var(--text-primary)' }}>Incidents</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{incidents.length} total</div>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
          <button onClick={fetchIncidents} style={{ width: 32, height: 32, borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-card)', color: 'var(--text-muted)', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <RefreshCw size={13} />
          </button>
          {alerts.length > 0 && incidents.length === 0 && (
            <button onClick={createFromAll} disabled={creating} style={{ padding: '6px 14px', borderRadius: 6, fontSize: 12, fontWeight: 600, background: '#4ade8022', border: '1px solid #4ade8044', color: '#4ade80', cursor: 'pointer' }}>
              ⚡ Auto-create
            </button>
          )}
          <button onClick={() => setShowCreate(s => !s)} style={{ padding: '6px 14px', borderRadius: 6, fontSize: 12, fontWeight: 600, background: showCreate ? '#06b6d433' : '#06b6d422', border: '1px solid #06b6d444', color: 'var(--accent-cyan)', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6 }}>
            {showCreate ? <X size={13} /> : <Plus size={13} />}
            {showCreate ? 'Cancel' : 'New Incident'}
          </button>
        </div>
      </div>

      {/* Create panel — professional alert selector */}
      {showCreate && (
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: 16, flexShrink: 0 }}>
          <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)', marginBottom: 14, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Plus size={14} color="var(--accent-cyan)" /> Create Incident
          </div>
          <div style={{ display: 'flex', gap: 14 }}>
            <div style={{ flex: 1 }}>
              <AlertSelector alerts={alerts} selected={selectedAlerts} onChange={setSelectedAlerts} />
            </div>
            <div style={{ width: 200, display: 'flex', flexDirection: 'column', gap: 8 }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Incident Title</div>
              <input
                value={title}
                onChange={e => setTitle(e.target.value)}
                placeholder="Auto-generated from alerts..."
                style={{ padding: '7px 10px', fontSize: 12, borderRadius: 6, background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
              />
              {selectedAlerts.length > 0 && (
                <div style={{ padding: '8px 10px', background: 'var(--bg-secondary)', borderRadius: 6, border: '1px solid var(--border)', fontSize: 11 }}>
                  <div style={{ color: 'var(--text-muted)', marginBottom: 4 }}>Selected:</div>
                  {selectedAlerts.slice(0, 3).map(id => {
                    const a = alerts.find(x => x.alert_id === id)
                    return a ? (
                      <div key={id} style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 3 }}>
                        <span className={`badge badge-${a.severity}`} style={{ fontSize: 9, padding: '0 4px' }}>{a.severity?.slice(0,4).toUpperCase()}</span>
                        <span style={{ fontSize: 10, color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.title?.slice(0,22)}</span>
                      </div>
                    ) : null
                  })}
                  {selectedAlerts.length > 3 && <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>+{selectedAlerts.length - 3} more</div>}
                </div>
              )}
              <button
                onClick={createIncident}
                disabled={!selectedAlerts.length || creating}
                style={{
                  marginTop: 'auto', padding: '9px 16px', borderRadius: 6, fontSize: 13, fontWeight: 600,
                  background: selectedAlerts.length ? 'var(--accent-cyan)' : 'var(--bg-secondary)',
                  border: 'none',
                  color: selectedAlerts.length ? '#0a0f1e' : 'var(--text-muted)',
                  cursor: selectedAlerts.length ? 'pointer' : 'not-allowed',
                }}
              >
                {creating ? 'Creating...' : `Create Incident (${selectedAlerts.length})`}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* State filter tabs */}
      <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
        {['all', 'new', 'triaging', 'contained', 'closed', 'dismissed'].map(state => {
          const cfg = STATE_CFG[state]
          const label = cfg ? cfg.label : 'All'
          const color = cfg ? cfg.color : 'var(--text-muted)'
          const bg = cfg ? cfg.bg : 'var(--bg-card)'
          const border = cfg ? cfg.border : 'var(--border)'
          const count = state === 'all' ? incidents.length : (counts[state] || 0)
          const active = filter === state
          return (
            <button key={state} onClick={() => setFilter(state)} style={{ padding: '5px 12px', borderRadius: 6, fontSize: 12, fontWeight: active ? 600 : 400, background: active ? bg : 'transparent', border: `1px solid ${active ? border : 'var(--border)'}`, color: active ? color : 'var(--text-muted)', cursor: 'pointer' }}>
              {label}{count > 0 && <span style={{ marginLeft: 4, opacity: 0.7 }}>({count})</span>}
            </button>
          )
        })}
      </div>

      {/* Incident list */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {loading ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 100, color: 'var(--text-muted)' }}>Loading...</div>
        ) : filtered.length === 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: 180, color: 'var(--text-muted)', gap: 10 }}>
            <Shield size={32} style={{ opacity: 0.15 }} />
            <div style={{ fontSize: 14, fontWeight: 500, color: 'var(--text-secondary)' }}>{filter === 'all' ? 'No incidents yet' : `No ${filter} incidents`}</div>
            {filter === 'all' && alerts.length > 0 && <div style={{ fontSize: 12 }}>Click <strong style={{ color: '#4ade80' }}>⚡ Auto-create</strong> or <strong style={{ color: 'var(--accent-cyan)' }}>New Incident</strong></div>}
          </div>
        ) : (
          filtered.map(i => <IncidentCard key={i.incident_id} incident={i} onUpdate={updateIncident} />)
        )}
      </div>
    </div>
  )
}
