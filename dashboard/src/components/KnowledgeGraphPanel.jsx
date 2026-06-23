import { useEffect, useRef, useState, useCallback } from 'react'
import { Network, Search, RefreshCw } from 'lucide-react'

const API = 'http://localhost:8000'

const NODE_CFG = {
  source_ip:  { color: '#ef4444', r: 14, label: 'Source IP' },
  host:       { color: '#f97316', r: 12, label: 'Host' },
  tactic:     { color: '#eab308', r: 12, label: 'Tactic' },
  chain:      { color: '#4ade80', r: 11, label: 'Chain' },
  alert:      { color: '#a78bfa', r: 9,  label: 'Alert' },
  technique:  { color: '#06b6d4', r: 8,  label: 'Technique' },
}

// Extract subgraph strictly reachable from ONE source IP node
// Never crosses to another source_ip's direct edges
function extractIPSubgraph(sourceIPNode, allNodes, allEdges) {
  const nodeById = {}
  allNodes.forEach(n => { nodeById[n.id] = n })

  // Build adjacency — but DO NOT traverse edges that lead to OTHER source_ip nodes
  const adj = {}
  allNodes.forEach(n => { adj[n.id] = [] })
  allEdges.forEach(e => {
    adj[e.source]?.push(e.target)
    adj[e.target]?.push(e.source)
  })

  const visited = new Set([sourceIPNode.id])
  const queue = [sourceIPNode.id]

  while (queue.length) {
    const cur = queue.shift()
    for (const nb of (adj[cur] || [])) {
      if (visited.has(nb)) continue
      const nbNode = nodeById[nb]
      // Stop at other source_ip nodes — don't cross into their subgraph
      if (nbNode && nbNode.type === 'source_ip' && nb !== sourceIPNode.id) continue
      visited.add(nb)
      queue.push(nb)
    }
  }

  const nodes = allNodes.filter(n => visited.has(n.id))
  const edges = allEdges.filter(e => visited.has(e.source) && visited.has(e.target))
  return { nodes, edges }
}

function initLayout(nodes, edges, W, H) {
  const RING = { source_ip: 0, host: 0, tactic: 1, chain: 1, alert: 2, technique: 3 }
  const typeCounts = {}, typeIdx = {}
  nodes.forEach(n => { typeCounts[n.type] = (typeCounts[n.type] || 0) + 1; typeIdx[n.type] = 0 })
  const maxR = Math.min(W * 0.36, H * 0.40)
  const RING_R = [0, maxR * 0.28, maxR * 0.60, maxR]
  return nodes.map(n => {
    const ring = RING[n.type] ?? 2
    const r = RING_R[ring]
    const idx = typeIdx[n.type]++
    const total = typeCounts[n.type]
    const angle = total === 1 ? -Math.PI / 2 : (idx / total) * Math.PI * 2 - Math.PI / 2
    const jx = r > 0 ? (Math.random() - 0.5) * 22 : 0
    const jy = r > 0 ? (Math.random() - 0.5) * 12 : 0
    return { ...n, x: W / 2 + (r > 0 ? Math.cos(angle) * r : 0) + jx, y: H / 2 + (r > 0 ? Math.sin(angle) * r : 0) + jy, vx: 0, vy: 0 }
  })
}

function SingleIPGraph({ ipNode, allNodes, allEdges, search }) {
  const canvasRef = useRef(null)
  const wrapRef = useRef(null)
  const animRef = useRef(null)
  const nodesRef = useRef([])
  const dragging = useRef(null)
  const needsInit = useRef(true)
  const [canvasSize, setCanvasSize] = useState({ w: 800, h: 280 })
  const [selected, setSelected] = useState(null)
  const [desc, setDesc] = useState(null)

  const sg = extractIPSubgraph(ipNode, allNodes, allEdges)

  useEffect(() => {
    if (!wrapRef.current) return
    const ob = new ResizeObserver(entries => {
      const { width, height } = entries[0].contentRect
      if (width > 50 && height > 50) { setCanvasSize({ w: Math.floor(width), h: Math.floor(height) }); needsInit.current = true }
    })
    ob.observe(wrapRef.current)
    return () => ob.disconnect()
  }, [])

  useEffect(() => { needsInit.current = true }, [ipNode.id])

  useEffect(() => {
    if (!sg.nodes.length || !canvasRef.current) return
    const canvas = canvasRef.current
    const { w: W, h: H } = canvasSize
    const ctx = canvas.getContext('2d')

    if (needsInit.current) {
      nodesRef.current = initLayout(sg.nodes, sg.edges, W, H)
      needsInit.current = false
    }

    const nodeById = {}
    nodesRef.current.forEach(n => { nodeById[n.id] = n })

    const draw = () => {
      ctx.clearRect(0, 0, W, H)
      ctx.fillStyle = '#090e1c'; ctx.fillRect(0, 0, W, H)

      sg.edges.forEach(e => {
        const s = nodeById[e.source], t = nodeById[e.target]
        if (!s || !t) return
        ctx.beginPath(); ctx.moveTo(s.x, s.y); ctx.lineTo(t.x, t.y)
        ctx.strokeStyle = '#1a3050'; ctx.lineWidth = 1; ctx.stroke()
      })

      nodesRef.current.forEach(n => {
        const cfg = NODE_CFG[n.type] || NODE_CFG.alert
        const r = cfg.r
        const isSel = selected?.id === n.id
        const isHit = search.length > 1 && n.label.toLowerCase().includes(search.toLowerCase())

        if (isSel || isHit) {
          ctx.beginPath(); ctx.arc(n.x, n.y, r + 7, 0, Math.PI * 2)
          const g = ctx.createRadialGradient(n.x, n.y, r, n.x, n.y, r + 7)
          g.addColorStop(0, `${cfg.color}44`); g.addColorStop(1, 'transparent')
          ctx.fillStyle = g; ctx.fill()
        }

        ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, Math.PI * 2)
        const grad = ctx.createRadialGradient(n.x - r * 0.3, n.y - r * 0.3, 0, n.x, n.y, r)
        grad.addColorStop(0, `${cfg.color}ee`); grad.addColorStop(1, `${cfg.color}55`)
        ctx.fillStyle = grad; ctx.fill()
        ctx.strokeStyle = isSel ? '#fff' : `${cfg.color}bb`; ctx.lineWidth = isSel ? 2 : 1; ctx.stroke()

        const label = n.label.length > 13 ? n.label.slice(0, 12) + '…' : n.label
        ctx.font = '9px -apple-system, sans-serif'; ctx.textAlign = 'center'
        const lw = ctx.measureText(label).width
        ctx.fillStyle = '#070c18ee'
        ctx.beginPath(); ctx.roundRect(n.x - lw / 2 - 2, n.y + r + 2, lw + 4, 12, 2); ctx.fill()
        ctx.fillStyle = isSel ? '#fff' : '#607a90'
        ctx.fillText(label, n.x, n.y + r + 11)
      })
    }

    const simulate = () => {
      const REPEL = 3000, ATTRACT = 0.018, DAMP = 0.80, CX = 0.003, CY = 0.004, CAP = 3, IDEAL = 90
      nodesRef.current.forEach(a => {
        if (dragging.current === a) return
        a.vx += (W / 2 - a.x) * CX; a.vy += (H / 2 - a.y) * CY
        nodesRef.current.forEach(b => {
          if (a === b) return
          const dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy + 1
          if (d2 < 130 * 130) { const d = Math.sqrt(d2), f = REPEL / d2; a.vx += dx / d * f; a.vy += dy / d * f }
        })
      })
      sg.edges.forEach(e => {
        const s = nodeById[e.source], t = nodeById[e.target]
        if (!s || !t) return
        const dx = t.x - s.x, dy = t.y - s.y, d = Math.sqrt(dx * dx + dy * dy) || 1
        const f = (d - IDEAL) * ATTRACT
        s.vx += dx / d * f; s.vy += dy / d * f; t.vx -= dx / d * f; t.vy -= dy / d * f
      })
      nodesRef.current.forEach(n => {
        if (dragging.current === n) return
        n.vx *= DAMP; n.vy *= DAMP
        const sp = Math.hypot(n.vx, n.vy)
        if (sp > CAP) { n.vx = n.vx / sp * CAP; n.vy = n.vy / sp * CAP }
        n.x = Math.max(20, Math.min(W - 20, n.x + n.vx))
        n.y = Math.max(20, Math.min(H - 20, n.y + n.vy))
      })
      draw(); animRef.current = requestAnimationFrame(simulate)
    }

    cancelAnimationFrame(animRef.current)
    animRef.current = requestAnimationFrame(simulate)

    const toC = e => { const r = canvas.getBoundingClientRect(); return { x: (e.clientX - r.left) * (W / r.width), y: (e.clientY - r.top) * (H / r.height) } }
    const getNode = (x, y) => nodesRef.current.find(n => Math.hypot(n.x - x, n.y - y) < (NODE_CFG[n.type] || NODE_CFG.alert).r + 5)

    const onClick = async e => {
      const { x, y } = toC(e); const n = getNode(x, y)
      if (!n) { setSelected(null); setDesc(null); return }
      setSelected(n)
      try { const r = await fetch(`${API}/api/graph/${encodeURIComponent(n.id)}`); setDesc((await r.json()).description) }
      catch { setDesc(null) }
    }
    const onDown = e => { const { x, y } = toC(e); const n = getNode(x, y); if (n) { dragging.current = n; canvas.style.cursor = 'grabbing' } }
    const onMove = e => { if (!dragging.current) return; const { x, y } = toC(e); dragging.current.x = x; dragging.current.y = y; dragging.current.vx = dragging.current.vy = 0 }
    const onUp = () => { dragging.current = null; canvas.style.cursor = 'default' }

    canvas.addEventListener('click', onClick); canvas.addEventListener('mousedown', onDown)
    window.addEventListener('mousemove', onMove); window.addEventListener('mouseup', onUp)
    return () => {
      cancelAnimationFrame(animRef.current)
      canvas.removeEventListener('click', onClick); canvas.removeEventListener('mousedown', onDown)
      window.removeEventListener('mousemove', onMove); window.removeEventListener('mouseup', onUp)
    }
  }, [sg.nodes.length, sg.edges.length, selected, search, canvasSize])

  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 8, marginBottom: 12, overflow: 'hidden' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 14px', background: '#0d1625', borderBottom: '1px solid var(--border)' }}>
        <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#ef4444', boxShadow: '0 0 6px #ef4444aa' }} />
        <span style={{ fontFamily: 'var(--mono)', fontSize: 13, fontWeight: 700, color: '#ef4444' }}>{ipNode.label}</span>
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{sg.nodes.length} nodes · {sg.edges.length} edges</span>
        {selected && (
          <div style={{ marginLeft: 'auto', padding: '3px 10px', background: `${NODE_CFG[selected.type]?.color || '#94a3b8'}22`, border: `1px solid ${NODE_CFG[selected.type]?.color || '#94a3b8'}44`, borderRadius: 5, fontSize: 11, color: NODE_CFG[selected.type]?.color || 'var(--accent-cyan)', fontWeight: 600, fontFamily: 'var(--mono)' }}>
            {selected.type.replace('_',' ')}: {selected.label}
          </div>
        )}
      </div>
      <div style={{ display: 'flex' }}>
        <div ref={wrapRef} style={{ flex: 1, height: 280, position: 'relative', background: '#090e1c' }}>
          <canvas ref={canvasRef} width={canvasSize.w} height={canvasSize.h} style={{ position: 'absolute', inset: 0, width: '100%', height: '100%' }} />
          <div style={{ position: 'absolute', bottom: 6, left: 10, fontSize: 9, color: '#1a3050', pointerEvents: 'none' }}>Click to inspect · Drag to reposition</div>
        </div>
        {selected && desc && (
          <div style={{ width: 210, flexShrink: 0, background: '#0d1625', borderLeft: '1px solid var(--border)', padding: '12px', overflowY: 'auto', maxHeight: 280 }}>
            <div style={{ fontFamily: 'var(--mono)', fontSize: 12, color: NODE_CFG[selected.type]?.color || 'var(--accent-cyan)', fontWeight: 700, marginBottom: 8, wordBreak: 'break-all' }}>{selected.label}</div>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.7 }}>
              {desc.split('\n').slice(0, 14).map((line, i) => {
                if (!line.trim()) return <div key={i} style={{ height: 4 }} />
                if (line.startsWith('Total') || line.startsWith('MITRE') || line.startsWith('Assoc'))
                  return <div key={i} style={{ color: 'var(--text-primary)', fontWeight: 600, marginTop: 6, marginBottom: 2 }}>{line}</div>
                if (line.startsWith('  -'))
                  return <div key={i} style={{ display: 'flex', gap: 4, paddingLeft: 4 }}><span style={{ color: 'var(--accent-cyan)' }}>·</span><span>{line.slice(3)}</span></div>
                return <div key={i} style={{ color: 'var(--text-muted)', fontSize: 10 }}>{line}</div>
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default function KnowledgeGraphPanel() {
  const [allNodes, setAllNodes] = useState([])
  const [allEdges, setAllEdges] = useState([])
  const [sourceIPs, setSourceIPs] = useState([])
  const [nodeCount, setNodeCount] = useState(0)
  const [edgeCount, setEdgeCount] = useState(0)
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(true)

  const fetchGraph = useCallback(async () => {
    setLoading(true)
    try {
      const res = await fetch(`${API}/api/graph`)
      const data = await res.json()
      const nodes = data.nodes || []
      const edges = data.edges || []
      setAllNodes(nodes)
      setAllEdges(edges)
      setNodeCount(data.node_count || nodes.length)
      setEdgeCount(data.edge_count || edges.length)
      setSourceIPs(nodes.filter(n => n.type === 'source_ip'))
    } catch {}
    setLoading(false)
  }, [])

  useEffect(() => { fetchGraph() }, [])

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
        <div style={{ width: 32, height: 32, borderRadius: 8, background: '#06b6d422', border: '1px solid #06b6d444', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Network size={14} color="var(--accent-cyan)" />
        </div>
        <div>
          <div style={{ fontWeight: 700, fontSize: 15 }}>Knowledge Graph</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            {nodeCount} nodes · {edgeCount} edges
            {sourceIPs.length > 0 && <span style={{ marginLeft: 8, color: '#4ade80', fontWeight: 600 }}>· {sourceIPs.length} source IP{sourceIPs.length > 1 ? 's' : ''}</span>}
          </div>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, alignItems: 'center' }}>
          {Object.entries(NODE_CFG).map(([t, c]) => (
            <span key={t} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, color: 'var(--text-muted)' }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: c.color }} />{c.label}
            </span>
          ))}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, padding: '4px 10px', marginLeft: 6 }}>
            <Search size={11} color="var(--text-muted)" />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Highlight..." style={{ background: 'none', border: 'none', outline: 'none', color: 'var(--text-primary)', fontSize: 11, width: 90 }} />
          </div>
          <button onClick={fetchGraph} style={{ width: 28, height: 28, borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-card)', color: 'var(--text-muted)', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <RefreshCw size={12} />
          </button>
        </div>
      </div>

      <div style={{ flex: 1, overflowY: 'auto' }}>
        {loading ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 200, color: 'var(--text-muted)' }}>Loading...</div>
        ) : nodeCount === 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: 200, color: 'var(--text-muted)', gap: 10 }}>
            <Network size={36} style={{ opacity: 0.15 }} />
            <div style={{ fontSize: 14, fontWeight: 500 }}>No graph data</div>
            <div style={{ fontSize: 12 }}>Run kill chain then click refresh</div>
          </div>
        ) : sourceIPs.length === 0 ? (
          // No source_ip nodes — show single unified graph
          <SingleIPGraph
            ipNode={{ id: '__all__', label: 'All Sources', type: 'source_ip' }}
            allNodes={allNodes}
            allEdges={allEdges}
            search={search}
          />
        ) : (
          sourceIPs.map((ip) => (
            <SingleIPGraph
              key={ip.id}
              ipNode={ip}
              allNodes={allNodes}
              allEdges={allEdges}
              search={search}
            />
          ))
        )}
      </div>
    </div>
  )
}
