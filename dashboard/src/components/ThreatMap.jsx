import { useEffect, useRef, useState } from 'react'
import { Globe, AlertTriangle } from 'lucide-react'

const API = 'http://localhost:8000'
const SEV_COLOR = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#4ade80' }
const RISK_COLOR = { high: '#ef4444', medium: '#f97316', low: '#4ade80', unknown: '#94a3b8', internal: '#6366f1' }

function project(lat, lon, W, H) {
  return { x: ((lon + 180) / 360) * W, y: ((90 - lat) / 180) * H }
}

function drawGeometry(ctx, geometry, W, H) {
  const drawRing = (ring) => {
    if (!ring.length) return
    ctx.beginPath()
    ring.forEach(([lon, lat], i) => {
      const { x, y } = project(lat, lon, W, H)
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y)
    })
    ctx.closePath(); ctx.fill(); ctx.stroke()
  }
  if (geometry.type === 'Polygon') geometry.coordinates.forEach(drawRing)
  else if (geometry.type === 'MultiPolygon') geometry.coordinates.forEach(p => p.forEach(drawRing))
}

export default function ThreatMap({ alerts }) {
  const canvasRef = useRef(null)
  const wrapRef = useRef(null)
  const [enriched, setEnriched] = useState({})
  const [loading, setLoading] = useState(false)
  const [selected, setSelected] = useState(null)
  const [countries, setCountries] = useState(null)
  const [canvasSize, setCanvasSize] = useState({ w: 960, h: 480 })

  useEffect(() => {
    fetch('https://raw.githubusercontent.com/holtzy/D3-graph-gallery/master/DATA/world.geojson')
      .then(r => r.json())
      .then(data => setCountries(data.features))
      .catch(() => setCountries([]))
  }, [])

  useEffect(() => {
    if (!wrapRef.current) return
    const ob = new ResizeObserver(entries => {
      const { width, height } = entries[0].contentRect
      if (width > 100 && height > 100) setCanvasSize({ w: Math.floor(width), h: Math.floor(height) })
    })
    ob.observe(wrapRef.current)
    return () => ob.disconnect()
  }, [])

  useEffect(() => {
    const ips = [...new Set(alerts.map(a => a.source_key).filter(ip => ip && /^\d+\.\d+\.\d+\.\d+$/.test(ip)))]
    const toFetch = ips.filter(ip => !enriched[ip])
    if (!toFetch.length) return
    setLoading(true)
    Promise.all(toFetch.map(ip =>
      fetch(`${API}/api/enrich/${ip}`).then(r => r.json()).then(d => [ip, d]).catch(() => null)
    )).then(results => {
      const map = {}
      results.filter(Boolean).forEach(([ip, d]) => { map[ip] = d })
      setEnriched(prev => ({ ...prev, ...map }))
      setLoading(false)
    })
  }, [alerts.length])

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    const { w: W, h: H } = canvasSize

    ctx.clearRect(0, 0, W, H)

    // Ocean gradient
    const oceanGrad = ctx.createLinearGradient(0, 0, 0, H)
    oceanGrad.addColorStop(0, '#0a1628')
    oceanGrad.addColorStop(1, '#060e1a')
    ctx.fillStyle = oceanGrad
    ctx.fillRect(0, 0, W, H)

    // Subtle grid
    ctx.strokeStyle = '#0f2040'
    ctx.lineWidth = 0.4
    for (let lon = -180; lon <= 180; lon += 30) {
      const x = ((lon + 180) / 360) * W
      ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke()
    }
    for (let lat = -90; lat <= 90; lat += 30) {
      const y = ((90 - lat) / 180) * H
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke()
    }

    // Countries
    if (countries && countries.length > 0) {
      ctx.fillStyle = '#162440'
      ctx.strokeStyle = '#1e3a5f'
      ctx.lineWidth = 0.5
      countries.forEach(f => { if (f.geometry) drawGeometry(ctx, f.geometry, W, H) })
    }

    // Equator
    ctx.strokeStyle = '#1a3050'
    ctx.lineWidth = 0.8
    ctx.setLineDash([3, 6])
    ctx.beginPath(); ctx.moveTo(0, H / 2); ctx.lineTo(W, H / 2); ctx.stroke()
    ctx.setLineDash([])

    // IP markers — SMALLER dots
    const ipMap = {}
    alerts.forEach(a => {
      const ip = a.source_key
      if (!ip || !/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return
      if (!ipMap[ip]) ipMap[ip] = []
      ipMap[ip].push(a)
    })

    Object.entries(ipMap).forEach(([ip, ipAlerts]) => {
      const geo = enriched[ip]
      if (!geo || geo.is_private || !geo.latitude || !geo.longitude) return

      const { x, y } = project(geo.latitude, geo.longitude, W, H)
      const topSev = ipAlerts.reduce((b, a) => {
        const rank = { critical: 4, high: 3, medium: 2, low: 1 }
        return (rank[a.severity] || 0) > (rank[b] || 0) ? a.severity : b
      }, 'low')
      const color = SEV_COLOR[topSev] || '#94a3b8'

      // SMALLER: base 6px + 1.5px per alert, max 14px (was 10 + 2*count max 22)
      const r = Math.min(6 + ipAlerts.length * 1.5, 14)
      const isSel = selected?.ip === ip

      // Outer pulse ring — subtle
      ctx.beginPath()
      ctx.arc(x, y, r + 6, 0, Math.PI * 2)
      const pulse = ctx.createRadialGradient(x, y, r, x, y, r + 6)
      pulse.addColorStop(0, `${color}28`)
      pulse.addColorStop(1, 'transparent')
      ctx.fillStyle = pulse
      ctx.fill()

      // Main dot
      const dotGrad = ctx.createRadialGradient(x - r * 0.3, y - r * 0.3, 0, x, y, r)
      dotGrad.addColorStop(0, isSel ? '#ffffff' : `${color}ff`)
      dotGrad.addColorStop(1, `${color}88`)
      ctx.beginPath()
      ctx.arc(x, y, r, 0, Math.PI * 2)
      ctx.fillStyle = dotGrad
      ctx.fill()
      ctx.strokeStyle = isSel ? '#ffffff' : color
      ctx.lineWidth = isSel ? 2 : 1.2
      ctx.stroke()

      // Count badge — only if > 1, and smaller
      if (ipAlerts.length > 1) {
        const badgeR = 7
        ctx.beginPath()
        ctx.arc(x + r - 1, y - r + 1, badgeR, 0, Math.PI * 2)
        ctx.fillStyle = color; ctx.fill()
        ctx.fillStyle = '#fff'
        ctx.font = 'bold 8px monospace'
        ctx.textAlign = 'center'
        ctx.fillText(ipAlerts.length, x + r - 1, y - r + 4)
      }

      // Location label
      const label = geo.city ? `${geo.city}, ${geo.country_code}` : ip
      ctx.font = `${isSel ? 'bold ' : ''}9px -apple-system, sans-serif`
      ctx.textAlign = 'center'
      const lw = ctx.measureText(label).width
      ctx.fillStyle = '#0a1628cc'
      ctx.beginPath()
      ctx.roundRect(x - lw / 2 - 3, y + r + 3, lw + 6, 12, 2)
      ctx.fill()
      ctx.fillStyle = isSel ? '#06b6d4' : '#5a7090'
      ctx.fillText(label, x, y + r + 12)
    })

  }, [countries, enriched, alerts, canvasSize, selected])

  const handleClick = (e) => {
    const canvas = canvasRef.current
    if (!canvas) return
    const rect = canvas.getBoundingClientRect()
    const mx = (e.clientX - rect.left) * (canvasSize.w / rect.width)
    const my = (e.clientY - rect.top) * (canvasSize.h / rect.height)
    const { w: W, h: H } = canvasSize
    const ipMap = {}
    alerts.forEach(a => { if (a.source_key) { if (!ipMap[a.source_key]) ipMap[a.source_key] = []; ipMap[a.source_key].push(a) } })
    let clicked = null
    Object.entries(ipMap).forEach(([ip, ipAlerts]) => {
      const geo = enriched[ip]
      if (!geo || geo.is_private || !geo.latitude || !geo.longitude) return
      const { x, y } = project(geo.latitude, geo.longitude, W, H)
      const r = Math.min(6 + ipAlerts.length * 1.5, 14)
      if (Math.hypot(mx - x, my - y) < r + 8) {
        const topSev = ipAlerts.reduce((b, a) => ({ critical: 4, high: 3, medium: 2, low: 1 }[a.severity] > ({ critical: 4, high: 3, medium: 2, low: 1 }[b] || 0) ? a.severity : b), 'low')
        clicked = { ip, geo, alerts: ipAlerts, topSev }
      }
    })
    setSelected(clicked)
  }

  const geolocated = Object.values(enriched).filter(d => !d.is_private && d.latitude).length

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
        <div style={{ width: 32, height: 32, borderRadius: 8, background: '#06b6d422', border: '1px solid #06b6d444', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Globe size={14} color="var(--accent-cyan)" />
        </div>
        <div>
          <div style={{ fontWeight: 700, fontSize: 15 }}>Threat Map</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            {loading ? 'Enriching IPs...' : countries === null ? 'Loading world map...' : `${geolocated} IP(s) geolocated · ${alerts.length} alerts`}
          </div>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 14 }}>
          {Object.entries(SEV_COLOR).map(([sev, color]) => (
            <span key={sev} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, color: 'var(--text-secondary)' }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: color, boxShadow: `0 0 3px ${color}` }} />{sev}
            </span>
          ))}
        </div>
      </div>

      <div style={{ flex: 1, display: 'flex', gap: 12, minHeight: 0 }}>
        <div ref={wrapRef} style={{ flex: 1, position: 'relative', borderRadius: 8, border: '1px solid var(--border)', overflow: 'hidden', background: '#060e1a' }}>
          <canvas ref={canvasRef} width={canvasSize.w} height={canvasSize.h} style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', cursor: 'crosshair' }} onClick={handleClick} />
          {countries === null && (
            <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: 12 }}>
              Loading world map...
            </div>
          )}
          <div style={{ position: 'absolute', bottom: 8, right: 12, fontSize: 9, color: '#1e3a5f', pointerEvents: 'none', fontStyle: 'italic' }}>Natural Earth · Equirectangular</div>
          <div style={{ position: 'absolute', bottom: 8, left: 12, fontSize: 9, color: '#253655', pointerEvents: 'none' }}>Click a marker to inspect</div>
        </div>

        {selected && (
          <div style={{ width: 230, flexShrink: 0, background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: 14, overflowY: 'auto' }}>
            <div style={{ fontFamily: 'var(--mono)', color: 'var(--accent-cyan)', fontWeight: 700, fontSize: 13, marginBottom: 6, wordBreak: 'break-all' }}>{selected.ip}</div>
            <div style={{ marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
              <span className={`badge badge-${selected.topSev}`}>{selected.topSev?.toUpperCase()}</span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{selected.alerts.length} alert(s)</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 9, fontSize: 12 }}>
              {selected.geo.country && <div><div style={{ color: 'var(--text-muted)', fontSize: 10, textTransform: 'uppercase', marginBottom: 2 }}>Location</div><div style={{ color: 'var(--text-primary)' }}>{[selected.geo.city, selected.geo.region, selected.geo.country].filter(Boolean).join(', ')}</div></div>}
              {selected.geo.isp && <div><div style={{ color: 'var(--text-muted)', fontSize: 10, textTransform: 'uppercase', marginBottom: 2 }}>ISP</div><div style={{ color: 'var(--text-secondary)' }}>{selected.geo.isp}</div></div>}
              {selected.geo.asn && <div><div style={{ color: 'var(--text-muted)', fontSize: 10, textTransform: 'uppercase', marginBottom: 2 }}>ASN</div><div style={{ color: 'var(--text-secondary)', fontFamily: 'var(--mono)', fontSize: 11 }}>{selected.geo.asn}</div></div>}
              {selected.geo.latitude && <div><div style={{ color: 'var(--text-muted)', fontSize: 10, textTransform: 'uppercase', marginBottom: 2 }}>Coordinates</div><div style={{ color: 'var(--text-secondary)', fontFamily: 'var(--mono)', fontSize: 11 }}>{selected.geo.latitude?.toFixed(3)}°, {selected.geo.longitude?.toFixed(3)}°</div></div>}
              {selected.geo.is_hosting && <div style={{ padding: '4px 8px', background: '#7c2d1222', border: '1px solid #7c2d1266', borderRadius: 4, fontSize: 11, color: '#fdba74' }}>⚠ Hosting / datacenter</div>}
              {selected.geo.abuse_score != null && <div><div style={{ color: 'var(--text-muted)', fontSize: 10, textTransform: 'uppercase', marginBottom: 2 }}>Abuse Score</div><div style={{ fontSize: 20, fontWeight: 700, color: RISK_COLOR[selected.geo.risk_level] }}>{selected.geo.abuse_score}<span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 400 }}>/100</span></div></div>}
              <div style={{ borderTop: '1px solid var(--border)', paddingTop: 8 }}>
                <div style={{ color: 'var(--text-muted)', fontSize: 10, textTransform: 'uppercase', marginBottom: 5 }}>Alerts ({selected.alerts.length})</div>
                {selected.alerts.slice(0, 5).map((a, i) => (
                  <div key={i} style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 4 }}>
                    <span className={`badge badge-${a.severity}`}>{a.severity?.slice(0, 4).toUpperCase()}</span>
                    <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{a.title?.slice(0, 24)}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {geolocated === 0 && alerts.length > 0 && !loading && countries !== null && (
        <div style={{ padding: '7px 12px', borderRadius: 6, fontSize: 11, background: '#1e293b', border: '1px solid var(--border)', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
          <AlertTriangle size={12} color="#eab308" />
          No geolocatable IPs found. Run: <code style={{ color: 'var(--accent-cyan)', fontFamily: 'var(--mono)' }}>bash examples/send_kill_chain.sh</code>
        </div>
      )}
    </div>
  )
}
