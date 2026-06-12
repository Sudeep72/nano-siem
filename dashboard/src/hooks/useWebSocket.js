import { useState, useEffect, useRef, useCallback } from 'react'

const WS_URL = 'ws://localhost:8000/ws/events'
const MAX_EVENTS = 200
const MAX_ALERTS = 100

export function useWebSocket() {
  const [connected, setConnected] = useState(false)
  const [events, setEvents] = useState([])
  const [alerts, setAlerts] = useState([])
  const [stats, setStats] = useState({
    events_processed: 0, sigma_hits: 0, chain_alerts: 0,
    ml_anomalies: 0, alerts_written: 0, deduped: 0,
    events_per_sec: 0, uptime_seconds: 0, tracked_sources: 0,
    ml_avg_score: 0, ml_max_score: 0,
  })
  const wsRef = useRef(null)
  const reconnectRef = useRef(null)

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return

    try {
      const ws = new WebSocket(WS_URL)
      wsRef.current = ws

      ws.onopen = () => {
        setConnected(true)
        if (reconnectRef.current) {
          clearTimeout(reconnectRef.current)
          reconnectRef.current = null
        }
      }

      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data)
          if (msg.type === 'event') {
            setEvents(prev => [msg.data, ...prev].slice(0, MAX_EVENTS))
          } else if (msg.type === 'alert') {
            setAlerts(prev => [msg.data, ...prev].slice(0, MAX_ALERTS))
          } else if (msg.type === 'stats') {
            setStats(msg.data)
          }
        } catch {}
      }

      ws.onclose = () => {
        setConnected(false)
        reconnectRef.current = setTimeout(connect, 3000)
      }

      ws.onerror = () => {
        ws.close()
      }
    } catch {}
  }, [])

  useEffect(() => {
    connect()
    return () => {
      if (reconnectRef.current) clearTimeout(reconnectRef.current)
      wsRef.current?.close()
    }
  }, [connect])

  return { connected, events, alerts, stats }
}
