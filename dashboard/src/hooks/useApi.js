import { useState, useEffect } from 'react'

const API = 'http://localhost:8000'

async function apiFetch(path) {
  const res = await fetch(API + path)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

export function useRules() {
  const [rules, setRules] = useState([])
  const [loading, setLoading] = useState(true)
  useEffect(() => {
    apiFetch('/api/rules').then(setRules).catch(() => {}).finally(() => setLoading(false))
  }, [])
  return { rules, loading }
}

export function useChains() {
  const [chains, setChains] = useState([])
  useEffect(() => {
    apiFetch('/api/chains').then(setChains).catch(() => {})
  }, [])
  return chains
}

export function useCoverage() {
  const [coverage, setCoverage] = useState(null)
  useEffect(() => {
    apiFetch('/api/coverage').then(setCoverage).catch(() => {})
  }, [])
  return coverage
}

export function useHealth() {
  const [health, setHealth] = useState(null)
  useEffect(() => {
    const check = () => apiFetch('/api/health').then(setHealth).catch(() => setHealth(null))
    check()
    const id = setInterval(check, 10000)
    return () => clearInterval(id)
  }, [])
  return health
}
