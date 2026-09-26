import { useEffect, useState } from 'react'
import { getHealth, type HealthResponse } from './api/client'

type BackendState =
  | { kind: 'checking' }
  | { kind: 'online'; health: HealthResponse }
  | { kind: 'offline'; error: string }

function App() {
  const [backend, setBackend] = useState<BackendState>({ kind: 'checking' })

  useEffect(() => {
    const controller = new AbortController()
    getHealth(controller.signal)
      .then((health) => setBackend({ kind: 'online', health }))
      .catch((err: unknown) => {
        if (controller.signal.aborted) return
        setBackend({ kind: 'offline', error: err instanceof Error ? err.message : String(err) })
      })
    return () => controller.abort()
  }, [])

  return (
    <main className="shell">
      <h1>ASKQ</h1>
      <p className="tagline">Ask Questions to your Data</p>

      <section className="status-card" aria-label="Backend status">
        <h2>Backend status</h2>
        {backend.kind === 'checking' && <p>Checking backend…</p>}
        {backend.kind === 'online' && (
          <p className="ok">
            Online: {backend.health.service} v{backend.health.version} (
            {backend.health.environment})
          </p>
        )}
        {backend.kind === 'offline' && (
          <p className="error">Offline: {backend.error}</p>
        )}
      </section>

      <p className="phase-note">Phase 1 scaffold: development environment only.</p>
    </main>
  )
}

export default App
