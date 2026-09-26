import { render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App'

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('App smoke test', () => {
  it('renders the ASKQ title and reports an online backend', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            status: 'ok',
            service: 'askq-backend',
            version: '0.1.0',
            environment: 'test',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      ),
    )

    render(<App />)

    expect(screen.getByRole('heading', { name: 'ASKQ' })).toBeInTheDocument()
    expect(await screen.findByText(/Online: askq-backend v0\.1\.0/)).toBeInTheDocument()
  })

  it('reports an offline backend when the health check fails', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('', { status: 503 })))

    render(<App />)

    expect(await screen.findByText(/Offline: Backend returned HTTP 503/)).toBeInTheDocument()
  })
})
