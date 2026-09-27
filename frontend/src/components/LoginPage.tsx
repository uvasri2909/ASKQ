import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { ApiError, getHealth } from '../api/client'
import { useSession } from '../auth/context'
import { ErrorNote } from './Status'

// Deliberately the same text for every credential failure: the page never
// says whether the username exists or the account is locked.
const INVALID = 'Invalid username or password.'

function loginError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.kind === 'unauthorized') return INVALID
    if (error.kind === 'validation') return 'Enter your username and password.'
    return error.message
  }
  return 'Sign-in failed. Please try again.'
}

export function LoginPage() {
  const { signIn, notice } = useSession()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    getHealth(controller.signal)
      .then(() => setBackendOnline(true))
      .catch(() => {
        if (!controller.signal.aborted) setBackendOnline(false)
      })
    return () => controller.abort()
  }, [])

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!username.trim() || !password) {
      setError('Enter your username and password.')
      return
    }
    setBusy(true)
    setError(null)
    try {
      await signIn(username.trim(), password)
    } catch (err) {
      setError(loginError(err))
    } finally {
      setPassword('') // never kept after an attempt
      setBusy(false)
    }
  }

  return (
    <main className="login">
      <form className="login-card" onSubmit={submit} noValidate aria-labelledby="login-title">
        <h1 id="login-title" className="brand">
          ASKQ
        </h1>
        <p className="tagline">Ask questions to your university data, securely.</p>

        {notice && <p className="state state-info">{notice}</p>}

        <label htmlFor="username">Username</label>
        <input
          id="username"
          name="username"
          autoComplete="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          maxLength={50}
          disabled={busy}
          required
        />

        <label htmlFor="password">Password</label>
        <input
          id="password"
          name="password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          maxLength={1024}
          disabled={busy}
          required
        />

        {error && <ErrorNote message={error} />}

        <button type="submit" className="button button-primary" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>

        <p className="login-status" aria-live="polite">
          Server:{' '}
          {backendOnline === null
            ? 'checking…'
            : backendOnline
              ? 'online'
              : 'unreachable'}
        </p>
      </form>
    </main>
  )
}
