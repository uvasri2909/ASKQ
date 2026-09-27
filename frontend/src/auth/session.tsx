// Session state. The backend is the source of truth: after login the user
// (role, permissions) is taken from the login response, and every later
// request is re-authorized by the server. The token stays in api/client.ts
// memory only; the password is never stored.

import { useCallback, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { login as apiLogin } from '../api/askq'
import { setAccessToken, setUnauthorizedHandler } from '../api/client'
import type { User } from '../api/types'
import { SessionContext } from './context'

export function SessionProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const signOut = useCallback(() => {
    setAccessToken(null)
    setUser(null)
  }, [])

  useEffect(() => {
    // Any 401 from an authenticated call ends the session.
    setUnauthorizedHandler(() => {
      setAccessToken(null)
      setUser(null)
      setNotice('Your session has ended. Please sign in again.')
    })
    return () => setUnauthorizedHandler(null)
  }, [])

  const signIn = useCallback(async (username: string, password: string) => {
    const result = await apiLogin(username, password)
    setAccessToken(result.accessToken)
    setNotice(null)
    setUser(result.user)
  }, [])

  const value = useMemo(() => ({ user, notice, signIn, signOut }), [user, notice, signIn, signOut])
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>
}
