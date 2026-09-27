import { createContext, useContext } from 'react'
import type { User } from '../api/types'

export interface SessionValue {
  user: User | null
  notice: string | null
  signIn: (username: string, password: string) => Promise<void>
  signOut: () => void
}

export const SessionContext = createContext<SessionValue | null>(null)

export function useSession(): SessionValue {
  const value = useContext(SessionContext)
  if (value === null) throw new Error('useSession must be used inside <SessionProvider>')
  return value
}
