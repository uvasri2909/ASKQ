import { AppShell } from './components/AppShell'
import { LoginPage } from './components/LoginPage'
import { useSession } from './auth/context'
import { SessionProvider } from './auth/session'

function Root() {
  const { user } = useSession()
  // No session, no application: every authenticated view lives inside AppShell.
  return user === null ? <LoginPage /> : <AppShell user={user} />
}

export default function App() {
  return (
    <SessionProvider>
      <Root />
    </SessionProvider>
  )
}
