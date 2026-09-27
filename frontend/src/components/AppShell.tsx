// The authenticated layout. Navigation reflects the permissions the backend
// reported, purely for convenience; the backend re-checks every request.

import { useState } from 'react'
import type { User } from '../api/types'
import { useSession } from '../auth/context'
import { ROLE_LABEL } from '../format'
import { AskPage } from './AskPage'
import { HistoryPage } from './HistoryPage'
import { ProfilePage } from './ProfilePage'

type View = 'ask' | 'history' | 'profile'

const NAV: { view: View; label: string; permission: string | null }[] = [
  { view: 'ask', label: 'Ask ASKQ', permission: 'ASK_QUESTIONS' },
  { view: 'history', label: 'Query history', permission: 'VIEW_OWN_HISTORY' },
  { view: 'profile', label: 'Profile', permission: null },
]

export function AppShell({ user }: { user: User }) {
  const { signOut } = useSession()
  const items = NAV.filter((n) => n.permission === null || user.permissions.includes(n.permission))
  const [view, setView] = useState<View>(items[0]?.view ?? 'profile')
  const [conversation, setConversation] = useState<string | null>(null)
  const [menuOpen, setMenuOpen] = useState(false)
  // Re-mount the Ask page when a conversation is opened from History.
  const [askKey, setAskKey] = useState(0)

  function go(next: View) {
    setView(next)
    setMenuOpen(false)
    if (next === 'ask') {
      setConversation(null)
      setAskKey((k) => k + 1)
    }
  }

  function openConversation(id: string) {
    setConversation(id)
    setAskKey((k) => k + 1)
    setView('ask')
  }

  return (
    <div className="shell">
      <header className="topbar">
        <button
          type="button"
          className="menu-button"
          aria-expanded={menuOpen}
          aria-controls="sidebar"
          onClick={() => setMenuOpen((open) => !open)}
        >
          Menu
        </button>
        <span className="brand brand-small">ASKQ</span>
      </header>

      <nav id="sidebar" className={`sidebar${menuOpen ? ' open' : ''}`} aria-label="Main">
        <div className="brand">ASKQ</div>
        <ul className="nav-list">
          {items.map((item) => (
            <li key={item.view}>
              <button
                type="button"
                className={`nav-item${view === item.view ? ' active' : ''}`}
                aria-current={view === item.view ? 'page' : undefined}
                onClick={() => go(item.view)}
              >
                {item.label}
              </button>
            </li>
          ))}
        </ul>
        <div className="user-box">
          <span className="user-name">{user.username}</span>
          <span className={`role role-${user.role.toLowerCase()}`}>{ROLE_LABEL[user.role] ?? user.role}</span>
          <button type="button" className="button button-small" onClick={signOut}>
            Sign out
          </button>
        </div>
      </nav>

      <main className="content">
        {view === 'ask' && <AskPage key={askKey} initialConversation={conversation} />}
        {view === 'history' && <HistoryPage onOpen={openConversation} />}
        {view === 'profile' && <ProfilePage user={user} />}
      </main>
    </div>
  )
}
