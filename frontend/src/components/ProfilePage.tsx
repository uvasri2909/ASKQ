import type { User } from '../api/types'
import { ROLE_LABEL } from '../format'

// Describes the role in words only; what a user may see is decided by the
// backend on every request, never by this page.
const SCOPE_TEXT: Record<string, string> = {
  ADMIN: 'Individual records across the whole university.',
  HOD: 'Individual records within your department; university-wide statistics as aggregates.',
  TEACHER:
    'Individual records for the students you teach or advise; university-wide statistics as aggregates.',
  STUDENT: 'Your own records; university-wide statistics as aggregates.',
}

export function ProfilePage({ user }: { user: User }) {
  return (
    <section className="page" aria-labelledby="profile-title">
      <header className="page-head">
        <h1 id="profile-title">Profile</h1>
      </header>
      <dl className="profile">
        <dt>Username</dt>
        <dd>{user.username}</dd>
        <dt>Role</dt>
        <dd>{ROLE_LABEL[user.role] ?? user.role}</dd>
        <dt>Data you can ask about</dt>
        <dd>{SCOPE_TEXT[user.role] ?? '—'}</dd>
        <dt>Permissions</dt>
        <dd>
          <ul className="plain-list">
            {user.permissions.map((p) => (
              <li key={p}>{p.replaceAll('_', ' ').toLowerCase()}</li>
            ))}
          </ul>
        </dd>
      </dl>
      <h2>How ASKQ protects the data</h2>
      <ol className="plain-list numbered">
        <li>Your question is turned into SQL by a language model, which is never trusted.</li>
        <li>The SQL is parsed and checked: only a single safe, read-only query is allowed.</li>
        <li>Your role's access rules are applied on the server, whatever the question says.</li>
        <li>
          CAIR checks whether the answer, combined with your earlier questions, could reveal
          information about individuals, and withholds it if so.
        </li>
        <li>Only then does the query run, on a read-only database account.</li>
      </ol>
    </section>
  )
}
