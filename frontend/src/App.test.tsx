import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'
import { setAccessToken } from './api/client'
import {
  EMPTY_LIST,
  HEALTH,
  HOD,
  TOKEN,
  json,
  loginOk,
  leakyQueryResponse,
  mockApi,
  queryResponse,
} from './test/mockApi'

beforeEach(() => setAccessToken(null))
afterEach(() => vi.unstubAllGlobals())

// Minimal stand-in for user-event: typing sets the value, clicking fires a click.
type Actor = { type: (el: HTMLElement, text: string) => Promise<void>; click: (el: HTMLElement) => Promise<void> }
const actor: Actor = {
  async type(el, text) {
    fireEvent.change(el, { target: { value: ((el as HTMLInputElement).value ?? '') + text } })
  },
  async click(el) {
    fireEvent.click(el)
  },
}
function setupUser(): Actor {
  return actor
}

const BASE_ROUTES = {
  'GET /health': HEALTH,
  'POST /api/v1/auth/login': loginOk(),
  'GET /api/v1/conversations': EMPTY_LIST,
  'GET /api/v1/history': EMPTY_LIST,
}

async function signIn(routes: Record<string, unknown> = {}) {
  const api = mockApi({ ...BASE_ROUTES, ...routes })
  const user = setupUser()
  render(<App />)
  await user.type(screen.getByLabelText('Username'), 't0001')
  await user.type(screen.getByLabelText('Password'), 'correct-horse-battery')
  await user.click(screen.getByRole('button', { name: 'Sign in' }))
  await screen.findByRole('navigation', { name: 'Main' })
  return { api, user }
}

async function ask(user: Actor, text: string) {
  await user.type(screen.getByLabelText('Your question'), text)
  await user.click(screen.getByRole('button', { name: 'Ask' }))
}

// ---------------- authentication and routing ----------------

describe('login and routing', () => {
  it('shows the login page when not signed in', async () => {
    mockApi(BASE_ROUTES)
    render(<App />)
    expect(screen.getByRole('heading', { name: 'ASKQ' })).toBeInTheDocument()
    expect(screen.getByLabelText('Username')).toBeInTheDocument()
    expect(screen.queryByRole('navigation', { name: 'Main' })).not.toBeInTheDocument()
    expect(await screen.findByText(/Server: online/)).toBeInTheDocument()
  })

  it('signs in and shows the backend-reported identity', async () => {
    const { api } = await signIn()
    expect(screen.getByText('t0001')).toBeInTheDocument()
    expect(screen.getByText('Head of Department')).toBeInTheDocument()
    const loginCall = api.calls.find((c) => c.path === '/api/v1/auth/login')
    expect(loginCall?.body).toEqual({ username: 't0001', password: 'correct-horse-battery' })
    // Neither the password nor the token is ever rendered or stored.
    expect(document.body.textContent).not.toContain('correct-horse-battery')
    expect(document.body.innerHTML).not.toContain(TOKEN)
    expect(JSON.stringify(localStorage)).not.toContain(TOKEN)
    expect(JSON.stringify(sessionStorage)).not.toContain(TOKEN)
    // Later calls carry the token as a bearer header.
    const listCall = api.calls.find((c) => c.path.startsWith('/api/v1/conversations'))
    expect(listCall?.headers.Authorization).toBe(`Bearer ${TOKEN}`)
  })

  it('shows one generic message for any credential failure and clears the password', async () => {
    mockApi({
      ...BASE_ROUTES,
      'POST /api/v1/auth/login': json(
        { error: { code: 'unauthenticated', message: 'Account locked for user admin' } },
        401,
      ),
    })
    const user = setupUser()
    render(<App />)
    await user.type(screen.getByLabelText('Username'), 'admin')
    await user.type(screen.getByLabelText('Password'), 'wrong-password')
    await user.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid username or password.')
    expect(screen.queryByText(/locked/)).not.toBeInTheDocument()
    expect(screen.getByLabelText('Password')).toHaveValue('')
  })

  it('requires both fields before calling the backend', async () => {
    const { calls } = mockApi(BASE_ROUTES)
    const user = setupUser()
    render(<App />)
    await user.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(screen.getByRole('alert')).toHaveTextContent('Enter your username and password.')
    expect(calls.some((c) => c.path === '/api/v1/auth/login')).toBe(false)
  })

  it('reports an unreachable server during sign-in', async () => {
    mockApi({
      ...BASE_ROUTES,
      'POST /api/v1/auth/login': () => {
        throw new TypeError('Failed to fetch')
      },
    })
    const user = setupUser()
    render(<App />)
    await user.type(screen.getByLabelText('Username'), 'a')
    await user.type(screen.getByLabelText('Password'), 'b')
    await user.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/Cannot reach the ASKQ server/)
  })

  it('signs out and hides every authenticated page', async () => {
    const { api, user } = await signIn()
    await user.click(screen.getByRole('button', { name: 'Sign out' }))
    expect(screen.getByLabelText('Username')).toBeInTheDocument()
    expect(screen.queryByRole('navigation', { name: 'Main' })).not.toBeInTheDocument()
    expect(screen.queryByText('t0001')).not.toBeInTheDocument()
    const before = api.calls.length
    // Nothing authenticated is requested after sign-out.
    await new Promise((r) => setTimeout(r, 20))
    expect(api.calls.slice(before).some((c) => c.headers.Authorization)).toBe(false)
  })

  it('ends the session when the backend rejects the token', async () => {
    const { user } = await signIn({
      'POST /api/v1/query': json({ error: { code: 'unauthenticated', message: 'x' } }, 401),
    })
    await ask(user, 'anything')
    expect(await screen.findByText('Your session has ended. Please sign in again.')).toBeInTheDocument()
    expect(screen.getByLabelText('Username')).toBeInTheDocument()
  })
})

// ---------------- asking questions ----------------

describe('asking a question', () => {
  it('sends only the question, shows a loading state, then the answer', async () => {
    let release: (value: Response) => void = () => {}
    const { api, user } = await signIn({
      'POST /api/v1/query': () => new Promise<Response>((resolve) => (release = resolve)),
    })
    await ask(user, 'Average marks by department?')
    expect(await screen.findByText(/Checking your question and running it securely/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Asking…' })).toBeDisabled()
    const call = api.calls.find((c) => c.path === '/api/v1/query')
    expect(call?.body).toEqual({ question: 'Average marks by department?' })
    release(json(queryResponse()))
    expect(await screen.findByRole('article', { name: 'Answer' })).toBeInTheDocument()
  })

  it('renders an ALLOW answer: explanation, chart, table and row count, but never SQL or scores', async () => {
    const { user } = await signIn({ 'POST /api/v1/query': queryResponse() })
    await ask(user, 'q')
    const card = await screen.findByRole('article', { name: 'Answer' })
    expect(within(card).getByText('Answered')).toBeInTheDocument()
    expect(within(card).getByText('Average marks by department.')).toBeInTheDocument()
    expect(within(card).getByRole('img', { name: /Bar chart of avg_marks/ })).toBeInTheDocument()
    const table = within(card).getByRole('table')
    expect(within(table).getByText('CSE')).toBeInTheDocument()
    expect(within(table).getByText('68.25')).toBeInTheDocument()
    expect(within(card).getByText('2 rows')).toBeInTheDocument()
  })

  it('shows nothing internal even if a backend sent SQL, scores, codes or CAIR details', async () => {
    const { user } = await signIn({
      'POST /api/v1/query': leakyQueryResponse({
        decision: 'RESTRICT',
        rows: [['CSE', 71.5]],
        row_count: 1,
      }),
    })
    await ask(user, 'q')
    const card = await screen.findByRole('article', { name: 'Partial answer' })
    // Open the "How ASKQ checked this" panel so its content is rendered too.
    fireEvent.click(within(card).getByText('How ASKQ checked this'))
    const text = document.body.textContent ?? ''
    for (const secret of ['secret_sql_marker', 'WITHHELD_GROUP_MARKER', '0.4321', '0.43', '>= 5', 'INFERENCE_RISK_MARKER', 'DIFFERENCING']) {
      expect(text).not.toContain(secret)
    }
  })

  it('renders a RESTRICT answer with a privacy notice and nothing about what was withheld', async () => {
    const { user } = await signIn({
      'POST /api/v1/query': queryResponse({
        decision: 'RESTRICT',
        message: 'Query executed with additional restrictions.',
        rows: [['CSE', 71.5]],
        row_count: 1,
        security: {
          validation: 'PASSED',
          authorization: 'ALLOWED',
          guard_decision: 'RESTRICT',
          guard_reasons: ['Part of the result was withheld to protect individuals.'],
          scope: 'DEPARTMENT',
          notes: [],
        },
      }),
    })
    await ask(user, 'q')
    const card = await screen.findByRole('article', { name: 'Partial answer' })
    expect(within(card).getByText(/withheld to protect individuals' privacy/)).toBeInTheDocument()
    expect(within(card).getByText('1 row')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain("'ECE'")
  })

  it.each([
    ['BLOCK', 'Not answered', 'This query was blocked because it could reveal protected information.'],
    ['DENIED', 'Not permitted', 'Your role is not permitted to query some of the requested data.'],
    ['REJECTED', 'Query not allowed', 'Only read-only SELECT queries are allowed.'],
    ['FAILED', 'ASKQ could not answer this question', 'The language model took too long to respond.'],
  ])('renders a %s decision with the safe backend message and no data', async (decision, heading, message) => {
    const { user } = await signIn({
      'POST /api/v1/query': queryResponse({
        decision,
        message,
        explanation: 'model text that is not shown for refusals',
        columns: [],
        rows: [],
        row_count: 0,
        chart: null,
      }),
    })
    await ask(user, 'q')
    const card = await screen.findByRole('article', { name: heading })
    expect(within(card).getByText(message)).toBeInTheDocument()
    expect(within(card).queryByRole('table')).not.toBeInTheDocument()
    expect(within(card).queryByText('model text that is not shown for refusals')).not.toBeInTheDocument()
  })

  it('shows an empty-result state', async () => {
    const { user } = await signIn({
      'POST /api/v1/query': queryResponse({ rows: [], row_count: 0 }),
    })
    await ask(user, 'q')
    expect(await screen.findByText(/No matching data/)).toBeInTheDocument()
  })

  it.each([
    [500, { error: { code: 'internal_error', message: 'Traceback: secret stuff' } }, 'Something went wrong on the server. Please try again.'],
    [503, { error: { code: 'service_unavailable', message: 'Service temporarily unavailable.' } }, 'Service temporarily unavailable.'],
    [422, { error: { code: 'validation_error', message: 'Invalid request.' } }, 'Invalid request.'],
  ])('shows a safe message for HTTP %s', async (status, body, expected) => {
    const { user } = await signIn({ 'POST /api/v1/query': json(body, status) })
    await ask(user, 'q')
    expect(await screen.findByText(expected)).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('Traceback')
  })

  it('shows a network error', async () => {
    const { user } = await signIn({
      'POST /api/v1/query': () => {
        throw new TypeError('Failed to fetch')
      },
    })
    await ask(user, 'q')
    expect(await screen.findByText(/Cannot reach the ASKQ server/)).toBeInTheDocument()
  })

  it.each([
    ['not an object', ['x']],
    ['unknown decision', queryResponse({ decision: 'MAYBE' })],
    ['ragged rows', queryResponse({ rows: [['CSE']] })],
    ['missing security', queryResponse({ security: undefined })],
  ])('rejects a malformed response (%s)', async (_, body) => {
    const { user } = await signIn({ 'POST /api/v1/query': body })
    await ask(user, 'q')
    expect(await screen.findByText('The server sent an unexpected response.')).toBeInTheDocument()
  })

  it('renders hostile values as plain text', async () => {
    const payload = '<img src=x onerror="window.__pwned=1">'
    const { user } = await signIn({
      'POST /api/v1/query': queryResponse({
        explanation: payload,
        rows: [[payload, 1]],
        chart: { type: 'bar', x: 'department_code', y: 'avg_marks' },
      }),
    })
    await ask(user, 'q')
    await screen.findByRole('article', { name: 'Answer' })
    expect(document.querySelector('img')).toBeNull()
    expect(screen.getAllByText(payload).length).toBeGreaterThan(0)
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined()
  })

  it('validates the question before sending', async () => {
    const { api, user } = await signIn()
    await user.click(screen.getByRole('button', { name: 'Ask' }))
    expect(screen.getByRole('alert')).toHaveTextContent('Type a question first.')
    expect(api.calls.some((c) => c.path === '/api/v1/query')).toBe(false)
  })
})

// ---------------- conversations and history ----------------

const CONV_A = '22222222-2222-4222-8222-222222222222'
const CONVERSATIONS = {
  items: [
    { id: CONV_A, title: 'Marks by department', started_at: '2026-09-27T10:00:00Z', last_activity_at: '2026-09-27T10:05:00Z', turns: 2 },
    { id: '33333333-3333-4333-8333-333333333333', title: 'Fees', started_at: '2026-09-26T09:00:00Z', last_activity_at: '2026-09-26T09:00:00Z', turns: 1 },
  ],
  page: { limit: 50, offset: 0 },
}
const DETAIL_A = {
  id: CONV_A,
  title: 'Marks by department',
  started_at: '2026-09-27T10:00:00Z',
  turns: [
    { turn_no: 1, question: 'Average marks by department?', summary: 'Average marks per department.', decision: 'ALLOW', asked_at: '2026-09-27T10:00:00Z' },
    { turn_no: 2, question: 'And excluding one student?', summary: null, decision: 'BLOCK', asked_at: '2026-09-27T10:05:00Z' },
  ],
}

describe('conversations', () => {
  it('lists conversations, opens one and continues it', async () => {
    const { api, user } = await signIn({
      'GET /api/v1/conversations': CONVERSATIONS,
      [`GET /api/v1/conversations/${CONV_A}`]: DETAIL_A,
      'POST /api/v1/query': queryResponse({ conversation_id: CONV_A }),
    })
    await user.click(await screen.findByRole('button', { name: /Marks by department/ }))
    expect(await screen.findByText('And excluding one student?')).toBeInTheDocument()
    expect(screen.getByText('Average marks per department.')).toBeInTheDocument()
    expect(screen.getByText('Withheld')).toBeInTheDocument()
    await ask(user, 'And for year 2?')
    await screen.findByRole('article', { name: 'Answer' })
    const call = api.calls.filter((c) => c.path === '/api/v1/query').at(-1)
    expect(call?.body).toEqual({ question: 'And for year 2?', conversation_id: CONV_A })
  })

  it('starts a new conversation without a conversation id', async () => {
    const { api, user } = await signIn({
      'GET /api/v1/conversations': CONVERSATIONS,
      [`GET /api/v1/conversations/${CONV_A}`]: DETAIL_A,
      'POST /api/v1/query': queryResponse(),
    })
    await user.click(await screen.findByRole('button', { name: /Marks by department/ }))
    await screen.findByText('And excluding one student?')
    await user.click(screen.getByRole('button', { name: 'New conversation' }))
    expect(screen.queryByText('And excluding one student?')).not.toBeInTheDocument()
    await ask(user, 'Fresh question')
    await screen.findByRole('article', { name: 'Answer' })
    const call = api.calls.filter((c) => c.path === '/api/v1/query').at(-1)
    expect(call?.body).toEqual({ question: 'Fresh question' })
  })

  it('shows an error when a conversation cannot be loaded', async () => {
    const { user } = await signIn({
      'GET /api/v1/conversations': CONVERSATIONS,
      [`GET /api/v1/conversations/${CONV_A}`]: json({ error: { code: 'not_found', message: 'Conversation not found.' } }, 404),
    })
    await user.click(await screen.findByRole('button', { name: /Marks by department/ }))
    expect(await screen.findByText('Conversation not found.')).toBeInTheDocument()
  })
})

describe('history', () => {
  const HISTORY = {
    items: [
      { query_id: 9, conversation_id: CONV_A, turn_no: 2, question: 'And excluding one student?', summary: null, decision: 'BLOCK', row_count: null, asked_at: '2026-09-27T10:05:00Z' },
      { query_id: 8, conversation_id: CONV_A, turn_no: 1, question: 'Average marks by department?', summary: 'Average marks per department.', decision: 'ALLOW', row_count: 7, asked_at: '2026-09-27T10:00:00Z' },
    ],
    page: { limit: 100, offset: 0 },
  }

  it('renders the history and opens a conversation from it', async () => {
    const { user } = await signIn({
      'GET /api/v1/history': HISTORY,
      'GET /api/v1/conversations': CONVERSATIONS,
      [`GET /api/v1/conversations/${CONV_A}`]: DETAIL_A,
    })
    await user.click(screen.getByRole('button', { name: 'Query history' }))
    const table = await screen.findByRole('region', { name: 'Query history' })
    expect(within(table).getByText('Average marks by department?')).toBeInTheDocument()
    expect(within(table).getByText('Withheld')).toBeInTheDocument()
    expect(within(table).getByText('Answered')).toBeInTheDocument()
    expect(within(table).getByText('7')).toBeInTheDocument()
    await user.click(within(table).getAllByRole('button', { name: 'Open conversation' })[0])
    expect(await screen.findByText('Average marks per department.')).toBeInTheDocument()
  })

  it('shows an empty history', async () => {
    const { user } = await signIn()
    await user.click(screen.getByRole('button', { name: 'Query history' }))
    expect(await screen.findByText('You have not asked any questions yet.')).toBeInTheDocument()
  })

  it('shows a forbidden error with retry', async () => {
    const { user } = await signIn({
      'GET /api/v1/history': json({ error: { code: 'forbidden', message: 'You do not have permission to perform this action.' } }, 403),
    })
    await user.click(screen.getByRole('button', { name: 'Query history' }))
    expect(await screen.findByText('You do not have permission to perform this action.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
  })
})

describe('navigation', () => {
  it('only offers sections the backend permits', async () => {
    await signIn({
      'POST /api/v1/auth/login': loginOk({ ...HOD, permissions: ['ASK_QUESTIONS'] }),
    })
    expect(screen.getByRole('button', { name: 'Ask ASKQ' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Query history' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Profile' })).toBeInTheDocument()
  })

  it('shows the profile from the backend identity', async () => {
    const { user } = await signIn()
    await user.click(screen.getByRole('button', { name: 'Profile' }))
    expect(await screen.findByRole('heading', { name: 'Profile' })).toBeInTheDocument()
    expect(screen.getByText(/Individual records within your department/)).toBeInTheDocument()
    await waitFor(() => expect(screen.getByText('ask questions')).toBeInTheDocument())
  })
})
