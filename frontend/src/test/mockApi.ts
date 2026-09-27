// A tiny fetch mock: routes by "METHOD /path" and records every call.
import { vi } from 'vitest'

export interface Call {
  method: string
  path: string
  body: unknown
  headers: Record<string, string>
}

export type Handler = (call: Call) => Response | Promise<Response>

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

export function mockApi(routes: Record<string, Handler | Response | unknown>) {
  const calls: Call[] = []
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost')
    const method = (init?.method ?? 'GET').toUpperCase()
    const call: Call = {
      method,
      path: url.pathname + url.search,
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
      headers: (init?.headers ?? {}) as Record<string, string>,
    }
    calls.push(call)
    const route = routes[`${method} ${url.pathname}`]
    if (route === undefined) return json({ error: { code: 'not_found', message: 'Not Found' } }, 404)
    if (typeof route === 'function') return (route as Handler)(call)
    if (route instanceof Response) return route.clone()
    return json(route)
  })
  vi.stubGlobal('fetch', fetchMock)
  return { calls, fetchMock }
}

export const HEALTH = { status: 'ok', service: 'askq-backend', version: '0.1.0', environment: 'test' }

export const HOD = {
  id: 2,
  username: 't0001',
  role: 'HOD',
  permissions: ['ASK_QUESTIONS', 'VIEW_OWN_HISTORY'],
}

export const TOKEN = 'header.payload.signature-not-for-display'

export function loginOk(user = HOD) {
  return { access_token: TOKEN, token_type: 'bearer', expires_in: 3600, user }
}

// Exactly the fields POST /api/v1/query returns (backend QueryResponse). Since
// Phase 6 the API sends no SQL, risk score or reason code.
export function queryResponse(overrides: Record<string, unknown> = {}) {
  return {
    query_id: 1,
    conversation_id: '11111111-1111-4111-8111-111111111111',
    decision: 'ALLOW',
    message: 'Query executed.',
    question: 'q',
    resolved_question: 'q',
    explanation: 'Average marks by department.',
    columns: ['department_code', 'avg_marks'],
    rows: [
      ['CSE', 71.5],
      ['ECE', 68.25],
    ],
    row_count: 2,
    row_limit: 500,
    execution_ms: 12,
    chart: { type: 'bar', x: 'department_code', y: 'avg_marks' },
    security: {
      validation: 'PASSED',
      authorization: 'ALLOWED',
      guard_decision: 'ALLOW',
      guard_reasons: ['No inference risk was found for this statistic.'],
      scope: 'DEPARTMENT',
      notes: ['Results are limited to 500 rows.'],
    },
    ...overrides,
  }
}

// What an older (pre-Phase 6) or tampered backend might add. The validator must
// drop all of it before anything reaches the UI.
export const LEAKY_EXTRAS = {
  sql: "SELECT secret_sql_marker FROM x WHERE NOT (d.department_code = 'WITHHELD_GROUP_MARKER') HAVING COUNT(*) >= 5",
  reason_code: 'INFERENCE_RISK_MARKER',
  cair: { detectors: ['DIFFERENCING'], excluded: [['WITHHELD_GROUP_MARKER']] },
}

export function leakyQueryResponse(overrides: Record<string, unknown> = {}) {
  const base = queryResponse(overrides)
  return {
    ...base,
    ...LEAKY_EXTRAS,
    security: { ...(base.security as Record<string, unknown>), risk_score: 0.4321 },
  }
}

export const EMPTY_LIST = { items: [], page: { limit: 50, offset: 0 } }
