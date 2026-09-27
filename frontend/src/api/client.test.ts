import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { askQuestion, listHistory } from './askq'
import { ApiError, request, setAccessToken, setUnauthorizedHandler } from './client'
import { parseQueryResult } from './validate'
import { LEAKY_EXTRAS, json, leakyQueryResponse, mockApi, queryResponse } from '../test/mockApi'

beforeEach(() => setAccessToken('t0k'))
afterEach(() => {
  setAccessToken(null)
  setUnauthorizedHandler(null)
  vi.unstubAllGlobals()
})

describe('request', () => {
  it('refuses authenticated calls without a token and never hits the network', async () => {
    setAccessToken(null)
    const { calls } = mockApi({})
    await expect(listHistory()).rejects.toMatchObject({ kind: 'unauthorized' })
    expect(calls).toHaveLength(0)
  })

  it('sends the bearer token without cookies', async () => {
    const { fetchMock } = mockApi({ 'GET /api/v1/history': { items: [], page: { limit: 1, offset: 0 } } })
    await listHistory()
    const init = fetchMock.mock.calls[0][1] as RequestInit
    expect(init.credentials).toBe('omit')
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer t0k')
  })

  it('never shows 5xx bodies', async () => {
    mockApi({ 'GET /x': json({ error: { message: 'pymysql.err.OperationalError: password=...' } }, 500) })
    const err = await request('/x', (v) => v).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).message).not.toContain('pymysql')
  })

  it('ignores over-long error messages', async () => {
    mockApi({ 'GET /x': json({ error: { message: 'x'.repeat(301) } }, 404) })
    await expect(request('/x', (v) => v)).rejects.toMatchObject({ message: 'That item could not be found.' })
  })

  it('treats a non-JSON body as malformed', async () => {
    mockApi({ 'GET /x': new Response('<html>proxy error</html>', { status: 200 }) })
    await expect(request('/x', (v) => v)).rejects.toMatchObject({ kind: 'malformed' })
  })

  it('calls the unauthorized handler on 401', async () => {
    const handler = vi.fn()
    setUnauthorizedHandler(handler)
    mockApi({ 'GET /x': json({}, 401) })
    await expect(request('/x', (v) => v)).rejects.toMatchObject({ kind: 'unauthorized' })
    expect(handler).toHaveBeenCalledOnce()
  })
})

describe('askQuestion', () => {
  it('sends only the question and conversation id', async () => {
    const { calls } = mockApi({ 'POST /api/v1/query': queryResponse() })
    await askQuestion('How many?', 'abc')
    expect(calls[0].body).toEqual({ question: 'How many?', conversation_id: 'abc' })
  })
})

describe('parseQueryResult', () => {
  it('accepts the Phase 6 response, which has no SQL, score or code', () => {
    const body = queryResponse()
    expect(body).not.toHaveProperty('sql')
    expect(body).not.toHaveProperty('reason_code')
    expect(body.security).not.toHaveProperty('risk_score')
    expect(parseQueryResult(body).decision).toBe('ALLOW')
  })

  it('drops SQL, scores, codes and CAIR details if a backend ever sent them', () => {
    const result = parseQueryResult(leakyQueryResponse())
    const text = JSON.stringify(result)
    for (const value of ['secret_sql_marker', 'WITHHELD_GROUP_MARKER', '0.4321', 'INFERENCE_RISK_MARKER', 'DIFFERENCING']) {
      expect(text).not.toContain(value)
    }
    for (const key of Object.keys(LEAKY_EXTRAS)) expect(result).not.toHaveProperty(key)
    expect(result.security).not.toHaveProperty('riskScore')
    expect(result.security).not.toHaveProperty('risk_score')
    // The UI's types have no such fields, so no component can render them.
    // @ts-expect-error QueryResult has no sql
    expect(result.sql).toBeUndefined()
    // @ts-expect-error SecuritySummary has no risk score
    expect(result.security.riskScore).toBeUndefined()
  })

  it('turns non-primitive cells into text and ignores unknown chart types', () => {
    const result = parseQueryResult(
      queryResponse({ rows: [[{ a: 1 }, 2]], row_count: 1, chart: { type: 'sankey' } }),
    )
    expect(result.rows[0][0]).toBe('[object Object]')
    expect(result.chart).toBeNull()
  })
})
