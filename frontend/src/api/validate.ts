// Runtime checks for backend responses. Anything that does not match the
// expected shape is rejected as malformed; values are copied field by field,
// so unexpected extra fields never reach the UI. (The API no longer sends SQL,
// risk scores or reason codes; if an older or tampered backend did, they would
// be dropped here.)

import type {
  Cell,
  ChartHint,
  ChartType,
  ConversationDetail,
  ConversationItem,
  Decision,
  HealthResponse,
  HistoryEntry,
  LoginResult,
  QueryResult,
  Role,
  SecuritySummary,
  TurnItem,
  User,
} from './types'

export class MalformedResponseError extends Error {
  constructor(what: string) {
    super(`Unexpected response from the server (${what}).`)
    this.name = 'MalformedResponseError'
  }
}

type Json = Record<string, unknown>

const ROLES: readonly Role[] = ['ADMIN', 'HOD', 'TEACHER', 'STUDENT']
const DECISIONS: readonly Decision[] = ['ALLOW', 'RESTRICT', 'BLOCK', 'DENIED', 'REJECTED', 'FAILED']
const CHARTS: readonly ChartType[] = ['table', 'bar', 'line', 'pie', 'number']

function obj(value: unknown, what: string): Json {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new MalformedResponseError(what)
  }
  return value as Json
}

function str(value: unknown, what: string): string {
  if (typeof value !== 'string') throw new MalformedResponseError(what)
  return value
}

function optStr(value: unknown, what: string): string | null {
  return value === null || value === undefined ? null : str(value, what)
}

function num(value: unknown, what: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) throw new MalformedResponseError(what)
  return value
}

function optNum(value: unknown, what: string): number | null {
  return value === null || value === undefined ? null : num(value, what)
}

function list(value: unknown, what: string): unknown[] {
  if (!Array.isArray(value)) throw new MalformedResponseError(what)
  return value
}

function oneOf<T extends string>(value: unknown, options: readonly T[], what: string): T {
  if (typeof value !== 'string' || !(options as readonly string[]).includes(value)) {
    throw new MalformedResponseError(what)
  }
  return value as T
}

function cell(value: unknown): Cell {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value
  if (typeof value === 'number' && Number.isFinite(value)) return value
  // Anything else (objects, arrays, NaN) is shown as plain text, never as markup.
  return value === undefined ? null : String(value)
}

export function parseHealth(value: unknown): HealthResponse {
  const o = obj(value, 'health')
  return {
    status: str(o.status, 'health.status'),
    service: str(o.service, 'health.service'),
    version: str(o.version, 'health.version'),
    environment: str(o.environment, 'health.environment'),
  }
}

export function parseUser(value: unknown): User {
  const o = obj(value, 'user')
  return {
    id: num(o.id, 'user.id'),
    username: str(o.username, 'user.username'),
    role: oneOf(o.role, ROLES, 'user.role'),
    permissions: list(o.permissions, 'user.permissions').map((p) => str(p, 'permission')),
  }
}

export function parseLogin(value: unknown): LoginResult {
  const o = obj(value, 'login')
  return {
    accessToken: str(o.access_token, 'login.access_token'),
    expiresIn: num(o.expires_in, 'login.expires_in'),
    user: parseUser(o.user),
  }
}

function parseChart(value: unknown): ChartHint | null {
  if (value === null || value === undefined) return null
  const o = obj(value, 'chart')
  if (typeof o.type !== 'string' || !(CHARTS as readonly string[]).includes(o.type)) {
    return null // an unknown chart hint is ignored, not fatal
  }
  return {
    type: o.type as ChartType,
    x: typeof o.x === 'string' ? o.x : '',
    y: typeof o.y === 'string' ? o.y : '',
  }
}

function parseSecurity(value: unknown): SecuritySummary {
  const o = obj(value, 'security')
  return {
    validation: optStr(o.validation, 'security.validation'),
    authorization: optStr(o.authorization, 'security.authorization'),
    guardDecision: optStr(o.guard_decision, 'security.guard_decision'),
    guardReasons: list(o.guard_reasons ?? [], 'security.guard_reasons').map((r) =>
      str(r, 'reason'),
    ),
    scope: str(o.scope, 'security.scope'),
    notes: list(o.notes ?? [], 'security.notes').map((n) => str(n, 'note')),
  }
}

export function parseQueryResult(value: unknown): QueryResult {
  const o = obj(value, 'query')
  const columns = list(o.columns, 'query.columns').map((c) => str(c, 'column'))
  const rows = list(o.rows, 'query.rows').map((row) => {
    const cells = list(row, 'query.row')
    if (cells.length !== columns.length) throw new MalformedResponseError('row width')
    return cells.map(cell)
  })
  return {
    queryId: num(o.query_id, 'query.query_id'),
    conversationId: str(o.conversation_id, 'query.conversation_id'),
    decision: oneOf(o.decision, DECISIONS, 'query.decision'),
    message: str(o.message, 'query.message'),
    question: str(o.question, 'query.question'),
    explanation: optStr(o.explanation, 'query.explanation'),
    columns,
    rows,
    rowCount: num(o.row_count, 'query.row_count'),
    rowLimit: optNum(o.row_limit, 'query.row_limit'),
    chart: parseChart(o.chart),
    security: parseSecurity(o.security),
  }
}

function parseConversationItem(value: unknown): ConversationItem {
  const o = obj(value, 'conversation')
  return {
    id: str(o.id, 'conversation.id'),
    title: optStr(o.title, 'conversation.title'),
    startedAt: str(o.started_at, 'conversation.started_at'),
    lastActivityAt: str(o.last_activity_at, 'conversation.last_activity_at'),
    turns: num(o.turns, 'conversation.turns'),
  }
}

export function parseConversationList(value: unknown): ConversationItem[] {
  return list(obj(value, 'conversations').items, 'conversations.items').map(parseConversationItem)
}

function parseTurn(value: unknown): TurnItem {
  const o = obj(value, 'turn')
  return {
    turnNo: num(o.turn_no, 'turn.turn_no'),
    question: str(o.question, 'turn.question'),
    summary: optStr(o.summary, 'turn.summary'),
    decision: o.decision === null ? null : oneOf(o.decision, DECISIONS, 'turn.decision'),
    askedAt: str(o.asked_at, 'turn.asked_at'),
  }
}

export function parseConversationDetail(value: unknown): ConversationDetail {
  const o = obj(value, 'conversation')
  return {
    id: str(o.id, 'conversation.id'),
    title: optStr(o.title, 'conversation.title'),
    startedAt: str(o.started_at, 'conversation.started_at'),
    turns: list(o.turns, 'conversation.turns').map(parseTurn),
  }
}

export function parseHistory(value: unknown): HistoryEntry[] {
  return list(obj(value, 'history').items, 'history.items').map((item) => {
    const o = obj(item, 'history item')
    return {
      queryId: num(o.query_id, 'history.query_id'),
      conversationId: optStr(o.conversation_id, 'history.conversation_id'),
      turnNo: optNum(o.turn_no, 'history.turn_no'),
      question: str(o.question, 'history.question'),
      summary: optStr(o.summary, 'history.summary'),
      decision: oneOf(o.decision, DECISIONS, 'history.decision'),
      rowCount: optNum(o.row_count, 'history.row_count'),
      askedAt: str(o.asked_at, 'history.asked_at'),
    }
  })
}
