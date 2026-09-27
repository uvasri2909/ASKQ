// Shapes of the ASKQ backend API (backend/app/api/*). Every response is
// checked at runtime by validate.ts before the UI uses it.

export type Role = 'ADMIN' | 'HOD' | 'TEACHER' | 'STUDENT'

export type Decision = 'ALLOW' | 'RESTRICT' | 'BLOCK' | 'DENIED' | 'REJECTED' | 'FAILED'

export type ChartType = 'table' | 'bar' | 'line' | 'pie' | 'number'

export interface HealthResponse {
  status: string
  service: string
  version: string
  environment: string
}

export interface User {
  id: number
  username: string
  role: Role
  permissions: string[]
}

export interface LoginResult {
  accessToken: string
  expiresIn: number
  user: User
}

export type Cell = string | number | boolean | null

export interface ChartHint {
  type: ChartType
  x: string
  y: string
}

export interface SecuritySummary {
  validation: string | null
  authorization: string | null
  guardDecision: string | null
  guardReasons: string[]
  scope: string
  notes: string[]
}

// The fields the UI uses. The API sends no SQL, risk score or reason code
// (removed from the backend response in Phase 6), and this type has no place
// for them either.
export interface QueryResult {
  queryId: number
  conversationId: string
  decision: Decision
  message: string
  question: string
  explanation: string | null
  columns: string[]
  rows: Cell[][]
  rowCount: number
  rowLimit: number | null
  chart: ChartHint | null
  security: SecuritySummary
}

export interface ConversationItem {
  id: string
  title: string | null
  startedAt: string
  lastActivityAt: string
  turns: number
}

export interface TurnItem {
  turnNo: number
  question: string
  summary: string | null
  decision: Decision | null
  askedAt: string
}

export interface ConversationDetail {
  id: string
  title: string | null
  startedAt: string
  turns: TurnItem[]
}

export interface HistoryEntry {
  queryId: number
  conversationId: string | null
  turnNo: number | null
  question: string
  summary: string | null
  decision: Decision
  rowCount: number | null
  askedAt: string
}
