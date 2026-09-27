// The single place that talks to the backend.
//
// * Requests are same-origin (/api, /health); in development the Vite dev
//   server proxies them to FastAPI. VITE_API_BASE_URL can point elsewhere.
// * The access token lives only in this module's memory: never in
//   localStorage, sessionStorage, cookies, the URL or the DOM. A page reload
//   therefore means logging in again (the safest option with a bearer token).
// * Errors are normalised into ApiError with a safe, generic message; the
//   backend's error body is used only for its already-safe `message` field.

import { MalformedResponseError, parseHealth } from './validate'
import type { HealthResponse } from './types'

export type ErrorKind =
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'validation'
  | 'unavailable'
  | 'server'
  | 'network'
  | 'malformed'

export class ApiError extends Error {
  readonly kind: ErrorKind
  readonly status: number | null

  constructor(kind: ErrorKind, message: string, status: number | null = null) {
    super(message)
    this.name = 'ApiError'
    this.kind = kind
    this.status = status
  }
}

const BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/+$/, '')

let accessToken: string | null = null
let onUnauthorized: (() => void) | null = null

export function setAccessToken(token: string | null): void {
  accessToken = token
}

export function hasAccessToken(): boolean {
  return accessToken !== null
}

/** Called when an authenticated request is rejected (expired or revoked session). */
export function setUnauthorizedHandler(handler: (() => void) | null): void {
  onUnauthorized = handler
}

const GENERIC: Record<ErrorKind, string> = {
  unauthorized: 'Your session has ended. Please sign in again.',
  forbidden: 'You do not have permission to do that.',
  not_found: 'That item could not be found.',
  validation: 'The request was not valid. Please check your input.',
  unavailable: 'ASKQ is temporarily unavailable. Please try again shortly.',
  server: 'Something went wrong on the server. Please try again.',
  network: 'Cannot reach the ASKQ server. Check your connection and try again.',
  malformed: 'The server sent an unexpected response.',
}

function kindFor(status: number): ErrorKind {
  if (status === 401) return 'unauthorized'
  if (status === 403) return 'forbidden'
  if (status === 404) return 'not_found'
  if (status === 422 || status === 400) return 'validation'
  if (status === 503) return 'unavailable'
  return 'server'
}

async function safeMessage(response: Response, kind: ErrorKind): Promise<string> {
  // Only the backend's own error message is shown (it is written to be safe),
  // and only for request-level problems; 5xx bodies are never displayed.
  if (kind === 'server') return GENERIC.server
  try {
    const body = (await response.json()) as { error?: { message?: unknown } }
    const message = body?.error?.message
    if (typeof message === 'string' && message.length > 0 && message.length <= 300) {
      return message
    }
  } catch {
    // fall through to the generic message
  }
  return GENERIC[kind]
}

export interface RequestOptions {
  method?: 'GET' | 'POST'
  body?: unknown
  auth?: boolean
  signal?: AbortSignal
}

export async function request<T>(
  path: string,
  parse: (value: unknown) => T,
  { method = 'GET', body, auth = true, signal }: RequestOptions = {},
): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (auth) {
    if (accessToken === null) throw new ApiError('unauthorized', GENERIC.unauthorized, 401)
    headers.Authorization = `Bearer ${accessToken}`
  }

  let response: Response
  try {
    response = await fetch(`${BASE_URL}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal,
      credentials: 'omit',
    })
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error
    throw new ApiError('network', GENERIC.network)
  }

  if (!response.ok) {
    const kind = kindFor(response.status)
    const message = await safeMessage(response, kind)
    if (kind === 'unauthorized' && auth) onUnauthorized?.()
    throw new ApiError(kind, message, response.status)
  }

  let json: unknown
  try {
    json = await response.json()
  } catch {
    throw new ApiError('malformed', GENERIC.malformed, response.status)
  }
  try {
    return parse(json)
  } catch (error) {
    if (error instanceof MalformedResponseError) {
      throw new ApiError('malformed', GENERIC.malformed, response.status)
    }
    throw error
  }
}

export function getHealth(signal?: AbortSignal): Promise<HealthResponse> {
  return request('/health', parseHealth, { auth: false, signal })
}

export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message
  return GENERIC.server
}
