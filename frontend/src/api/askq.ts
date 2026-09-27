// Typed ASKQ endpoints. Request bodies contain only the fields the backend
// accepts; role, scope, permissions, SQL and decisions are never sent.

import { request } from './client'
import type {
  ConversationDetail,
  ConversationItem,
  HistoryEntry,
  LoginResult,
  QueryResult,
  User,
} from './types'
import {
  parseConversationDetail,
  parseConversationList,
  parseHistory,
  parseLogin,
  parseQueryResult,
  parseUser,
} from './validate'

export function login(username: string, password: string): Promise<LoginResult> {
  return request('/api/v1/auth/login', parseLogin, {
    method: 'POST',
    auth: false,
    body: { username, password },
  })
}

export function fetchMe(signal?: AbortSignal): Promise<User> {
  return request('/api/v1/auth/me', parseUser, { signal })
}

export function askQuestion(question: string, conversationId: string | null): Promise<QueryResult> {
  const body: { question: string; conversation_id?: string } = { question }
  if (conversationId) body.conversation_id = conversationId
  return request('/api/v1/query', parseQueryResult, { method: 'POST', body })
}

export function listConversations(signal?: AbortSignal): Promise<ConversationItem[]> {
  return request('/api/v1/conversations?limit=50', parseConversationList, { signal })
}

export function getConversation(id: string, signal?: AbortSignal): Promise<ConversationDetail> {
  return request(`/api/v1/conversations/${encodeURIComponent(id)}`, parseConversationDetail, {
    signal,
  })
}

export function listHistory(signal?: AbortSignal): Promise<HistoryEntry[]> {
  return request('/api/v1/history?limit=100', parseHistory, { signal })
}
