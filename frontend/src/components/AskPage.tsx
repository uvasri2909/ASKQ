// Ask ASKQ: the conversation list, the current conversation and the question box.
// The request carries only the question and (optionally) the conversation id.

import { useCallback, useEffect, useRef, useState } from 'react'
import type { FormEvent, KeyboardEvent } from 'react'
import { askQuestion, getConversation, listConversations } from '../api/askq'
import { ApiError, errorMessage } from '../api/client'
import type { ConversationItem, QueryResult, TurnItem } from '../api/types'
import { formatDateTime } from '../format'
import { ResultCard } from './ResultCard'
import { DecisionBadge, Empty, ErrorNote, Loading } from './Status'

const MAX_QUESTION = 1000
const EXAMPLES = [
  'What is the average attendance percentage by department?',
  'How many students are there in each year level?',
  'What are my grades this term?',
]

type Entry =
  | { kind: 'past'; key: string; turn: TurnItem }
  | { kind: 'pending'; key: string; question: string }
  | { kind: 'result'; key: string; question: string; result: QueryResult }
  | { kind: 'error'; key: string; question: string; message: string }

let nextKey = 0
const key = () => `e${(nextKey += 1)}`

function Question({ text }: { text: string }) {
  return (
    <div className="bubble bubble-user">
      <span className="speaker">You</span>
      <p>{text}</p>
    </div>
  )
}

export function AskPage({ initialConversation }: { initialConversation: string | null }) {
  const [conversations, setConversations] = useState<ConversationItem[] | null>(null)
  const [listError, setListError] = useState<string | null>(null)
  const [active, setActive] = useState<string | null>(initialConversation)
  const [entries, setEntries] = useState<Entry[]>([])
  const [threadState, setThreadState] = useState<'idle' | 'loading' | 'error'>(
    initialConversation ? 'loading' : 'idle',
  )
  const [threadError, setThreadError] = useState<string | null>(null)
  const [question, setQuestion] = useState('')
  const [inputError, setInputError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [listVersion, setListVersion] = useState(0)
  const endRef = useRef<HTMLDivElement | null>(null)

  // Conversation list: (re)loaded whenever listVersion changes.
  useEffect(() => {
    const controller = new AbortController()
    listConversations(controller.signal).then(
      (items) => {
        setListError(null)
        setConversations(items)
      },
      (error: unknown) => {
        if (controller.signal.aborted) return
        if (error instanceof ApiError && error.kind === 'unauthorized') return // session handler
        setListError(errorMessage(error))
      },
    )
    return () => controller.abort()
  }, [listVersion])

  const refreshConversations = useCallback(() => setListVersion((n) => n + 1), [])

  // Fetches a conversation's turns; state changes only in the callbacks.
  const loadThread = useCallback((id: string, signal?: AbortSignal) => {
    getConversation(id, signal).then(
      (detail) => {
        setEntries(detail.turns.map((turn) => ({ kind: 'past', key: key(), turn })))
        setThreadState('idle')
      },
      (error: unknown) => {
        if (signal?.aborted) return
        setThreadState('error')
        setThreadError(errorMessage(error))
      },
    )
  }, [])

  useEffect(() => {
    if (!initialConversation) return
    const controller = new AbortController()
    loadThread(initialConversation, controller.signal)
    return () => controller.abort()
  }, [initialConversation, loadThread])

  function openConversation(id: string) {
    setActive(id)
    setEntries([])
    setThreadState('loading')
    setThreadError(null)
    loadThread(id)
  }

  useEffect(() => {
    endRef.current?.scrollIntoView?.({ block: 'end' })
  }, [entries])

  function newConversation() {
    setActive(null)
    setEntries([])
    setThreadState('idle')
    setThreadError(null)
    setInputError(null)
  }

  async function submit(event?: FormEvent) {
    event?.preventDefault()
    const text = question.trim()
    if (!text) {
      setInputError('Type a question first.')
      return
    }
    if (text.length > MAX_QUESTION) {
      setInputError(`Questions can be at most ${MAX_QUESTION} characters.`)
      return
    }
    setInputError(null)
    setBusy(true)
    const pendingKey = key()
    setEntries((current) => [...current, { kind: 'pending', key: pendingKey, question: text }])
    setQuestion('')
    try {
      const result = await askQuestion(text, active)
      setActive(result.conversationId)
      setEntries((current) =>
        current.map((e) =>
          e.key === pendingKey ? { kind: 'result', key: pendingKey, question: text, result } : e,
        ),
      )
      refreshConversations()
    } catch (error) {
      setEntries((current) =>
        current.map((e) =>
          e.key === pendingKey
            ? { kind: 'error', key: pendingKey, question: text, message: errorMessage(error) }
            : e,
        ),
      )
    } finally {
      setBusy(false)
    }
  }

  function onKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
      event.preventDefault()
      void submit()
    }
  }

  return (
    <div className="ask">
      <aside className="conversations" aria-label="Conversations">
        <button type="button" className="button button-primary button-block" onClick={newConversation}>
          New conversation
        </button>
        <h2 className="panel-title">Conversations</h2>
        {conversations === null && !listError && <Loading label="Loading conversations…" />}
        {listError && <ErrorNote message={listError} onRetry={refreshConversations} />}
        {conversations !== null && conversations.length === 0 && <Empty>No conversations yet.</Empty>}
        {conversations !== null && conversations.length > 0 && (
          <ul className="conversation-list">
            {conversations.map((c) => (
              <li key={c.id}>
                <button
                  type="button"
                  className={`conversation-item${c.id === active ? ' active' : ''}`}
                  aria-current={c.id === active ? 'true' : undefined}
                  onClick={() => openConversation(c.id)}
                >
                  <span className="conversation-title">{c.title ?? 'Untitled conversation'}</span>
                  <span className="conversation-meta">
                    {c.turns} {c.turns === 1 ? 'question' : 'questions'} · {formatDateTime(c.lastActivityAt)}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </aside>

      <section className="thread" aria-label="Current conversation">
        <div className="thread-body" aria-live="polite">
          {threadState === 'loading' && <Loading label="Loading conversation…" />}
          {threadState === 'error' && threadError && <ErrorNote message={threadError} />}
          {threadState === 'idle' && entries.length === 0 && (
            <Empty>
              <h2>Ask a question about the university data</h2>
              <p>
                ASKQ turns your question into SQL, checks it for safety, applies your access
                rights and inference-risk protection, and only then runs it.
              </p>
              <ul className="examples">
                {EXAMPLES.map((example) => (
                  <li key={example}>
                    <button type="button" className="link-button" onClick={() => setQuestion(example)}>
                      {example}
                    </button>
                  </li>
                ))}
              </ul>
            </Empty>
          )}
          {entries.some((e) => e.kind === 'past') && (
            <p className="note">
              Earlier answers are not stored (only their outcome); ask again to see current data.
            </p>
          )}
          {entries.map((entry) => {
            if (entry.kind === 'past') {
              return (
                <div key={entry.key} className="exchange">
                  <Question text={entry.turn.question} />
                  <div className="bubble bubble-askq">
                    <span className="speaker">
                      ASKQ {entry.turn.decision && <DecisionBadge decision={entry.turn.decision} />}
                    </span>
                    <p>{entry.turn.summary ?? 'No summary was recorded.'}</p>
                  </div>
                </div>
              )
            }
            return (
              <div key={entry.key} className="exchange">
                <Question text={entry.question} />
                <div className="bubble bubble-askq">
                  <span className="speaker">ASKQ</span>
                  {entry.kind === 'pending' && (
                    <Loading label="Checking your question and running it securely…" />
                  )}
                  {entry.kind === 'error' && <ErrorNote message={entry.message} />}
                  {entry.kind === 'result' && <ResultCard result={entry.result} />}
                </div>
              </div>
            )
          })}
          <div ref={endRef} />
        </div>

        <form className="composer" onSubmit={submit}>
          <label htmlFor="question" className="visually-hidden">
            Your question
          </label>
          <textarea
            id="question"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder="e.g. What is the average attendance for my department?"
            rows={2}
            maxLength={MAX_QUESTION}
            disabled={busy}
            aria-describedby="question-hint"
          />
          <div className="composer-row">
            <span id="question-hint" className="hint">
              {inputError ? (
                <span className="field-error" role="alert">
                  {inputError}
                </span>
              ) : (
                `${active ? 'Continuing this conversation' : 'New conversation'} · Ctrl+Enter to send`
              )}
            </span>
            <button type="submit" className="button button-primary" disabled={busy}>
              {busy ? 'Asking…' : 'Ask'}
            </button>
          </div>
        </form>
      </section>
    </div>
  )
}
