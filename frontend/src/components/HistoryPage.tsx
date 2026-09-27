import { useCallback, useEffect, useState } from 'react'
import { listHistory } from '../api/askq'
import { ApiError, errorMessage } from '../api/client'
import type { HistoryEntry } from '../api/types'
import { formatDateTime } from '../format'
import { DecisionBadge, Empty, ErrorNote, Loading } from './Status'

export function HistoryPage({ onOpen }: { onOpen: (conversationId: string) => void }) {
  const [items, setItems] = useState<HistoryEntry[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    listHistory(controller.signal).then(setItems, (err: unknown) => {
      if (controller.signal.aborted) return
      if (err instanceof ApiError && err.kind === 'unauthorized') return // session handler
      setError(errorMessage(err))
    })
    return () => controller.abort()
  }, [attempt])

  const retry = useCallback(() => {
    setError(null)
    setItems(null)
    setAttempt((n) => n + 1)
  }, [])

  return (
    <section className="page" aria-labelledby="history-title">
      <header className="page-head">
        <h1 id="history-title">Query history</h1>
        <p className="muted">Your own questions and their outcomes, newest first.</p>
      </header>
      {items === null && !error && <Loading label="Loading history…" />}
      {error && <ErrorNote message={error} onRetry={retry} />}
      {items !== null && items.length === 0 && <Empty>You have not asked any questions yet.</Empty>}
      {items !== null && items.length > 0 && (
        <div className="table-wrap" tabIndex={0} role="region" aria-label="Query history">
          <table className="result-table history-table">
            <thead>
              <tr>
                <th scope="col">When</th>
                <th scope="col">Question</th>
                <th scope="col">Outcome</th>
                <th scope="col">Summary</th>
                <th scope="col">Rows</th>
                <th scope="col">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.queryId}>
                  <td className="nowrap">{formatDateTime(item.askedAt)}</td>
                  <td>{item.question}</td>
                  <td>
                    <DecisionBadge decision={item.decision} />
                  </td>
                  <td>{item.summary ?? '—'}</td>
                  <td className="num">{item.rowCount ?? '—'}</td>
                  <td>
                    {item.conversationId && (
                      <button
                        type="button"
                        className="button button-small"
                        onClick={() => onOpen(item.conversationId as string)}
                      >
                        Open conversation
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
