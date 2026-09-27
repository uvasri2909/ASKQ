import type { ReactNode } from 'react'
import type { Decision } from '../api/types'
import { DECISION_LABEL } from '../format'

export function DecisionBadge({ decision }: { decision: Decision }) {
  return (
    <span className={`badge badge-${decision.toLowerCase()}`} data-decision={decision}>
      {DECISION_LABEL[decision]}
    </span>
  )
}

export function Loading({ label }: { label: string }) {
  return (
    <p className="state state-loading" role="status" aria-live="polite">
      <span className="spinner" aria-hidden="true" />
      {label}
    </p>
  )
}

export function ErrorNote({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="state state-error" role="alert">
      <span>{message}</span>
      {onRetry && (
        <button type="button" className="button button-small" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  )
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="state state-empty">{children}</div>
}
