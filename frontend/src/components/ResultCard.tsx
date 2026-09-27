// How one answer is shown. The decision comes from the backend and is shown
// as-is; the text shown is the backend's own safe message (plus fixed labels).
// SQL, risk scores and detector details are not part of the UI model at all.

import type { QueryResult } from '../api/types'
import { Chart } from './Chart'
import { chartSpec } from './chartSpec'
import { ResultTable } from './ResultTable'
import { DecisionBadge, Empty } from './Status'

const HEADINGS = {
  ALLOW: 'Answer',
  RESTRICT: 'Partial answer',
  BLOCK: 'Not answered',
  DENIED: 'Not permitted',
  REJECTED: 'Query not allowed',
  FAILED: 'ASKQ could not answer this question',
} as const

const STEP_LABEL: Record<string, string> = {
  PASSED: 'passed',
  REJECTED: 'rejected',
  ALLOWED: 'allowed',
  REWRITTEN: 'allowed, limited to your scope',
  DENIED: 'denied',
  ALLOW: 'no risk found',
  RESTRICT: 'part withheld',
  BLOCK: 'withheld',
}

function SecurityPanel({ result }: { result: QueryResult }) {
  const { security } = result
  const steps: [string, string | null][] = [
    ['SQL safety check', security.validation],
    ['Authorization', security.authorization],
    ['Inference-risk check (CAIR)', security.guardDecision],
  ]
  return (
    <details className="security">
      <summary>How ASKQ checked this</summary>
      <ol className="steps">
        {steps.map(([label, value]) => (
          <li key={label} className={value ? 'step-done' : 'step-skipped'}>
            <span>{label}</span>
            <span className="step-value">{value ? (STEP_LABEL[value] ?? value) : 'not reached'}</span>
          </li>
        ))}
      </ol>
      {[...security.notes, ...security.guardReasons].map((note, i) => (
        <p key={i} className="note">
          {note}
        </p>
      ))}
    </details>
  )
}

export function ResultCard({ result }: { result: QueryResult }) {
  const answered = result.decision === 'ALLOW' || result.decision === 'RESTRICT'
  const spec = answered ? chartSpec(result.chart, result.columns, result.rows) : null
  return (
    <article className={`result result-${result.decision.toLowerCase()}`} aria-label={HEADINGS[result.decision]}>
      <header className="result-head">
        <h3>{HEADINGS[result.decision]}</h3>
        <DecisionBadge decision={result.decision} />
      </header>

      {result.decision === 'RESTRICT' && (
        <p className="notice notice-restrict">
          Part of this result was withheld to protect individuals&apos; privacy. The rows shown are
          safe to share; nothing is shown about what was withheld.
        </p>
      )}

      {!answered && <p className="notice">{result.message}</p>}

      {answered && result.explanation && <p className="explanation">{result.explanation}</p>}

      {answered && result.rows.length === 0 && (
        <Empty>No matching data. Groups too small to protect individuals are never shown.</Empty>
      )}

      {answered && result.rows.length > 0 && (
        <>
          {spec && <Chart spec={spec} />}
          <ResultTable columns={result.columns} rows={result.rows} />
          <p className="meta">
            {result.rowCount.toLocaleString()} {result.rowCount === 1 ? 'row' : 'rows'}
            {result.rowLimit !== null && result.rowCount >= result.rowLimit
              ? ` (limited to ${result.rowLimit.toLocaleString()})`
              : ''}
          </p>
        </>
      )}

      <SecurityPanel result={result} />
    </article>
  )
}
