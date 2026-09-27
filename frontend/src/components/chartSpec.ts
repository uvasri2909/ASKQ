// Decides whether (and how) a result can be charted. A chart is drawn only
// when the backend's hint fits the data (right shape, numeric values, sensible
// size); otherwise the caller shows the table alone.

import type { Cell, ChartHint } from '../api/types'
import { formatCell } from '../format'

export interface ChartSpec {
  type: 'bar' | 'line' | 'pie' | 'number'
  labels: string[]
  values: number[]
  xLabel: string
  yLabel: string
}

const LIMITS = { bar: 30, line: 200, pie: 8 }

function numericColumn(rows: Cell[][], index: number): boolean {
  return rows.length > 0 && rows.every((row) => typeof row[index] === 'number')
}

/** The chart to draw, or null when the data does not support the hint. */
export function chartSpec(hint: ChartHint | null, columns: string[], rows: Cell[][]): ChartSpec | null {
  if (hint === null || hint.type === 'table' || rows.length === 0 || columns.length === 0) {
    return null
  }
  let y = hint.y ? columns.indexOf(hint.y) : -1
  if (y < 0) y = columns.findIndex((_, i) => numericColumn(rows, i))
  if (y < 0 || !numericColumn(rows, y)) return null
  const values = rows.map((row) => row[y] as number)

  if (hint.type === 'number') {
    if (rows.length !== 1) return null
    return { type: 'number', labels: [], values, xLabel: '', yLabel: columns[y] }
  }

  let x = hint.x ? columns.indexOf(hint.x) : -1
  if (x < 0 || x === y) x = columns.findIndex((_, i) => i !== y)
  if (x < 0) return null
  const labels = rows.map((row) => formatCell(row[x]))

  if (hint.type === 'pie') {
    if (rows.length < 2 || rows.length > LIMITS.pie || values.some((v) => v < 0)) return null
    if (values.reduce((a, b) => a + b, 0) <= 0) return null
  } else if (rows.length > LIMITS[hint.type] || (hint.type === 'line' && rows.length < 2)) {
    return null
  }
  return { type: hint.type, labels, values, xLabel: columns[x], yLabel: columns[y] }
}
