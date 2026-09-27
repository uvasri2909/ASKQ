import type { Cell } from '../api/types'
import { formatCell } from '../format'

export function ResultTable({ columns, rows }: { columns: string[]; rows: Cell[][] }) {
  return (
    <div className="table-wrap" tabIndex={0} role="region" aria-label="Result table">
      <table className="result-table">
        <thead>
          <tr>
            {columns.map((column, i) => (
              <th key={`${i}-${column}`} scope="col">
                {column}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, r) => (
            <tr key={r}>
              {row.map((value, c) => (
                <td key={c} className={typeof value === 'number' ? 'num' : undefined}>
                  {formatCell(value)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
