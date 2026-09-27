// Small dependency-free SVG charts. A chart is drawn only when the backend's
// hint fits the data (right shape, numeric values, sensible size); otherwise
// nothing is drawn and the table alone is shown. All labels are rendered as
// text nodes (React escapes them), never as markup.

import { formatCell } from '../format'
import type { ChartSpec } from './chartSpec'

const PALETTE = ['#2563eb', '#16a34a', '#d97706', '#9333ea', '#dc2626', '#0891b2', '#65a30d', '#db2777']

function BarChart({ spec }: { spec: ChartSpec }) {
  const width = 640
  const barHeight = 26
  const labelWidth = 150
  const height = spec.values.length * barHeight + 16
  const max = Math.max(...spec.values.map(Math.abs), 1)
  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="chart" role="img" aria-label={`Bar chart of ${spec.yLabel} by ${spec.xLabel}`}>
      {spec.values.map((value, i) => {
        const w = (Math.abs(value) / max) * (width - labelWidth - 90)
        const y = 8 + i * barHeight
        return (
          <g key={i}>
            <text x={labelWidth - 8} y={y + 16} textAnchor="end" className="chart-label">
              {spec.labels[i].length > 22 ? `${spec.labels[i].slice(0, 21)}…` : spec.labels[i]}
            </text>
            <rect x={labelWidth} y={y + 3} width={w} height={barHeight - 8} rx={3} fill={PALETTE[0]}>
              <title>{`${spec.labels[i]}: ${formatCell(value)}`}</title>
            </rect>
            <text x={labelWidth + w + 6} y={y + 16} className="chart-value">
              {formatCell(value)}
            </text>
          </g>
        )
      })}
    </svg>
  )
}

function LineChart({ spec }: { spec: ChartSpec }) {
  const width = 640
  const height = 240
  const pad = 36
  const min = Math.min(...spec.values)
  const max = Math.max(...spec.values)
  const span = max - min || 1
  const points = spec.values.map((v, i) => {
    const x = pad + (i * (width - 2 * pad)) / (spec.values.length - 1)
    const y = height - pad - ((v - min) / span) * (height - 2 * pad)
    return { x, y, v, label: spec.labels[i] }
  })
  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="chart" role="img" aria-label={`Line chart of ${spec.yLabel} over ${spec.xLabel}`}>
      <line x1={pad} y1={height - pad} x2={width - pad} y2={height - pad} className="chart-axis" />
      <polyline points={points.map((p) => `${p.x},${p.y}`).join(' ')} fill="none" stroke={PALETTE[0]} strokeWidth={2} />
      {points.map((p, i) => (
        <circle key={i} cx={p.x} cy={p.y} r={3.5} fill={PALETTE[0]}>
          <title>{`${p.label}: ${formatCell(p.v)}`}</title>
        </circle>
      ))}
      <text x={pad} y={height - 10} className="chart-label">{points[0].label}</text>
      <text x={width - pad} y={height - 10} textAnchor="end" className="chart-label">{points[points.length - 1].label}</text>
      <text x={pad} y={20} className="chart-label">{`${spec.yLabel}: ${formatCell(min)} – ${formatCell(max)}`}</text>
    </svg>
  )
}

function PieChart({ spec }: { spec: ChartSpec }) {
  const total = spec.values.reduce((a, b) => a + b, 0)
  const r = 80
  const c = 2 * Math.PI * r
  const lengths = spec.values.map((value) => (value / total) * c)
  const offsets = lengths.map((_, i) => lengths.slice(0, i).reduce((a, b) => a + b, 0))
  return (
    <div className="pie-wrap">
      <svg viewBox="0 0 220 220" className="chart chart-pie" role="img" aria-label={`Share of ${spec.yLabel} by ${spec.xLabel}`}>
        <g transform="rotate(-90 110 110)">
          {spec.values.map((value, i) => (
            <circle
              key={i}
              cx={110}
              cy={110}
              r={r}
              fill="none"
              stroke={PALETTE[i % PALETTE.length]}
              strokeWidth={36}
              strokeDasharray={`${lengths[i]} ${c - lengths[i]}`}
              strokeDashoffset={-offsets[i]}
            >
              <title>{`${spec.labels[i]}: ${formatCell(value)}`}</title>
            </circle>
          ))}
        </g>
      </svg>
      <ul className="legend">
        {spec.labels.map((label, i) => (
          <li key={i}>
            <span className="swatch" style={{ background: PALETTE[i % PALETTE.length] }} aria-hidden="true" />
            {label}: {formatCell(spec.values[i])} ({((spec.values[i] / total) * 100).toFixed(1)}%)
          </li>
        ))}
      </ul>
    </div>
  )
}

export function Chart({ spec }: { spec: ChartSpec }) {
  if (spec.type === 'number') {
    return (
      <div className="kpi" role="img" aria-label={`${spec.yLabel}: ${formatCell(spec.values[0])}`}>
        <span className="kpi-value">{formatCell(spec.values[0])}</span>
        <span className="kpi-label">{spec.yLabel}</span>
      </div>
    )
  }
  if (spec.type === 'bar') return <BarChart spec={spec} />
  if (spec.type === 'line') return <LineChart spec={spec} />
  return <PieChart spec={spec} />
}
