import { describe, expect, it } from 'vitest'
import { chartSpec } from './chartSpec'

const COLS = ['dept', 'avg']
const ROWS = [
  ['CSE', 70],
  ['ECE', 65],
  ['ME', 60],
]

describe('chartSpec', () => {
  it('builds a bar chart from a matching hint', () => {
    expect(chartSpec({ type: 'bar', x: 'dept', y: 'avg' }, COLS, ROWS)).toEqual({
      type: 'bar',
      labels: ['CSE', 'ECE', 'ME'],
      values: [70, 65, 60],
      xLabel: 'dept',
      yLabel: 'avg',
    })
  })

  it('falls back to sensible columns when the hint names unknown ones', () => {
    const spec = chartSpec({ type: 'line', x: 'nope', y: 'missing' }, COLS, ROWS)
    expect(spec?.xLabel).toBe('dept')
    expect(spec?.yLabel).toBe('avg')
  })

  it.each([
    ['no hint', null, COLS, ROWS],
    ['table hint', { type: 'table', x: '', y: '' }, COLS, ROWS],
    ['no rows', { type: 'bar', x: 'dept', y: 'avg' }, COLS, []],
    ['non-numeric values', { type: 'bar', x: 'dept', y: 'dept' }, ['dept'], [['a'], ['b']]],
    ['mixed numeric column', { type: 'bar', x: 'dept', y: 'avg' }, COLS, [['a', 1], ['b', '2']]],
    ['line with one point', { type: 'line', x: 'dept', y: 'avg' }, COLS, [['a', 1]]],
    ['pie with a negative slice', { type: 'pie', x: 'dept', y: 'avg' }, COLS, [['a', 3], ['b', -1]]],
    ['pie summing to zero', { type: 'pie', x: 'dept', y: 'avg' }, COLS, [['a', 0], ['b', 0]]],
    ['pie with too many slices', { type: 'pie', x: 'dept', y: 'avg' }, COLS, Array.from({ length: 9 }, (_, i) => [`d${i}`, i + 1])],
    ['bar with too many bars', { type: 'bar', x: 'dept', y: 'avg' }, COLS, Array.from({ length: 31 }, (_, i) => [`d${i}`, i])],
    ['KPI over several rows', { type: 'number', x: '', y: 'avg' }, COLS, ROWS],
  ] as const)('draws nothing for %s', (_, hint, columns, rows) => {
    expect(chartSpec(hint as never, [...columns], rows.map((r) => [...r]))).toBeNull()
  })

  it('builds a KPI from a single value', () => {
    expect(chartSpec({ type: 'number', x: '', y: 'total' }, ['total'], [[42]])).toMatchObject({
      type: 'number',
      values: [42],
      yLabel: 'total',
    })
  })
})
