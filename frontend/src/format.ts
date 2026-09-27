import type { Cell, Decision } from './api/types'

export function formatCell(value: Cell): string {
  if (value === null) return '—'
  if (typeof value === 'boolean') return value ? 'Yes' : 'No'
  if (typeof value === 'number') {
    return Number.isInteger(value)
      ? value.toLocaleString()
      : value.toLocaleString(undefined, { maximumFractionDigits: 2 })
  }
  return value
}

export function formatDateTime(iso: string): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

export const DECISION_LABEL: Record<Decision, string> = {
  ALLOW: 'Answered',
  RESTRICT: 'Partially answered',
  BLOCK: 'Withheld',
  DENIED: 'Not permitted',
  REJECTED: 'Rejected',
  FAILED: 'Failed',
}

export const ROLE_LABEL: Record<string, string> = {
  ADMIN: 'Administrator',
  HOD: 'Head of Department',
  TEACHER: 'Teacher',
  STUDENT: 'Student',
}
