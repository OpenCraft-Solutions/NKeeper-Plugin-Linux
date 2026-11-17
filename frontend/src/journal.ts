/** One journal entry. */
export interface JournalEntry {
  cursor: string
  time: string | null
  /** syslog's: 0 (emergency) to 7 (debug). */
  priority: number | null
  unit: string | null
  identifier: string | null
  pid: string | null
  hostname: string | null
  message: string
}

export interface JournalPage {
  entries: JournalEntry[]
  hasMore: boolean
  limited: boolean
}

export const PRIORITIES = ['Emergency', 'Alert', 'Critical', 'Error', 'Warning', 'Notice', 'Info', 'Debug']

/** What to read. Times are as a datetime-local field holds them: the browser's zone, or empty. */
export interface JournalFilters {
  start: string
  stop: string
  /** This priority and worse; empty for all. */
  maxPriority: string
  unit: string
  identifier: string
  search: string
}

export const NO_FILTERS: JournalFilters = { start: '', stop: '', maxPriority: '', unit: '', identifier: '', search: '' }

/** A datetime-local field's value as an instant for the server; undefined when empty or incomplete. */
export function fromLocalInput(value: string): string | undefined {
  const time = value ? new Date(value) : null
  return time && !Number.isNaN(time.getTime()) ? time.toISOString() : undefined
}

/** Why a start and stop can't be used, or null. */
export function rangeProblem(start: string, stop: string): string | null {
  const from = fromLocalInput(start)
  const to = fromLocalInput(stop)
  return from && to && from > to ? 'The start is after the stop.' : null
}

/** The filters as the plugin wants them. */
export function journalFilterBody(filters: JournalFilters, withTimes: boolean) {
  return {
    since: withTimes ? fromLocalInput(filters.start) : undefined,
    until: withTimes ? fromLocalInput(filters.stop) : undefined,
    maxPriority: filters.maxPriority === '' ? undefined : Number(filters.maxPriority),
    unit: filters.unit.trim() || undefined,
    identifier: filters.identifier.trim() || undefined,
    search: filters.search.trim() || undefined,
  }
}

/** Whether an entry has the text anywhere the table or its details show. */
export function journalEntryMatches(entry: JournalEntry, text: string): boolean {
  const needle = text.trim().toLowerCase()
  return !needle || [entry.message, entry.unit, entry.identifier, entry.hostname, entry.pid].some((value) => value?.toLowerCase().includes(needle))
}

/** A message's first line with text, for the table. */
export function firstLine(message: string): string {
  return message.split(/\r?\n/).find((line) => line.trim())?.trim() ?? ''
}
