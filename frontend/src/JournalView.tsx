import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import type { SessionViewProps } from '@nkeeper/sdk'
import { timeFormat, type ToolClient } from './client'
import { NO_FILTERS, PRIORITIES, firstLine, journalEntryMatches, journalFilterBody, rangeProblem, type JournalEntry, type JournalFilters, type JournalPage } from './journal'
import { useTool } from './tool'
import { Notice, ToolFrame } from './ToolFrame'

/** How many followed entries the view keeps, newest first. */
const MAX_FOLLOWED = 5000

/** The Journal tool's tab, ported from 1.x's JournalView. */
export function JournalView({ connect, host }: SessionViewProps) {
  const { state, reconnect } = useTool(connect, 'The journal')
  return (
    <ToolFrame title="Journal" host={host} state={state} reconnect={reconnect}>
      {state.kind === 'open' ? <Journal client={state.client} /> : null}
    </ToolFrame>
  )
}

function Journal({ client }: { client: ToolClient }) {
  const [draft, setDraft] = useState<JournalFilters>(NO_FILTERS)
  const [applied, setApplied] = useState<JournalFilters>(NO_FILTERS)
  const [entries, setEntries] = useState<JournalEntry[]>([])
  const [hasMore, setHasMore] = useState(false)
  const [limited, setLimited] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [following, setFollowing] = useState<string | null>(null)
  const [followNote, setFollowNote] = useState<string | null>(null)
  const [find, setFind] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)

  const read = useCallback(
    async (filters: JournalFilters, after?: string) => {
      setBusy(true)
      setError(null)
      try {
        const page = await client.request<JournalPage>('read', { ...journalFilterBody(filters, true), after })
        setEntries((current) => (after ? [...current, ...page.entries] : page.entries))
        setHasMore(page.hasMore)
        setLimited(page.limited)
      } catch (e) {
        setError(e instanceof Error ? e.message : 'The journal could not be read.')
      } finally {
        setBusy(false)
      }
    },
    [client],
  )

  useEffect(() => {
    // The first load, once the effect has run: it sets state as it goes.
    queueMicrotask(() => void read(NO_FILTERS))
  }, [read])

  // Followed entries arrive as `entry` messages for the follow's request.
  useEffect(() => {
    if (!following) {
      return
    }
    return client.on((message) => {
      if (message.id !== following) {
        return
      }
      if (message.type === 'entry' && message.entry) {
        setEntries((current) => [message.entry as JournalEntry, ...current].slice(0, MAX_FOLLOWED))
      } else if (message.type === 'limited') {
        setLimited(true)
      } else if (message.type === 'followEnded') {
        setFollowing(null)
        setFollowNote(typeof message.message === 'string' ? message.message : 'Following stopped.')
      } else if (message.type === 'error') {
        setFollowing(null)
        setError(typeof message.message === 'string' ? message.message : 'Following stopped.')
      }
    })
  }, [client, following])

  function apply(event: FormEvent) {
    event.preventDefault()
    const problem = rangeProblem(draft.start, draft.stop)
    if (problem) {
      setError(problem)
      return
    }
    setApplied(draft)
    setFollowing(null)
    setFollowNote(null)
    void read(draft)
  }

  async function follow() {
    const id = client.newId()
    setFollowNote(null)
    setError(null)
    setFollowing(id)
    try {
      // Picks up after the newest entry shown, so nothing is missed or shown twice.
      await client.request('follow', { ...journalFilterBody(applied, false), after: entries[0]?.cursor }, id)
    } catch (e) {
      setFollowing(null)
      setError(e instanceof Error ? e.message : 'The journal could not be followed.')
    }
  }

  async function stop() {
    setFollowing(null)
    await client.request('stop').catch(() => undefined)
  }

  const shown = useMemo(() => entries.filter((entry) => journalEntryMatches(entry, find)), [entries, find])
  const set = (change: Partial<JournalFilters>) => setDraft((current) => ({ ...current, ...change }))

  return (
    <>
      <form className="nk-linux-form" onSubmit={apply}>
        <label>
          From
          <input className="nk-linux-input" type="datetime-local" value={draft.start} onChange={(e) => set({ start: e.target.value })} />
        </label>
        <label>
          To
          <input className="nk-linux-input" type="datetime-local" value={draft.stop} onChange={(e) => set({ stop: e.target.value })} />
        </label>
        <label>
          Priority
          <select className="nk-linux-select" value={draft.maxPriority} onChange={(e) => set({ maxPriority: e.target.value })}>
            <option value="">Any</option>
            {PRIORITIES.map((name, value) => (
              <option key={name} value={value}>
                {name} and worse
              </option>
            ))}
          </select>
        </label>
        <label>
          Unit
          <input className="nk-linux-input" value={draft.unit} onChange={(e) => set({ unit: e.target.value })} maxLength={256} spellCheck={false} placeholder="sshd.service" />
        </label>
        <label>
          Program
          <input className="nk-linux-input" value={draft.identifier} onChange={(e) => set({ identifier: e.target.value })} maxLength={256} spellCheck={false} placeholder="Any" />
        </label>
        <label>
          Search
          <input className="nk-linux-input" value={draft.search} onChange={(e) => set({ search: e.target.value })} maxLength={1024} spellCheck={false} placeholder="Regular expression" />
        </label>
        <button type="submit" className="nk-linux-button" data-primary="" disabled={busy}>
          {busy ? 'Reading…' : 'Show'}
        </button>
        {following ? (
          <button type="button" className="nk-linux-button" onClick={() => void stop()}>
            Stop following
          </button>
        ) : (
          <button type="button" className="nk-linux-button" disabled={busy} onClick={() => void follow()} title="Show new entries as they're written">
            Follow
          </button>
        )}
      </form>

      {limited ? (
        <Notice text="This login can only read part of the journal. Use root, a user who may use sudo without a password, or one in the systemd-journal group, to see it all." />
      ) : null}
      {error ? <Notice text={error} error onClose={() => setError(null)} /> : null}
      {followNote ? <Notice text={followNote} onClose={() => setFollowNote(null)} /> : null}
      {following ? <Notice text="Following: new entries appear at the top." /> : null}

      <div className="nk-linux-toolbar">
        <input className="nk-linux-input" placeholder="Find in the entries below" aria-label="Find in the entries below" value={find} onChange={(e) => setFind(e.target.value)} />
        <span className="nk-linux-muted">
          {shown.length.toLocaleString()} of {entries.length.toLocaleString()} entries
        </span>
      </div>

      {entries.length === 0 && !busy ? (
        <p className="nk-linux-muted">No entries match.</p>
      ) : (
        <table className="nk-linux-table">
          <thead>
            <tr>
              <th scope="col">Priority</th>
              <th scope="col">Time</th>
              <th scope="col">Program</th>
              <th scope="col">Message</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((entry) => {
              const open = expanded === entry.cursor
              return (
                <tr key={entry.cursor} data-selected={open ? '' : undefined}>
                  <td>
                    {entry.priority === null ? null : (
                      <span className="nk-linux-priority" data-level={entry.priority}>
                        {PRIORITIES[entry.priority] ?? entry.priority}
                      </span>
                    )}
                  </td>
                  <td className="nk-linux-mono">{entry.time ? timeFormat.format(new Date(entry.time)) : ''}</td>
                  <td>
                    {entry.identifier}
                    {entry.pid ? <span className="nk-linux-muted">[{entry.pid}]</span> : null}
                  </td>
                  <td>
                    <button type="button" className="nk-linux-link" aria-expanded={open} onClick={() => setExpanded(open ? null : entry.cursor)}>
                      {firstLine(entry.message) || '(empty)'}
                    </button>
                    {open ? (
                      <div>
                        <pre className="nk-linux-message nk-linux-mono">{entry.message}</pre>
                        <div className="nk-linux-muted">
                          {entry.unit ? `Unit ${entry.unit} · ` : ''}
                          {entry.hostname ? `Host ${entry.hostname}` : ''}
                        </div>
                      </div>
                    ) : null}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      )}

      {hasMore && !following ? (
        <div className="nk-linux-toolbar">
          <button type="button" className="nk-linux-button" disabled={busy} onClick={() => void read(applied, entries[entries.length - 1]?.cursor)}>
            {busy ? 'Reading…' : 'Older entries'}
          </button>
        </div>
      ) : null}
    </>
  )
}
