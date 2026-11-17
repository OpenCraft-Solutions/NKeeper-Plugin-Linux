import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import type { SessionViewProps } from '@nkeeper/sdk'
import { timeFormat, type ToolClient } from './client'
import { fromLocalInput, rangeProblem } from './journal'
import { DISTRIBUTION_PRIORITY, MODULE_NAME, NEW_POLICY, declaredModule, denialMatches, renameModule, suggestedName, type SelinuxModule, type SelinuxStatus } from './selinux'
import { useTool } from './tool'
import { Notice, ToolFrame } from './ToolFrame'

/** The SELinux tool's tab, ported from 1.x's SelinuxView. */
export function SelinuxView({ connect, host }: SessionViewProps) {
  const { state, reconnect } = useTool(connect, 'SELinux')
  return (
    <ToolFrame title="SELinux" host={host} state={state} reconnect={reconnect}>
      {state.kind === 'open' ? <Selinux client={state.client} /> : null}
    </ToolFrame>
  )
}

type Editing = { name: string; source: string }

function Selinux({ client }: { client: ToolClient }) {
  const [status, setStatus] = useState<SelinuxStatus | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [notice, setNotice] = useState<{ text: string; error?: boolean } | null>(null)
  const [start, setStart] = useState('')
  const [stop, setStop] = useState('')
  const [find, setFind] = useState('')
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [expanded, setExpanded] = useState<number | null>(null)
  const [editing, setEditing] = useState<Editing | null>(null)
  const [removing, setRemoving] = useState<SelinuxModule | null>(null)
  const [showDistribution, setShowDistribution] = useState(false)

  const refresh = useCallback(
    async (from = '', to = '') => {
      setBusy('Reading')
      try {
        setStatus(await client.request<SelinuxStatus>('status', { since: fromLocalInput(from), until: fromLocalInput(to) }))
        setSelected(new Set())
      } catch (e) {
        setNotice({ text: e instanceof Error ? e.message : 'SELinux could not be read.', error: true })
      } finally {
        setBusy(null)
      }
    },
    [client],
  )

  useEffect(() => {
    // The first load, once the effect has run: it sets state as it goes.
    queueMicrotask(() => void refresh())
  }, [refresh])

  const denials = useMemo(() => status?.denials.filter((d) => denialMatches(d, find)) ?? [], [status, find])
  const rangeError = rangeProblem(start, stop)

  async function generate() {
    const chosen = status?.denials.filter((d) => selected.has(d.eventId)) ?? []
    const name = suggestedName(chosen)
    setBusy('Generating')
    setNotice(null)
    try {
      const { source } = await client.request<{ source: string }>('generate', { name, eventIds: [...new Set(chosen.map((d) => d.eventId))] })
      setEditing({ name, source })
    } catch (e) {
      setNotice({ text: e instanceof Error ? e.message : "The policy couldn't be generated.", error: true })
    } finally {
      setBusy(null)
    }
  }

  async function install(event: FormEvent) {
    event.preventDefault()
    if (!editing) {
      return
    }
    const name = editing.name.trim()
    setBusy('Installing')
    setNotice(null)
    try {
      await client.request('install', { name, source: editing.source })
      setEditing(null)
      setNotice({ text: `Installed ${name}.` })
      await refresh(start, stop)
    } catch (e) {
      setNotice({ text: e instanceof Error ? e.message : "The policy wasn't installed.", error: true })
    } finally {
      setBusy(null)
    }
  }

  async function remove(module: SelinuxModule) {
    setRemoving(null)
    setBusy('Removing')
    setNotice(null)
    try {
      await client.request('remove', { name: module.name, priority: module.priority })
      setNotice({ text: `Removed ${module.name}.` })
      await refresh(start, stop)
    } catch (e) {
      setNotice({ text: e instanceof Error ? e.message : `${module.name} wasn't removed.`, error: true })
    } finally {
      setBusy(null)
    }
  }

  if (!status) {
    return notice ? <Notice text={notice.text} error={notice.error} /> : <p className="nk-linux-muted">Reading SELinux…</p>
  }

  if (status.mode === null) {
    return <Notice text="This host has no SELinux tools (getenforce isn't installed)." />
  }

  const modules = status.modules.filter((m) => showDistribution || m.priority !== DISTRIBUTION_PRIORITY)
  const declared = editing ? declaredModule(editing.source) : null
  const nameOk = editing ? MODULE_NAME.test(editing.name.trim()) : false

  return (
    <>
      {notice ? <Notice text={notice.text} error={notice.error} onClose={() => setNotice(null)} /> : null}

      <div className="nk-linux-toolbar">
        <span>
          Mode: <strong>{status.mode}</strong>
        </span>
        <span className="nk-linux-actions">
          <button type="button" className="nk-linux-button" disabled={busy !== null} onClick={() => void refresh(start, stop)}>
            {busy === 'Reading' ? 'Reading…' : 'Refresh'}
          </button>
        </span>
      </div>

      {editing ? (
        <form className="nk-linux-card" onSubmit={install} aria-label="Install a policy">
          <h3>Install a policy</h3>
          <p className="nk-linux-muted">Read it before installing: it is compiled and installed on the host as it stands.</p>
          <label className="nk-linux-form">
            Policy name
            <input
              className="nk-linux-input"
              value={editing.name}
              onChange={(e) => setEditing({ name: e.target.value, source: renameModule(editing.source, e.target.value.trim()) })}
              spellCheck={false}
            />
          </label>
          <label>
            <span className="nk-linux-muted">Policy source (.te)</span>
            <textarea className="nk-linux-textarea" value={editing.source} onChange={(e) => setEditing({ ...editing, source: e.target.value })} spellCheck={false} />
          </label>
          {nameOk && declared !== editing.name.trim() ? (
            <Notice text={`The source must start by declaring the module: module ${editing.name.trim()} 1.0;`} error />
          ) : null}
          <div className="nk-linux-card-actions">
            <button type="button" className="nk-linux-button" onClick={() => setEditing(null)}>
              Cancel
            </button>
            <button type="submit" className="nk-linux-button" data-danger="" disabled={busy !== null || !nameOk || declared !== editing.name.trim()}>
              {busy === 'Installing' ? 'Installing…' : 'Install'}
            </button>
          </div>
        </form>
      ) : null}

      <h2 className="nk-linux-section">Blocks and audits</h2>
      <form
        className="nk-linux-form"
        onSubmit={(e) => {
          e.preventDefault()
          if (!rangeError) {
            void refresh(start, stop)
          }
        }}
      >
        <label>
          Start
          <input className="nk-linux-input" type="datetime-local" value={start} onChange={(e) => setStart(e.target.value)} />
        </label>
        <label>
          Stop
          <input className="nk-linux-input" type="datetime-local" value={stop} onChange={(e) => setStop(e.target.value)} />
        </label>
        <button type="submit" className="nk-linux-button" disabled={rangeError !== null || busy !== null}>
          Show
        </button>
        <label>
          Find
          <input className="nk-linux-input" placeholder="Process, file, context…" value={find} onChange={(e) => setFind(e.target.value)} />
        </label>
        <button type="button" className="nk-linux-button" data-primary="" disabled={selected.size === 0 || busy !== null} onClick={() => void generate()}>
          {busy === 'Generating' ? 'Generating…' : `Allow ${selected.size || ''} selected…`}
        </button>
      </form>
      {rangeError ? <Notice text={rangeError} error /> : null}
      {status.auditProblem ? <Notice text={status.auditProblem} error /> : null}
      {status.denialsTruncated ? <Notice text="Only the newest 1,000 records are shown. Narrow the time range to see older ones." /> : null}

      {denials.length === 0 ? (
        <p className="nk-linux-muted">{status.auditProblem ? '' : 'Nothing was denied in this time range.'}</p>
      ) : (
        <table className="nk-linux-table">
          <thead>
            <tr>
              <th scope="col">
                <span hidden>Select</span>
              </th>
              <th scope="col">Result</th>
              <th scope="col">Time</th>
              <th scope="col">Process</th>
              <th scope="col">Denied</th>
              <th scope="col">Target</th>
            </tr>
          </thead>
          <tbody>
            {denials.map((denial, index) => {
              const open = expanded === index
              return (
                <tr key={`${denial.eventId}-${index}`} data-selected={selected.has(denial.eventId) ? '' : undefined}>
                  <td>
                    {denial.permissions.length > 0 ? (
                      <input
                        type="checkbox"
                        checked={selected.has(denial.eventId)}
                        aria-label={`Select ${denial.permissions.join(' ')} by ${denial.process ?? 'unknown'}`}
                        onChange={(e) =>
                          setSelected((current) => {
                            const next = new Set(current)
                            if (e.target.checked) {
                              next.add(denial.eventId)
                            } else {
                              next.delete(denial.eventId)
                            }
                            return next
                          })
                        }
                      />
                    ) : null}
                  </td>
                  <td>{denial.type === 'SELINUX_ERR' ? 'Error' : denial.blocked ? 'Blocked' : 'Allowed (logged)'}</td>
                  <td className="nk-linux-mono">{timeFormat.format(new Date(denial.time))}</td>
                  <td>
                    {denial.process}
                    {denial.pid ? <span className="nk-linux-muted">[{denial.pid}]</span> : null}
                  </td>
                  <td>{denial.permissions.join(' ')}</td>
                  <td>
                    <button type="button" className="nk-linux-link" aria-expanded={open} onClick={() => setExpanded(open ? null : index)}>
                      {denial.target ?? '(details)'}
                      {denial.targetClass ? <span className="nk-linux-muted"> ({denial.targetClass})</span> : null}
                    </button>
                    {open ? (
                      <div>
                        <div className="nk-linux-mono nk-linux-muted">
                          {denial.sourceContext} → {denial.targetContext}
                        </div>
                        <pre className="nk-linux-message nk-linux-mono">{denial.raw}</pre>
                      </div>
                    ) : null}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      )}

      <h2 className="nk-linux-section">Policies</h2>
      <div className="nk-linux-toolbar">
        <button type="button" className="nk-linux-button" disabled={busy !== null} onClick={() => setEditing({ name: 'my_policy', source: NEW_POLICY })}>
          New policy…
        </button>
        <button type="button" className="nk-linux-button" data-ghost="" aria-expanded={showDistribution} onClick={() => setShowDistribution((s) => !s)}>
          {showDistribution ? "Hide the distribution's" : "Show the distribution's"}
        </button>
      </div>
      {modules.length === 0 ? (
        <p className="nk-linux-muted">No local policies are installed.</p>
      ) : (
        <table className="nk-linux-table">
          <thead>
            <tr>
              <th scope="col">Module</th>
              <th scope="col">Priority</th>
              <th scope="col">
                <span hidden>Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {modules.map((module) => (
              <tr key={`${module.name}-${module.priority}`}>
                <td className="nk-linux-mono">{module.name}</td>
                <td>{module.priority}</td>
                <td>
                  <div className="nk-linux-row-actions">
                    {module.priority === DISTRIBUTION_PRIORITY ? null : removing === module ? (
                      <>
                        <button type="button" className="nk-linux-button" data-danger="" data-small="" onClick={() => void remove(module)}>
                          Remove {module.name}
                        </button>
                        <button type="button" className="nk-linux-button" data-ghost="" data-small="" onClick={() => setRemoving(null)}>
                          Keep
                        </button>
                      </>
                    ) : (
                      <button type="button" className="nk-linux-button" data-small="" disabled={busy !== null} onClick={() => setRemoving(module)}>
                        Remove
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  )
}
