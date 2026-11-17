import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent } from 'react'
import type { SessionViewProps } from '@nkeeper/sdk'
import { ToolError, formatSize, timeFormat, type ToolClient } from './client'
import { sortEntries, uploadFile, type Entry, type FolderSize, type Listing, type Sort } from './files'
import { useTool } from './tool'
import { Notice, ToolFrame } from './ToolFrame'

function SortHeader({ label, column, sort, onSort }: { label: string; column: Sort['key']; sort: Sort; onSort: (key: Sort['key']) => void }) {
  const active = sort.key === column
  return (
    <th scope="col" aria-sort={active ? (sort.descending ? 'descending' : 'ascending') : 'none'}>
      <button type="button" className="nk-linux-sort" onClick={() => onSort(column)}>
        {label} {active ? (sort.descending ? '▼' : '▲') : null}
      </button>
    </th>
  )
}

function FolderSizeText({ size }: { size: FolderSize | undefined }) {
  if (!size) {
    return <span className="nk-linux-muted">…</span>
  }
  return size.complete ? <>{formatSize(size.size)}</> : <span title="Part of this folder couldn’t be read, so it’s at least this big.">≥ {formatSize(size.size)}</span>
}

/** The Files tool's tab, ported from 1.x's FileBrowser. */
export function FilesView({ connect, host }: SessionViewProps) {
  const { state, reconnect } = useTool(connect, 'Files')
  return (
    <ToolFrame title="Files" host={host} state={state} reconnect={reconnect}>
      {state.kind === 'open' ? <Browser client={state.client} /> : null}
    </ToolFrame>
  )
}

function Browser({ client }: { client: ToolClient }) {
  const [listing, setListing] = useState<Listing | null>(null)
  const [sizes, setSizes] = useState<Record<string, FolderSize>>({})
  const [sort, setSort] = useState<Sort>({ key: 'name', descending: false })
  const [busy, setBusy] = useState<string | null>(null)
  const [notice, setNotice] = useState<{ text: string; error?: boolean } | null>(null)
  const [conflict, setConflict] = useState<File[] | null>(null)
  const [newFolder, setNewFolder] = useState<string | null>(null)
  const [renaming, setRenaming] = useState<{ entry: Entry; name: string } | null>(null)
  const [deleting, setDeleting] = useState<Entry | null>(null)
  const uploadRef = useRef<HTMLInputElement>(null)

  const open = useCallback(
    async (path: string | null) => {
      setBusy('Loading')
      try {
        const next = await client.request<Listing>('list', { path: path ?? '' })
        setListing(next)
        setSizes({})
        setRenaming(null)
        setDeleting(null)
        const folders = next.entries.filter((e) => e.kind === 'directory').map((e) => e.path)
        if (folders.length > 0) {
          const id = client.newId()
          const stop = client.on((message) => {
            if (message.id !== id) {
              return
            }
            if (message.type === 'size' && typeof message.path === 'string') {
              const size = { size: Number(message.size), complete: message.complete === true }
              setSizes((current) => ({ ...current, [message.path as string]: size }))
            } else if (message.type === 'reply' || message.type === 'error') {
              stop()
            }
          })
          client.request('sizes', { paths: folders }, id).catch(() => undefined)
        }
      } catch (error) {
        setNotice({ text: error instanceof Error ? error.message : 'The folder could not be read.', error: true })
      } finally {
        setBusy(null)
      }
    },
    [client],
  )

  useEffect(() => {
    // The first load, once the effect has run: it sets state as it goes.
    queueMicrotask(() => void open(null))
  }, [open])

  const entries = useMemo(() => (listing ? sortEntries(listing.entries, sort, sizes) : []), [listing, sort, sizes])

  async function run(what: string, action: () => Promise<unknown>, done?: string) {
    setBusy(what)
    setNotice(null)
    try {
      await action()
      if (done) {
        setNotice({ text: done })
      }
    } catch (error) {
      setNotice({ text: error instanceof Error ? error.message : `${what} failed.`, error: true })
    } finally {
      setBusy(null)
    }
    await open(listing?.path ?? null)
  }

  async function upload(files: File[], overwrite: boolean) {
    if (!listing) {
      return
    }
    setConflict(null)
    setBusy('Uploading')
    setNotice(null)
    const done: string[] = []
    try {
      for (const file of files) {
        setNotice({ text: `Uploading ${file.name}…` })
        try {
          await uploadFile(client, listing.path, file, overwrite, (sent) =>
            setNotice({ text: `Uploading ${file.name}: ${formatSize(sent)} of ${formatSize(file.size)}` }),
          )
          done.push(file.name)
        } catch (error) {
          if (error instanceof ToolError && /already exists/.test(error.message) && !overwrite) {
            setConflict(files.slice(files.indexOf(file)))
            setNotice({ text: `${error.message} Replace it?`, error: true })
            return
          }
          throw error
        }
      }
      setNotice({ text: done.length === 1 ? `Uploaded ${done[0]}.` : `Uploaded ${done.length} files.` })
    } catch (error) {
      setNotice({ text: error instanceof Error ? error.message : 'The upload failed.', error: true })
    } finally {
      setBusy(null)
      await open(listing.path)
    }
  }

  function chooseFiles(event: ChangeEvent<HTMLInputElement>) {
    const files = [...(event.target.files ?? [])]
    event.target.value = ''
    if (files.length > 0) {
      void upload(files, false)
    }
  }

  async function download(entry: Entry) {
    try {
      const { url } = await client.request<{ url: string }>('download', { path: entry.path })
      const link = document.createElement('a')
      link.href = url
      link.rel = 'noopener'
      document.body.append(link)
      link.click()
      link.remove()
    } catch (error) {
      setNotice({ text: error instanceof Error ? error.message : 'The download failed.', error: true })
    }
  }

  function sortBy(key: Sort['key']) {
    // A new column starts with what's usually wanted first: A to Z, the biggest, the newest.
    setSort((current) => (current.key === key ? { key, descending: !current.descending } : { key, descending: key !== 'name' }))
  }

  if (!listing) {
    return notice ? <Notice text={notice.text} error={notice.error} /> : <p className="nk-linux-muted">Loading…</p>
  }

  const segments = listing.path.split('/').filter(Boolean)
  return (
    <>
      <div className="nk-linux-toolbar">
        <nav className="nk-linux-crumbs" aria-label="Folder">
          <button type="button" className="nk-linux-link" onClick={() => void open('/')}>
            /
          </button>
          {segments.map((segment, index) => (
            <span key={index}>
              <button type="button" className="nk-linux-link" onClick={() => void open(`/${segments.slice(0, index + 1).join('/')}`)}>
                {segment}
              </button>
              {index < segments.length - 1 ? '/' : null}
            </span>
          ))}
        </nav>
        <button type="button" className="nk-linux-button" disabled={!listing.parent || busy !== null} onClick={() => void open(listing.parent)}>
          Up
        </button>
        <button type="button" className="nk-linux-button" disabled={busy !== null} onClick={() => void open(listing.path)}>
          Refresh
        </button>
        <button type="button" className="nk-linux-button" disabled={busy !== null} onClick={() => setNewFolder('')}>
          New folder
        </button>
        <button type="button" className="nk-linux-button" data-primary="" disabled={busy !== null} onClick={() => uploadRef.current?.click()}>
          {busy === 'Uploading' ? 'Uploading…' : 'Upload'}
        </button>
        <input ref={uploadRef} type="file" multiple hidden onChange={chooseFiles} aria-label="Files to upload" />
      </div>

      {notice ? (
        <Notice text={notice.text} error={notice.error} onClose={conflict ? undefined : () => setNotice(null)}>
          {conflict ? (
            <>
              <button type="button" className="nk-linux-button" data-danger="" onClick={() => void upload(conflict, true)}>
                Replace
              </button>
              <button type="button" className="nk-linux-button" data-ghost="" onClick={() => (setConflict(null), setNotice(null))}>
                Cancel
              </button>
            </>
          ) : null}
        </Notice>
      ) : null}

      {newFolder !== null ? (
        <form
          className="nk-linux-form"
          onSubmit={(event) => {
            event.preventDefault()
            const name = newFolder.trim()
            if (name) {
              setNewFolder(null)
              void run('Creating the folder', () => client.request('mkdir', { path: `${listing.path.replace(/\/$/, '')}/${name}` }))
            }
          }}
        >
          <input
            className="nk-linux-input"
            value={newFolder}
            onChange={(event) => setNewFolder(event.target.value)}
            placeholder="Folder name"
            aria-label="New folder name"
            autoFocus
          />
          <button type="submit" className="nk-linux-button" data-primary="">
            Create
          </button>
          <button type="button" className="nk-linux-button" data-ghost="" onClick={() => setNewFolder(null)}>
            Cancel
          </button>
        </form>
      ) : null}

      {listing.entries.length === 0 ? (
        <p className="nk-linux-muted">This folder is empty.</p>
      ) : (
        <table className="nk-linux-table">
          <thead>
            <tr>
              <SortHeader label="Name" column="name" sort={sort} onSort={sortBy} />
              <SortHeader label="Size" column="size" sort={sort} onSort={sortBy} />
              <SortHeader label="Modified" column="modified" sort={sort} onSort={sortBy} />
              <th scope="col">Permissions</th>
              <th scope="col">
                <span hidden>Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry) => (
              <tr key={entry.path}>
                <td>
                  {renaming?.entry === entry ? (
                    <form
                      className="nk-linux-form"
                      onSubmit={(event) => {
                        event.preventDefault()
                        const name = renaming.name.trim()
                        setRenaming(null)
                        if (name && name !== entry.name) {
                          void run('Renaming', () => client.request('rename', { path: entry.path, newPath: name }))
                        }
                      }}
                    >
                      <input
                        className="nk-linux-input"
                        value={renaming.name}
                        onChange={(event) => setRenaming({ entry, name: event.target.value })}
                        aria-label={`New name for ${entry.name}`}
                        autoFocus
                      />
                      <button type="submit" className="nk-linux-button" data-small="">
                        Rename
                      </button>
                    </form>
                  ) : entry.kind === 'directory' ? (
                    <button type="button" className="nk-linux-link" onClick={() => void open(entry.path)}>
                      📁 {entry.name}
                    </button>
                  ) : (
                    <span>
                      {entry.kind === 'link' ? '🔗' : '📄'} {entry.name}
                    </span>
                  )}
                </td>
                <td>{entry.kind === 'directory' ? <FolderSizeText size={sizes[entry.path]} /> : formatSize(entry.size)}</td>
                <td>{timeFormat.format(new Date(entry.modifiedUtc))}</td>
                <td className="nk-linux-mono">{entry.permissions}</td>
                <td>
                  <div className="nk-linux-row-actions">
                    {deleting === entry ? (
                      <>
                        <button
                          type="button"
                          className="nk-linux-button"
                          data-danger=""
                          data-small=""
                          onClick={() => {
                            setDeleting(null)
                            void run('Deleting', () => client.request('delete', { path: entry.path }), `Deleted ${entry.name}.`)
                          }}
                        >
                          Delete {entry.name}
                        </button>
                        <button type="button" className="nk-linux-button" data-ghost="" data-small="" onClick={() => setDeleting(null)}>
                          Keep
                        </button>
                      </>
                    ) : (
                      <>
                        {entry.kind === 'file' || entry.kind === 'directory' ? (
                          <button type="button" className="nk-linux-button" data-ghost="" data-small="" disabled={busy !== null} onClick={() => void download(entry)}>
                            Download
                          </button>
                        ) : null}
                        <button
                          type="button"
                          className="nk-linux-button"
                          data-ghost=""
                          data-small=""
                          disabled={busy !== null}
                          onClick={() => setRenaming({ entry, name: entry.name })}
                        >
                          Rename
                        </button>
                        <button type="button" className="nk-linux-button" data-ghost="" data-small="" disabled={busy !== null} onClick={() => setDeleting(entry)}>
                          Delete
                        </button>
                      </>
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
