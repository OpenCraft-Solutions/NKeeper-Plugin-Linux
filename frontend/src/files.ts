import { type ToolClient, type ToolMessage } from './client'

export interface Entry {
  name: string
  path: string
  kind: 'file' | 'directory' | 'link' | 'other'
  size: number
  modifiedUtc: string
  permissions: string
}

export interface Listing {
  path: string
  parent: string | null
  entries: Entry[]
}

export interface FolderSize {
  size: number
  complete: boolean
}

export type Sort = { key: 'name' | 'size' | 'modified'; descending: boolean }

/** The chunk size for uploads; the plugin takes at most 1 MB a frame. */
export const CHUNK = 1024 * 1024

/** The entries in display order: folders first, then by the chosen column (docs/architecture.md §7.25). */
export function sortEntries(entries: Entry[], sort: Sort, sizes: Record<string, FolderSize>): Entry[] {
  const sizeOf = (e: Entry) => (e.kind === 'directory' ? (sizes[e.path]?.size ?? -1) : e.size)
  const compare = (a: Entry, b: Entry) => {
    const by =
      sort.key === 'name'
        ? a.name.localeCompare(b.name, undefined, { sensitivity: 'base', numeric: true })
        : sort.key === 'size'
          ? sizeOf(a) - sizeOf(b)
          : Date.parse(a.modifiedUtc) - Date.parse(b.modifiedUtc)
    return sort.descending ? -by : by
  }
  return [...entries].sort((a, b) => {
    const folders = (a.kind === 'directory' ? 0 : 1) - (b.kind === 'directory' ? 0 : 1)
    return folders !== 0 && sort.key === 'name' ? folders : compare(a, b) || a.name.localeCompare(b.name)
  })
}

/** Sends a file in chunks, each after the plugin acknowledged the last, so a slow host slows the browser, not the server. */
export function uploadFile(
  client: ToolClient,
  folder: string,
  file: Blob & { name: string },
  overwrite: boolean,
  onProgress: (sent: number) => void,
): Promise<string> {
  const id = client.newId()
  return new Promise<string>((resolve, reject) => {
    let offset = 0
    const sendNext = async () => {
      const chunk = new Uint8Array(await file.slice(offset, offset + CHUNK).arrayBuffer())
      offset += chunk.byteLength
      client.send(chunk)
    }
    const stop = client.on((message: ToolMessage) => {
      if (message.id !== id) {
        return
      }
      if (message.type === 'ready') {
        void sendNext()
      } else if (message.type === 'ack') {
        onProgress(typeof message.received === 'number' ? message.received : offset)
        void sendNext()
      } else if (message.type === 'reply' || message.type === 'error') {
        stop()
      }
    })
    client
      .request<{ path: string }>('upload', { path: folder, name: file.name, size: file.size, overwrite }, id)
      .then((data) => resolve(data.path), reject)
  })
}
