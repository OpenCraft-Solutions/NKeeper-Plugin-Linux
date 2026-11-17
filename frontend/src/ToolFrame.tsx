import type { ReactNode } from 'react'
import type { ToolState } from './tool'

/**
 * The tools' styles, adopted when the plugin activates: 1.x's session look (a status bar over the tool, cards for
 * opening and failing), on the shell's design tokens, each with a fallback (docs/architecture.md §7.14).
 */
export const toolStyles = `
.nk-linux { display: flex; flex-direction: column; height: 100%; min-height: 0; background: var(--color-bg, #0b1220);
  color: var(--color-text, #e5ebf5); font-family: var(--font-sans, system-ui, sans-serif); font-size: 0.875rem; }
.nk-linux-status { display: flex; align-items: center; gap: 0.5rem; min-height: 2.25rem; padding: 0.25rem 1rem;
  background: var(--color-surface, #111a2e); border-bottom: 1px solid var(--color-border, #233150); font-size: 0.8125rem; }
.nk-linux-dot { width: 0.5rem; height: 0.5rem; flex-shrink: 0; border-radius: 999px; background: var(--color-text-subtle, #7d8ba6); }
.nk-linux-dot[data-state='connecting'] { background: var(--color-warning, #f5b84b); }
.nk-linux-dot[data-state='open'] { background: #4ade80; }
.nk-linux-dot[data-state='ended'] { background: #f87171; }
.nk-linux-status-text { font-weight: 550; }
.nk-linux-target { overflow: hidden; color: var(--color-text-muted, #9aa8c1); text-overflow: ellipsis; white-space: nowrap; }
.nk-linux-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; margin-left: auto; }
.nk-linux-body { position: relative; flex: 1; min-height: 0; overflow: auto; padding: 0.75rem 1rem; }
.nk-linux-overlay { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; padding: 1rem; }
.nk-linux-card { display: flex; flex-direction: column; gap: 0.75rem; max-width: 32rem; padding: 1.25rem 1.5rem;
  background: var(--color-surface, #111a2e); border: 1px solid var(--color-border-strong, #33456b); border-radius: var(--radius-lg, 12px);
  box-shadow: var(--shadow-card, 0 1px 2px rgb(0 0 0 / 0.3), 0 8px 24px rgb(0 0 0 / 0.25)); font-size: 0.9375rem; }
.nk-linux-card[data-error] { border-color: var(--color-danger-border, #b91c1c); }
.nk-linux-card-row { flex-direction: row; align-items: center; }
.nk-linux-card h3 { margin: 0; font-size: 1.0625rem; font-weight: 620; }
.nk-linux-card p { margin: 0; }
.nk-linux-card-actions { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 0.5rem; }
.nk-linux-spinner { width: 1rem; height: 1rem; border: 2px solid var(--color-border-strong, #33456b); border-top-color: var(--color-accent-text, #8fb4ff);
  border-radius: 999px; animation: nk-linux-spin 0.8s linear infinite; }
@keyframes nk-linux-spin { to { transform: rotate(360deg); } }
.nk-linux-button { display: inline-flex; align-items: center; justify-content: center; gap: 0.375rem; min-height: 2rem; padding: 0 0.75rem;
  border: 1px solid var(--color-border-strong, #33456b); border-radius: var(--radius-md, 8px); background: transparent;
  color: var(--color-text, #e5ebf5); font: inherit; font-size: 0.8125rem; font-weight: 600; cursor: pointer; white-space: nowrap; }
.nk-linux-button:hover:not(:disabled) { background: var(--color-surface-raised, #16213a); border-color: var(--color-border-hover, #46598a); }
.nk-linux-button:disabled { opacity: 0.5; cursor: default; }
.nk-linux-button[data-primary] { background: var(--color-accent, #2563eb); border-color: var(--color-accent, #2563eb); color: var(--color-on-accent, #fff); }
.nk-linux-button[data-danger] { border-color: var(--color-danger-border, #b91c1c); color: var(--color-danger-text, #fca5a5); }
.nk-linux-button[data-ghost] { border-color: transparent; }
.nk-linux-button[data-small] { min-height: 1.625rem; padding: 0 0.5rem; }
.nk-linux-input, .nk-linux-select, .nk-linux-textarea { min-height: 2rem; padding: 0 0.5rem; border: 1px solid var(--color-border-strong, #33456b);
  border-radius: var(--radius-md, 8px); background: var(--color-input-bg, #0b1220); color: var(--color-text, #e5ebf5); font: inherit; }
.nk-linux-textarea { width: 100%; min-height: 16rem; padding: 0.5rem; font-family: ui-monospace, 'Cascadia Mono', Consolas, monospace; font-size: 0.8125rem; }
.nk-linux-notice { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; margin-bottom: 0.75rem; padding: 0.5rem 0.75rem;
  border: 1px solid var(--color-border-strong, #33456b); border-radius: var(--radius-md, 8px); background: var(--color-surface, #111a2e); }
.nk-linux-notice[data-error] { border-color: var(--color-danger-border, #b91c1c); color: var(--color-danger-text, #fca5a5); }
.nk-linux-notice > span { flex: 1; }
.nk-linux-toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; margin-bottom: 0.75rem; }
.nk-linux-form { display: flex; flex-wrap: wrap; align-items: flex-end; gap: 0.5rem; margin-bottom: 0.75rem; }
.nk-linux-form label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.75rem; color: var(--color-text-muted, #9aa8c1); }
.nk-linux-table { width: 100%; border-collapse: collapse; }
.nk-linux-table th, .nk-linux-table td { padding: 0.375rem 0.5rem; border-bottom: 1px solid var(--color-border, #233150); text-align: left; vertical-align: top; }
.nk-linux-table th { position: sticky; top: -0.75rem; background: var(--color-bg, #0b1220); font-size: 0.75rem; font-weight: 600;
  color: var(--color-text-muted, #9aa8c1); }
.nk-linux-table tr[data-selected] td { background: var(--color-surface-raised, #16213a); }
.nk-linux-sort { padding: 0; border: 0; background: none; color: inherit; font: inherit; cursor: pointer; }
.nk-linux-link { padding: 0; border: 0; background: none; color: var(--color-accent-text, #8fb4ff); font: inherit; cursor: pointer; text-align: left; }
.nk-linux-link:hover { text-decoration: underline; }
.nk-linux-mono { font-family: ui-monospace, 'Cascadia Mono', Consolas, monospace; font-size: 0.8125rem; }
.nk-linux-muted { color: var(--color-text-muted, #9aa8c1); }
.nk-linux-crumbs { display: flex; flex-wrap: wrap; align-items: center; gap: 0.125rem; flex: 1; min-width: 0;
  font-family: ui-monospace, 'Cascadia Mono', Consolas, monospace; }
.nk-linux-row-actions { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 0.25rem; }
.nk-linux-message { white-space: pre-wrap; word-break: break-word; }
.nk-linux-priority { display: inline-block; min-width: 4.5rem; padding: 0 0.375rem; border-radius: 999px; font-size: 0.75rem; text-align: center;
  background: var(--color-surface-raised, #16213a); }
.nk-linux-priority[data-level='0'], .nk-linux-priority[data-level='1'], .nk-linux-priority[data-level='2'], .nk-linux-priority[data-level='3'] {
  background: #7f1d1d; color: #fecaca; }
.nk-linux-priority[data-level='4'] { background: #78350f; color: #fde68a; }
.nk-linux-section { margin: 1rem 0 0.5rem; font-size: 0.9375rem; font-weight: 620; }
.nk-linux-progress { width: 12rem; }
`

/** A tool's tab: the status bar, then the tool once it's open, or a card while it opens or after it failed. */
export function ToolFrame({
  title,
  host,
  state,
  reconnect,
  actions,
  children,
}: {
  title: string
  host: { name: string }
  state: ToolState
  reconnect: () => void
  actions?: ReactNode
  children?: ReactNode
}) {
  const dot = state.kind === 'open' ? 'open' : state.kind
  const status = state.kind === 'connecting' ? 'Connecting…' : state.kind === 'open' ? title : state.failed ? "Couldn't open" : 'Ended'
  return (
    <div className="nk-linux">
      <div className="nk-linux-status">
        <span className="nk-linux-dot" data-state={dot} />
        <span className="nk-linux-status-text">{status}</span>
        <span className="nk-linux-target">{host.name}</span>
        <div className="nk-linux-actions">
          {state.kind === 'open' ? actions : null}
          {state.kind === 'ended' && !state.failed ? (
            <span className="nk-linux-muted">{state.message}</span>
          ) : null}
          {state.kind === 'ended' && !state.failed ? (
            <button type="button" className="nk-linux-button" onClick={reconnect}>
              Reconnect
            </button>
          ) : null}
        </div>
      </div>
      <div className="nk-linux-body">
        {state.kind === 'connecting' ? (
          <div className="nk-linux-overlay">
            <div className="nk-linux-card nk-linux-card-row" role="status">
              <span className="nk-linux-spinner" aria-hidden="true" />
              <span>Opening {title.toLowerCase()} on {host.name}…</span>
            </div>
          </div>
        ) : null}
        {state.kind === 'ended' && state.failed ? (
          <div className="nk-linux-overlay">
            <div className="nk-linux-card" data-error="" role="alert">
              <h3>{title} couldn't be opened</h3>
              <p>{state.message}</p>
              <div className="nk-linux-card-actions">
                <button type="button" className="nk-linux-button" data-primary="" onClick={reconnect}>
                  Try again
                </button>
              </div>
            </div>
          </div>
        ) : null}
        {state.kind === 'open' ? children : null}
      </div>
    </div>
  )
}

/** A notice above a tool: what happened, or what went wrong. */
export function Notice({ text, error, onClose, children }: { text: string; error?: boolean; onClose?: () => void; children?: ReactNode }) {
  return (
    <div className="nk-linux-notice" data-error={error ? '' : undefined} role={error ? 'alert' : 'status'}>
      <span>{text}</span>
      {children}
      {onClose ? (
        <button type="button" className="nk-linux-button" data-ghost="" data-small="" onClick={onClose}>
          Dismiss
        </button>
      ) : null}
    </div>
  )
}
