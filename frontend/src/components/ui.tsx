import { useEffect, useId, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { AlertCircle, ArrowDown, ArrowLeft, ArrowUp, Check, ChevronRight, FileSearch, LoaderCircle, Search, X } from 'lucide-react'
import type { UseQueryResult } from '@tanstack/react-query'
import type { Assessment, Json, Note } from '../types'
import { useWrite } from '../lib/api'

export function human(value: string) { return value.replaceAll('_', ' ').toLowerCase().replace(/^\w/, (c) => c.toUpperCase()) }
export function date(value: string | null | undefined) {
  if (!value) return 'Not recorded'
  const parsed = new Date(value)
  return Number.isNaN(parsed.valueOf()) ? value : parsed.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}
export function shortId(value: string) { return value.slice(0, 8) }
export function AssessmentTrail({ id, label = 'Back to assessment' }: { id: string; label?: string }) {
  return <Link to={`/assessments/${encodeURIComponent(id)}`} className="back-link"><ArrowLeft size={14} />{label}</Link>
}
export function Badge({ value, severity = false }: { value: string; severity?: boolean }) {
  return <span className={`badge ${severity ? `severity-${value.toLowerCase()}` : ''}`}>{human(value)}</span>
}
export function PageHeader({ title, description, actions }: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return <header className="page-header"><div><h1>{title}</h1>{description && <div className="page-description">{description}</div>}</div>{actions && <div className="actions">{actions}</div>}</header>
}
export function Section({ title, children, action, className = '' }: { title: string; children: ReactNode; action?: ReactNode; className?: string }) {
  return <section className={`section ${className}`}><div className="section-heading"><h2>{title}</h2>{action}</div>{children}</section>
}
export function Empty({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return <div className="empty-state"><FileSearch size={25} aria-hidden="true" /><h3>{title}</h3>{children && <p>{children}</p>}{action}</div>
}
export function ErrorNotice({ error, retry }: { error: Error | string | null | undefined; retry?: () => void }) {
  if (!error) return null
  return <div className="notice error" role="alert"><AlertCircle size={18} aria-hidden="true" /><div>{typeof error === 'string' ? error : error.message}</div>{retry && <button className="button small" onClick={retry}>Retry</button>}</div>
}
export function Success({ children }: { children: ReactNode }) { return <div role="status" className="notice success"><Check size={17} aria-hidden="true" />{children}</div> }
export function Loading({ label = 'Loading records…' }: { label?: string }) {
  return <div className="loading" role="status"><LoaderCircle className="spin" size={19} aria-hidden="true" />{label}</div>
}
export function QueryState<T>({ query, children }: { query: UseQueryResult<T, Error>; children: (data: T) => ReactNode }) {
  if (query.isPending) return <Loading />
  if (query.isError) return <ErrorNotice error={query.error} retry={() => void query.refetch()} />
  return <>{children(query.data)}</>
}
export function AssessmentPolicyNotice({ query }: { query: UseQueryResult<Assessment, Error> }) {
  if (query.isPending) return <Loading label="Checking assessment policy…" />
  if (query.isError) return <ErrorNotice error={query.error} retry={() => void query.refetch()} />
  if (query.data.status === 'ARCHIVED') return <div className="notice">This assessment is archived and read-only. Existing evidence and reports remain available. <Link to={`/assessments/${query.data.id}`}>Restore it to draft to make changes.</Link></div>
  if (query.data.status === 'RUNNING') return <div className="notice">Collection is running. Records are read-only until the execution finishes.</div>
  return null
}
export function Field({ label, hint, children, className = '' }: { label: string; hint?: string; children: ReactNode; className?: string }) {
  return <label className={`field ${className}`}><span className="field-label">{label}</span>{children}{hint && <span className="field-hint">{hint}</span>}</label>
}
export function CheckField({ label, hint, checked, onChange, disabled = false }: { label: string; hint?: string; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return <label className="check-field"><input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} disabled={disabled} /><span><strong>{label}</strong>{hint && <span className="field-hint">{hint}</span>}</span></label>
}
export function Meta({ items }: { items: [string, ReactNode][] }) {
  return <dl className="metadata">{items.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value ?? 'Not recorded'}</dd></div>)}</dl>
}
export function JsonView({ value, label = 'Structured data' }: { value: Json | object; label?: string }) {
  return <pre className="code-block" tabIndex={0} aria-label={label}><code>{JSON.stringify(value, null, 2)}</code></pre>
}
export function RecordLink({ id, kind = 'evidence', children }: { id: string; kind?: 'evidence' | 'findings' | 'transactions' | 'cases'; children?: ReactNode }) {
  return <Link className="record-link" to={`/${kind}/${encodeURIComponent(id)}`}>{children || <><span className="mono">{shortId(id)}</span><ChevronRight size={13} aria-hidden="true" /></>}</Link>
}
export function Tabs({ items, label }: { items: { key: string; label: string; content: ReactNode }[]; label: string }) {
  const [active, setActive] = useState(items[0]?.key)
  const id = useId()
  const current = items.find((item) => item.key === active) || items[0]
  return <div><div role="tablist" aria-label={label} className="tabs">{items.map((item, index) =>
    <button key={item.key} role="tab" id={`${id}-${item.key}`} aria-controls={`${id}-panel`} aria-selected={current.key === item.key} tabIndex={current.key === item.key ? 0 : -1} onClick={() => setActive(item.key)} onKeyDown={(event) => {
      const next = event.key === 'ArrowRight' ? (index + 1) % items.length : event.key === 'ArrowLeft' ? (index + items.length - 1) % items.length : event.key === 'Home' ? 0 : event.key === 'End' ? items.length - 1 : -1
      if (next >= 0) { event.preventDefault(); setActive(items[next].key); document.getElementById(`${id}-${items[next].key}`)?.focus() }
    }}>{item.label}</button>)}</div><div role="tabpanel" id={`${id}-panel`} aria-labelledby={`${id}-${current.key}`} tabIndex={0}>{current.content}</div></div>
}

export interface Column<T> { key: string; label: string; render: (row: T) => ReactNode; sort?: (row: T) => string | number; className?: string }
export function DataTable<T extends { id: string }>({ rows, columns, label, search, emptyTitle = 'No records yet', emptyDescription, filters }: {
  rows: T[]; columns: Column<T>[]; label: string; search?: (row: T) => string
  emptyTitle?: string; emptyDescription?: string; filters?: ReactNode
}) {
  const [term, setTerm] = useState('')
  const [sorting, setSorting] = useState<{ key: string; direction: number } | null>(null)
  const [limit, setLimit] = useState(50)
  const filtered = search ? rows.filter((row) => search(row).toLowerCase().includes(term.toLowerCase())) : rows
  const column = columns.find((entry) => entry.key === sorting?.key)
  const sorted = column?.sort ? [...filtered].sort((a, b) => {
    const left = column.sort!(a), right = column.sort!(b)
    return (typeof left === 'number' && typeof right === 'number' ? left - right : String(left).localeCompare(String(right))) * (sorting?.direction || 1)
  }) : filtered
  return <div className="data-table">
    {(search || filters) && <div className="table-toolbar">{search && <label className="search-field"><Search size={16} aria-hidden="true" /><span className="sr-only">Search {label.toLowerCase()}</span><input type="search" placeholder={`Search ${label.toLowerCase()}…`} value={term} onChange={(e) => { setTerm(e.target.value); setLimit(50) }} /></label>}{filters}<span className="record-count">{filtered.length} {filtered.length === 1 ? 'record' : 'records'}</span></div>}
    {sorted.length ? <><div className="table-scroll" tabIndex={0} role="region" aria-label={label}><table><caption className="sr-only">{label}</caption><thead><tr>{columns.map((col) => <th key={col.key} className={col.className} scope="col" aria-sort={sorting?.key === col.key ? sorting.direction === 1 ? 'ascending' : 'descending' : undefined}>{col.sort ? <button className="sort-button" onClick={() => setSorting({ key: col.key, direction: sorting?.key === col.key ? -sorting.direction : 1 })}>{col.label}{sorting?.key === col.key && (sorting.direction === 1 ? <ArrowUp size={12} /> : <ArrowDown size={12} />)}</button> : col.label}</th>)}</tr></thead><tbody>{sorted.slice(0, limit).map((row) => <tr key={row.id}>{columns.map((col) => <td key={col.key} className={col.className}>{col.render(row)}</td>)}</tr>)}</tbody></table></div>{sorted.length > limit && <div className="table-footer"><button className="button" onClick={() => setLimit(limit + 50)}>Show 50 more</button><span className="muted">Showing {Math.min(limit, sorted.length)} of {sorted.length}</span></div>}</> : <Empty title={term ? 'No matching records' : emptyTitle}>{term ? 'Try a different search or clear the filters.' : emptyDescription}</Empty>}
  </div>
}

export function ConfirmDialog({ title, children, confirmLabel, onCancel, onConfirm, pending, error, danger = false }: {
  title: string; children: ReactNode; confirmLabel: string; onCancel: () => void
  onConfirm: () => void; pending: boolean; error?: Error | null; danger?: boolean
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const titleId = useId()
  useEffect(() => {
    const element = ref.current
    element?.showModal()
    return () => element?.close()
  }, [])
  return <dialog ref={ref} className="dialog" aria-labelledby={titleId} onCancel={(e) => { e.preventDefault(); if (!pending) onCancel() }}>
    <div className="dialog-heading"><h2 id={titleId}>{title}</h2><button autoFocus className="icon-button" aria-label="Cancel action" disabled={pending} onClick={onCancel}><X size={20} /></button></div>
    <div className="dialog-body">{children}</div><ErrorNotice error={error} />
    <div className="dialog-actions"><button className="button" disabled={pending} onClick={onCancel}>Cancel</button><button className={`button ${danger ? 'danger' : 'primary'}`} disabled={pending} onClick={onConfirm}>{pending ? 'Working…' : confirmLabel}</button></div>
  </dialog>
}

export function Notes({ notes, path, readOnly = false }: { notes: Note[]; path: string; readOnly?: boolean }) {
  const [content, setContent] = useState('')
  const [author, setAuthor] = useState('Local analyst')
  const mutation = useWrite<Note, { content: string; author: string }>(path)
  return <Section title="Analyst notes">
    {notes.length ? <ol className="note-list">{notes.map((note) => <li key={note.id}><div className="row-between"><strong>{note.author}</strong><time dateTime={note.created_at}>{date(note.created_at)}</time></div><p className="preserve">{note.content}</p><RecordLink id={note.evidence_id}>Note evidence <span className="mono">{shortId(note.evidence_id)}</span></RecordLink></li>)}</ol> : <p className="muted">No analyst notes. Record verification steps, context, and decisions.</p>}
    {readOnly ? <p className="field-hint note-form">Analyst notes are read-only for this assessment.</p> : <form className="stack note-form" onSubmit={(event) => { event.preventDefault(); mutation.mutate({ content: content.trim(), author: author.trim() }, { onSuccess: () => setContent('') }) }}>
      <div className="form-grid"><Field label="Analyst name"><input required maxLength={100} value={author} onChange={(e) => setAuthor(e.target.value)} /></Field></div>
      <Field label="New analyst note" hint="Saved as source evidence and included in the audit trail."><textarea required maxLength={20000} rows={4} value={content} onChange={(e) => setContent(e.target.value)} /></Field>
      <ErrorNotice error={mutation.error} />{mutation.isSuccess && <Success>Note saved.</Success>}
      <div><button className="button primary" disabled={mutation.isPending || !content.trim() || !author.trim()}>{mutation.isPending ? 'Saving…' : 'Add note'}</button></div>
    </form>}
  </Section>
}
