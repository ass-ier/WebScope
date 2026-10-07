import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Upload } from 'lucide-react'
import { useMutation } from '@tanstack/react-query'
import { api, useWrite } from '../lib/api'
import { useWorkspace } from '../lib/session'
import type { Assessment } from '../types'
import { CheckField, ErrorNotice, Field, PageHeader, Section, date } from '../components/ui'

export function UploadData() {
  const session = useWorkspace()
  const navigate = useNavigate()
  const [format, setFormat] = useState('har')
  const [name, setName] = useState('')
  const [target, setTarget] = useState('')
  const [document, setDocument] = useState<Record<string, unknown> | null>(null)
  const [filename, setFilename] = useState('')
  const [error, setError] = useState('')
  const [consent, setConsent] = useState(false)
  const [reading, setReading] = useState(false)
  const upload = useWrite<Assessment>('/imports')
  const examples = useMutation({
    mutationFn: () => api<Assessment[]>('/examples', 'POST', {}),
    onSuccess: () => navigate('/assessments'),
  })
  return <>
    <PageHeader title="Upload your own data" description="Analyze a capture or assessment without sending requests to its target." />
    <div className="notice retention-emphasis"><div><strong>Temporary upload — export before your session ends.</strong>
      <p>This workspace expires {date(session?.expires_at)}, or earlier on a hosted restart or redeploy. End session deletes its uploads, findings, notes and reports immediately. Closing a tab alone does not delete server data.</p></div></div>
    <form onSubmit={(event) => {
      event.preventDefault()
      if (!document) { setError('Choose a valid JSON or HAR file before uploading.'); return }
      upload.mutate({ format, name: name.trim(), target: target.trim() || null, document, consent },
        { onSuccess: result => navigate(`/assessments/${result.id}`) })
    }}>
      <Section title="Choose a supported capture">
        <div className="form-grid">
          <Field label="Upload format"><select value={format} onChange={event => { setFormat(event.target.value); setConsent(false) }}>
            <option value="har">HAR · HTTP request and response capture</option>
            <option value="webscope">WebScope JSON · full assessment export</option>
            <option value="openapi">OpenAPI JSON · API inventory</option>
          </select></Field>
          <Field label="Assessment name"><input required maxLength={160} value={name} onChange={event => setName(event.target.value)} placeholder="My application capture" /></Field>
          <Field label="Target URL" hint={format === 'openapi' ? 'Required: absolute HTTP(S) URL used to resolve relative API paths.' : 'Optional for HAR. WebScope JSON uses its recorded target.'}>
            <input type="url" required={format === 'openapi'} disabled={format === 'webscope'} maxLength={4096} value={target} onChange={event => setTarget(event.target.value)} placeholder="https://your-application.example" />
          </Field>
          <Field label="Data file" hint="Maximum 2 MB. JSON and HAR only; archives, executable files and YAML are not accepted.">
            <input type="file" accept=".json,.har,application/json" disabled={reading || upload.isPending}
              onChange={async event => {
                const file = event.target.files?.[0]
                setDocument(null); setFilename(''); setError(''); setConsent(false)
                if (!file) return
                if (file.size > 2_000_000) { setError('This file exceeds 2 MB. Export a smaller capture.'); return }
                if (!/\.(json|har)$/i.test(file.name)) { setError('Choose a .json or .har file.'); return }
                setReading(true)
                try {
                  const parsed: unknown = JSON.parse(await file.text())
                  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('The file must contain a JSON object.')
                  setDocument(parsed as Record<string, unknown>); setFilename(file.name)
                  if (!name) setName(file.name.replace(/\.(json|har)$/i, ''))
                } catch (failure) {
                  setError(failure instanceof Error ? `Cannot read this file: ${failure.message}` : 'Cannot read this file.')
                } finally { setReading(false) }
              }} />
          </Field>
        </div>
        {filename && <p className="muted upload-selected">Selected: {filename}. Nothing has been uploaded yet.</p>}
      </Section>
      <Section title="Understand what is imported">
        <p className="section-intro">{format === 'har'
          ? 'HAR imports preserve redacted request/response observations and derive inventories and deterministic findings. Request bodies are omitted. Captures may contain private data—remove it before uploading.'
          : format === 'webscope'
            ? 'WebScope imports restore evidence, inventories, notes, cases and declared findings under new IDs. Imported conclusions and rule declarations are labeled unverified; import does not prove the original claims.'
            : 'OpenAPI imports add methods, parameters and security requirements to inventory. Remote/file references are rejected; imported operations are never executed.'}</p>
        <p className="muted section-intro">Redaction cannot identify every opaque secret or text inside an image. Review your file first. Do not upload credentials or data you are not permitted to share with this deployment.</p>
        <CheckField label="I am allowed to upload this data and understand it is temporary" checked={consent} onChange={setConsent}
          hint="I will export anything I need before the session expires or I choose End session." />
      </Section>
      <ErrorNotice error={error || upload.error} />
      <div className="form-actions"><Link className="button" to="/assessments">Cancel</Link>
        <button className="button primary" disabled={!document || !consent || !name.trim() || reading || upload.isPending}><Upload size={16} />{upload.isPending ? 'Importing and redacting…' : 'Upload to temporary workspace'}</button></div>
    </form>
    <Section title="Prefer to explore synthetic examples?">
      <p className="section-intro">The bundled web investigation includes all example endpoints, evidence, findings, notes and a closed case. A second example contains all seven DNS record types and illustrative TLS weaknesses.</p>
      <button className="button" disabled={examples.isPending} onClick={() => examples.mutate()}>{examples.isPending ? 'Loading…' : 'Open synthetic examples'}</button>
      <ErrorNotice error={examples.error} />
    </Section>
  </>
}
