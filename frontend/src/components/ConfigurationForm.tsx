import { useState } from 'react'
import type { Configuration } from '../types'
import { CheckField, Field, Section } from './ui'

const splitLines = (value: string) => value.split('\n').map((v) => v.trim()).filter(Boolean)
export function ListInput({ label, value, onChange, hint, required = false, placeholder }: {
  label: string; value: string[]; onChange: (value: string[]) => void; hint?: string; required?: boolean; placeholder?: string
}) {
  const [text, setText] = useState(value.join('\n'))
  return <Field label={label} hint={hint}><textarea rows={3} required={required} placeholder={placeholder} value={text} onChange={(e) => { setText(e.target.value); onChange(splitLines(e.target.value)) }} /></Field>
}

export function ConfigurationForm({ value, onChange }: { value: Configuration; onChange: (config: Configuration) => void }) {
  const set = <K extends keyof Configuration>(key: K, next: Configuration[K]) => onChange({ ...value, [key]: next })
  const numbers: { key: keyof Pick<Configuration, 'max_requests' | 'rate_per_second' | 'timeout_seconds' | 'max_body_bytes' | 'max_redirects' | 'max_depth' | 'max_duration_seconds'>; label: string; min: number; max: number; step?: number }[] = [
    { key: 'max_requests', label: 'Request budget', min: 1, max: 200 },
    { key: 'rate_per_second', label: 'Requests per second', min: 0.1, max: 10, step: 0.1 },
    { key: 'timeout_seconds', label: 'Request timeout (seconds)', min: 0.1, max: 30, step: 0.1 },
    { key: 'max_duration_seconds', label: 'Run duration (seconds)', min: 1, max: 600, step: 0.1 },
    { key: 'max_body_bytes', label: 'Response limit (bytes)', min: 512, max: 2097152 },
    { key: 'max_redirects', label: 'Maximum redirects', min: 0, max: 10 },
    { key: 'max_depth', label: 'Discovery depth', min: 0, max: 3 },
  ]
  const collectors: { key: keyof Pick<Configuration, 'links' | 'javascript' | 'robots' | 'sitemap' | 'dns' | 'tls' | 'availability' | 'methods'>; label: string; hint: string }[] = [
    { key: 'links', label: 'Linked resources', hint: 'Discover in-scope links and forms.' },
    { key: 'javascript', label: 'JavaScript analysis', hint: 'Inspect script text; never execute it.' },
    { key: 'robots', label: 'robots.txt', hint: 'Inspect declared crawling directives.' },
    { key: 'sitemap', label: 'sitemap.xml', hint: 'Read published endpoint inventory.' },
    { key: 'dns', label: 'DNS collection', hint: 'Resolve selected host records.' },
    { key: 'tls', label: 'TLS certificate', hint: 'Inspect the HTTPS certificate.' },
    { key: 'availability', label: 'Check HTTP/HTTPS availability (HEAD on standard ports)', hint: 'Explicit Safe HTTP discovery only; shares the central request budget and scope controls.' },
    { key: 'methods', label: 'Observe advertised methods (OPTIONS)', hint: 'Explicit Safe HTTP discovery only; reads advertised methods and never executes imported methods.' },
  ]
  return <>
    <Section title="Collection policy">
      <div className="form-grid"><Field label="Collection mode"><select value={value.mode} onChange={(e) => set('mode', e.target.value as Configuration['mode'])}><option value="PASSIVE">Passive · no network requests</option><option value="SAFE_HTTP">Safe HTTP · authorized, scoped requests</option></select></Field></div>
      <p className="notice">{value.mode === 'PASSIVE' ? 'PASSIVE performs no target network activity. Work with imported inventory and existing evidence. Collector choices apply only if you later enable Safe HTTP.' : 'SAFE_HTTP permits explicitly initiated, read-only collection. Requests remain subject to scope, authorization, and the limits below.'}</p>
      <div className="form-grid checks-grid">{collectors.map((item) => <CheckField key={item.key} label={item.label} hint={item.hint} checked={value[item.key]} onChange={(next) => set(item.key, next)} />)}</div>
    </Section>
    <Section title="Request limits"><div className="form-grid three">{numbers.map((item) => <Field key={item.key} label={item.label}><input required type="number" min={item.min} max={item.max} step={item.step || 1} value={Number.isFinite(value[item.key]) ? value[item.key] : ''} onChange={(e) => set(item.key, e.target.valueAsNumber)} /></Field>)}</div></Section>
    <Section title="Explicit network permissions">
      <div className="form-grid">
        <ListInput label="Safe check paths" value={value.safe_paths} onChange={(paths) => set('safe_paths', paths)} hint="One absolute path per line. No host, query, or fragment. Only these paths can be checked." placeholder="/health" />
        <Field label="Additional allowed ports" hint="Comma-separated port numbers, 1–65535. At most 10. Empty uses the backend's default port policy."><input defaultValue={value.allowed_ports.join(', ')} placeholder="8443, 8766" onChange={(e) => {
          const ports = e.target.value.split(',').map((p) => p.trim()).filter(Boolean).map(Number)
          e.target.setCustomValidity(ports.length > 10 || ports.some((p) => !Number.isInteger(p) || p < 1 || p > 65535) ? 'Enter at most 10 valid port numbers.' : '')
          set('allowed_ports', ports)
        }} /></Field>
      </div>
      <CheckField label="Permit private / loopback networks" hint="Enable only for an explicitly authorized local or internal target. Does not bypass the host allowlist." checked={value.allow_private_network} onChange={(next) => set('allow_private_network', next)} />
    </Section>
    <Section title="Risk context"><p className="muted section-intro">These assessment-level factors inform transparent priority calculation, not automated severity or confidence.</p><div className="form-grid three">
      <Field label="Exposure"><select value={value.exposure} onChange={(e) => set('exposure', e.target.value as Configuration['exposure'])}><option value="INTERNAL">Internal</option><option value="INTERNET">Internet</option></select></Field>
      <Field label="Asset importance"><select value={value.asset_importance} onChange={(e) => set('asset_importance', e.target.value as Configuration['asset_importance'])}><option value="LOW">Low</option><option value="STANDARD">Standard</option><option value="PRODUCTION">Production</option></select></Field>
      <Field label="Authentication context"><select value={value.authentication_context} onChange={(e) => set('authentication_context', e.target.value as Configuration['authentication_context'])}><option value="UNKNOWN">Unknown</option><option value="REQUIRED">Required</option><option value="NOT_REQUIRED">Not required</option></select></Field>
    </div></Section>
  </>
}
