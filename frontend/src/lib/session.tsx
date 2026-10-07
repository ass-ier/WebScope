import { createContext, useContext, useEffect, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useLocation, useNavigate } from 'react-router-dom'
import { api } from './api'
import { ErrorNotice, Loading } from '../components/ui'

export interface WorkspaceStatus {
  mode: 'local' | 'hosted'
  temporary: boolean
  session_active: boolean
  expires_at: string | null
  network_enabled: boolean
  retention_notice: string
  max_upload_bytes: number
  max_storage_bytes: number
  max_assessments: number
  formats: string[]
}

const WorkspaceContext = createContext<WorkspaceStatus | null>(null)
export const useWorkspace = () => useContext(WorkspaceContext)

export function SessionGate({ children }: { children: ReactNode }) {
  const cache = useQueryClient()
  const navigate = useNavigate()
  const location = useLocation()
  const session = useQuery({
    queryKey: ['/session'], queryFn: () => api<WorkspaceStatus>('/session'),
    retry: false, refetchInterval: 60_000,
  })
  const start = useMutation({
    mutationFn: () => api<WorkspaceStatus>('/session', 'POST', {}),
    onSuccess: (status) => {
      cache.clear(); cache.setQueryData(['/session'], status)
      if (!['/', '/uploads', '/assessments', '/assessments/new', '/settings', '/cases'].includes(location.pathname)) navigate('/')
    },
  })
  useEffect(() => {
    const expire = () => {
      cache.removeQueries({ predicate: query => query.queryKey[0] !== '/session' })
      void cache.invalidateQueries({ queryKey: ['/session'] })
    }
    window.addEventListener('webscope-session-expired', expire)
    return () => window.removeEventListener('webscope-session-expired', expire)
  }, [cache])
  if (session.isPending) return <main className="session-entry"><Loading label="Checking temporary workspace…" /></main>
  if (session.isError) return <main className="session-entry"><h1>WebScope</h1><ErrorNotice error={session.error} retry={() => void session.refetch()} /></main>
  if (!session.data.session_active) return <main className="session-entry">
    <h1>Investigate the evidence. No sign-in.</h1>
    <p className="page-description">Explore WebScope with complete synthetic investigations, or upload your own captured data into an isolated temporary workspace.</p>
    <section className="section">
      <h2>Your uploads are temporary</h2>
      <ul className="retention-list">
        <li><strong>Export before you leave.</strong> There is no account, saved login, or recovery link.</li>
        <li>Your workspace expires <strong>24 hours after creation</strong>. Access ends immediately at expiry; the deletion worker runs every minute while this service is running.</li>
        <li><strong>A hosted restart or redeploy can clear it earlier.</strong> Uploads are not placed in permanent storage.</li>
        <li><strong>End session</strong> deletes the workspace immediately. Closing a tab or browser does not guarantee immediate server deletion.</li>
        <li>Tabs in the same browser profile share this session. Other sessions cannot access your workspace.</li>
      </ul>
      <p className="muted">The built-in web, DNS and TLS examples are synthetic, not findings from real targets. Hosted workspaces never scan websites; upload previously collected HAR, OpenAPI JSON, or WebScope JSON instead.</p>
    </section>
    <ErrorNotice error={start.error} />
    <div className="form-actions"><button className="button primary" disabled={start.isPending} onClick={() => start.mutate()}>{start.isPending ? 'Preparing synthetic examples…' : 'Start temporary workspace'}</button></div>
  </main>
  return <WorkspaceContext.Provider value={session.data}>{children}</WorkspaceContext.Provider>
}
