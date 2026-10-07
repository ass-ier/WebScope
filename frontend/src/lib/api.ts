import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function responseError(response: Response): Promise<ApiError> {
  let detail = `Request failed (${response.status}). Please retry.`
  try {
    const payload: unknown = await response.json()
    if (typeof payload === 'object' && payload !== null && 'detail' in payload) {
      if (typeof payload.detail === 'string') detail = payload.detail
      else if (Array.isArray(payload.detail)) detail = payload.detail.map((entry: unknown) =>
        typeof entry === 'object' && entry !== null && 'msg' in entry ? String(entry.msg) : 'Invalid input',
      ).join('; ')
    }
  } catch { /* Preserve the HTTP error when the server does not return JSON. */ }
  return new ApiError(detail, response.status)
}

export async function api<T>(path: string, method = 'GET', body?: unknown): Promise<T> {
  let response: Response
  try {
    response = await fetch(`/api${path}`, {
      method,
      headers: method === 'GET' ? { Accept: 'application/json' } : {
        'Content-Type': 'application/json',
        'X-WebScope-Request': 'workstation',
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    })
  } catch {
    throw new ApiError('Cannot reach the WebScope API. Check your connection or service availability, then retry.', 0)
  }
  if (!response.ok) {
    if (response.status === 401) window.dispatchEvent(new Event('webscope-session-expired'))
    throw await responseError(response)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export function useApi<T>(path: string, enabled = true) {
  return useQuery<T, Error>({ queryKey: [path], queryFn: () => api<T>(path), enabled })
}

export function useWrite<T, B = unknown>(path: string, method = 'POST') {
  const cache = useQueryClient()
  return useMutation<T, Error, B>({
    mutationFn: (body) => api<T>(path, method, body),
    onSuccess: async () => { await cache.invalidateQueries() },
  })
}

export async function downloadReport(id: string, filename: string) {
  let response: Response
  try { response = await fetch(`/api/reports/${encodeURIComponent(id)}/download`) }
  catch { throw new ApiError('Download failed. Check your connection and try again before the session expires.', 0) }
  if (!response.ok) throw await responseError(response)
  const url = URL.createObjectURL(await response.blob())
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.append(link)
  link.click()
  link.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export const assessmentPath = (id: string, resource = '') => `/assessments/${encodeURIComponent(id)}${resource ? `/${resource}` : ''}`
