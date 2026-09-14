import type {
  AgentInfo,
  AuditEvent,
  ConfigResponse,
  HealthResponse,
  PendingApprovalsResponse,
  PolicyRule,
  ProviderInfo,
  RunResult,
  RunSummary,
  Scenario,
  ToolInfo,
} from '../types'
import env from '../lib/env'

const DEFAULT_TIMEOUT_MS = 30_000
const BACKEND_URL_KEY = 'sentinel_backend_url'

/** Resolve the API base at call time so the Settings page can change it live. */
export function getApiBase(): string {
  try {
    const stored = localStorage.getItem(BACKEND_URL_KEY)
    if (stored && stored.trim()) return stored.trim().replace(/\/$/, '')
  } catch {
    /* ignore storage errors */
  }
  return env.API_BASE
}

export class ApiError extends Error {
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS)
  try {
    const res = await fetch(`${getApiBase()}${path}`, {
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      ...options,
    })
    if (!res.ok) {
      const body = await res.text().catch(() => '')
      let detail = body
      try {
        const parsed = JSON.parse(body)
        detail = parsed.error || parsed.message || body
      } catch {
        /* keep raw body */
      }
      throw new ApiError(res.status, detail || `Request failed with status ${res.status}`)
    }
    if (res.status === 204) return undefined as T
    return (await res.json()) as T
  } catch (error) {
    if (error instanceof ApiError) throw error
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw new ApiError(408, 'Request timed out')
    }
    throw new ApiError(0, error instanceof Error ? error.message : 'Network error')
  } finally {
    clearTimeout(timeout)
  }
}

export interface StatsResponse {
  total_runs: number
  total_events: number
  allowed: number
  blocked: number
  escalated: number
  high_risk: number
  decisions?: Record<string, number>
}

export interface EventsResponse {
  events: AuditEvent[]
}

export const api = {
  health: () => request<HealthResponse>('/health'),

  getConfig: () => request<ConfigResponse>('/config'),

  getProviders: () => request<{ providers: ProviderInfo[] }>('/providers'),

  getAgents: () => request<{ agents: AgentInfo[] }>('/agents'),

  getTools: () => request<{ tools: ToolInfo[] }>('/tools'),

  getPolicies: () => request<{ policies: PolicyRule[] }>('/policies'),

  getScenarios: () => request<{ scenarios: Scenario[] }>('/scenarios'),

  getScenario: (scenario_id: string) => request<Scenario>(`/scenarios/${scenario_id}`),

  startRun: (scenario_id?: string) =>
    request<RunResult>('/runs', {
      method: 'POST',
      body: JSON.stringify({ scenario_id }),
    }),

  getRuns: () => request<{ runs: RunSummary[] }>('/runs'),

  getRun: (run_id: string) => request<RunResult>(`/runs/${run_id}`),

  getRegressions: () =>
    request<{ cases: Array<{ scenario_id: string; name: string }> }>('/regressions'),

  getApprovals: () => request<PendingApprovalsResponse>('/approvals'),

  decideApproval: (approval_id: string, decision: 'APPROVE' | 'REJECT') =>
    request<{ approval_id: string; status: string; result?: unknown }>('/approvals', {
      method: 'POST',
      body: JSON.stringify({ approval_id, decision }),
    }),

  resetAgent: () => request<{ status: string }>('/approvals/reset', { method: 'POST' }),

  getEvents: () => request<EventsResponse>('/events'),

  getStats: () => request<StatsResponse>('/stats'),
}

export const backendUrl = {
  key: BACKEND_URL_KEY,
  get: () => {
    try {
      return localStorage.getItem(BACKEND_URL_KEY) || ''
    } catch {
      return ''
    }
  },
  set: (value: string) => {
    try {
      if (value.trim()) localStorage.setItem(BACKEND_URL_KEY, value.trim())
      else localStorage.removeItem(BACKEND_URL_KEY)
    } catch {
      /* ignore */
    }
  },
}
