export type Decision = 'ALLOW' | 'BLOCK' | 'ESCALATE'
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export type ApprovalStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXECUTED'

export interface Evidence {
  evidence_id: string
  signal: string
  points: number
  text: string
  source: string
}

export interface RiskAssessment {
  score: number
  level: RiskLevel
  evidence: Evidence[]
}

export interface SecurityDecision {
  decision: Decision
  risk: RiskAssessment
  reasons: string[]
  policy_version: string
  required_approval: boolean
}

export interface AuditEvent {
  event_id: string
  event_type: string
  message: string
  data: Record<string, unknown>
  run_id: string
  timestamp: string
}

export interface ApprovalRecord {
  approval_id: string
  run_id: string
  tool_name: string
  arguments: Record<string, unknown>
  signature: string
  risk_score: number
  risk_level: RiskLevel
  reasons: string[]
  status: ApprovalStatus
  operator?: string
  decided_at?: string
  created_at: string
}

export interface SecurityEvent {
  tool: string
  decision: Decision
  risk_score: number
  risk_level: RiskLevel
  signals: string[]
  arguments: Record<string, unknown>
  reasons: string[]
}

export interface ToolInfo {
  name: string
  category: string
  risk: RiskLevel
  requires_approval: boolean
  policy: string
  status: 'protected' | 'unprotected'
  calls_today: number
  kind?: 'read' | 'side_effect'
}

export interface AgentInfo {
  id: string
  name: string
  status: 'protected' | 'unprotected' | 'disconnected'
  provider: string
  model: string
  tools: string[]
  risk_profile: RiskLevel
  policy_set: string
  secured_by?: string
  last_activity?: string
}

export interface ProviderInfo {
  id: string
  name: string
  description: string
  sdk: string | null
  sdk_installed: boolean
  requires_api_key: boolean
  supports_base_url: boolean
  default_model: string | null
  models: string[]
  active: boolean
  configured: boolean
  docs_url: string | null
}

export interface ConfigResponse {
  version: string
  environment: string
  mode: string
  policy_version: string
  allowlisted_tools: string[]
  read_tools: string[]
  side_effect_tools: string[]
  model: {
    provider: string
    provider_name: string
    model_id: string | null
    sdk_installed: boolean
    api_key_set: boolean
    base_url: string | null
  }
  persistence: { durable: boolean; table_name: string | null }
  orchestration: { step_functions: boolean }
  aws_region: string
}

export interface RunSummary {
  run_id: string
  scenario_id: string
  decision: Decision
  risk_score: number
  risk_level: RiskLevel
  attack_detected: boolean
  regression_added: boolean
  security_score: number
}

export interface PolicyRule {
  id: string
  name: string
  description: string
  condition: string
  action: Decision
  target_tools: string[]
  enabled: boolean
}

export interface EvaluationReport {
  run_id: string
  scenario_id: string
  attack_detected: boolean
  risk_score: number
  risk_level: RiskLevel
  decision: Decision
  explanation: string
  mitigation: {
    mitigation_id: string
    version: string
    title: string
    rules: string[]
    applied: boolean
  }
  retest: {
    status: string
    attack_observed: boolean
    forbidden_actions_executed: string[]
    mitigation_effective: boolean
  }
  regression_added: boolean
  security_score: number
  audit: AuditEvent[]
}

export interface Scenario {
  scenario_id: string
  name: string
  input: string
  attack_type: string
  description: string
  expected_result: string
  forbidden_tools: string[]
  must_detect: boolean
}

export interface RunResult {
  run_id: string
  status: string
  report: EvaluationReport
}

export interface HealthResponse {
  status: string
  version: string
}

export interface PendingApprovalsResponse {
  pending: ApprovalRecord[]
  security_events: SecurityEvent[]
}

export interface ProviderConfig {
  id: string
  name: string
  configured: boolean
  models: string[]
  connected: boolean
}

export interface AppSettings {
  provider: string
  model: string
  api_key_set: boolean
  backend_url: string
  demo_mode: boolean
  environment: 'local' | 'demo' | 'production'
}
