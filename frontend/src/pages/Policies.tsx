import { Shield, AlertTriangle, CheckCircle, Ban } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { Card } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { PageState } from '../components/ui/PageState'
import { api } from '../api/client'
import { useApi } from '../lib/useApi'
import type { Decision } from '../types'

const actionIcons: Record<Decision, LucideIcon> = {
  ALLOW: CheckCircle,
  BLOCK: Ban,
  ESCALATE: AlertTriangle,
}

const actionColors: Record<Decision, string> = {
  ALLOW: 'text-allow',
  BLOCK: 'text-block',
  ESCALATE: 'text-escalate',
}

export function Policies() {
  const { data, error, loading, reload } = useApi(() => api.getPolicies(), [])
  const policies = data?.policies ?? []

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Shield className="w-5 h-5 text-accent" />
        <h1 className="text-xl font-bold">Security Policies</h1>
        <span className="text-xs font-mono text-text-muted bg-bg-elevated px-2 py-0.5 rounded">
          {policies.filter((p) => p.enabled).length} active
        </span>
      </div>

      <PageState loading={loading} error={error} onRetry={reload}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {policies.map((policy) => {
            const Icon = actionIcons[policy.action] ?? Shield
            const color = actionColors[policy.action] ?? 'text-text-secondary'
            return (
              <Card key={policy.id}>
                <div className="flex items-start gap-3 mb-3">
                  <div className={`w-8 h-8 rounded-lg bg-bg-elevated flex items-center justify-center ${color}`}>
                    <Icon className="w-4 h-4" />
                  </div>
                  <div className="flex-1">
                    <h3 className="font-semibold text-sm">{policy.name}</h3>
                    <p className="text-xs text-text-muted mt-0.5">{policy.description}</p>
                  </div>
                  <Badge variant="decision" decision={policy.action} size="sm">
                    {policy.action}
                  </Badge>
                </div>

                <div className="bg-bg-elevated rounded-md p-3 mb-3">
                  <div className="text-[10px] text-text-muted mb-1">CONDITION</div>
                  <code className="text-xs font-mono text-text-secondary">{policy.condition}</code>
                </div>

                <div className="flex items-center justify-between">
                  <div className="flex gap-1 flex-wrap">
                    {policy.target_tools.map((tool) => (
                      <span key={tool} className="text-[10px] font-mono bg-bg-elevated border border-border rounded px-1.5 py-0.5">
                        {tool}
                      </span>
                    ))}
                  </div>
                  <div className={`w-2 h-2 rounded-full ${policy.enabled ? 'bg-allow' : 'bg-text-muted'}`} />
                </div>
              </Card>
            )
          })}
        </div>
      </PageState>
    </div>
  )
}
