import { Wrench, Shield } from 'lucide-react'
import { Badge } from '../components/ui/Badge'
import { PageState } from '../components/ui/PageState'
import { api } from '../api/client'
import { useApi } from '../lib/useApi'

const riskColors: Record<string, string> = {
  LOW: 'bg-risk-low/10 text-risk-low',
  MEDIUM: 'bg-risk-medium/10 text-risk-medium',
  HIGH: 'bg-risk-high/10 text-risk-high',
  CRITICAL: 'bg-risk-critical/10 text-risk-critical',
}

export function Tools() {
  const { data, error, loading, reload } = useApi(() => api.getTools(), [])
  const tools = data?.tools ?? []

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Wrench className="w-5 h-5 text-accent" />
        <h1 className="text-xl font-bold">Tools</h1>
        <span className="text-xs font-mono text-text-muted bg-bg-elevated px-2 py-0.5 rounded">
          {tools.length} registered
        </span>
      </div>

      <PageState loading={loading} error={error} onRetry={reload}>
        <div className="border border-border rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-bg-elevated border-b border-border">
                <th className="text-left px-4 py-2.5 text-xs font-medium text-text-muted">Tool</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-text-muted">Category</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-text-muted">Risk</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-text-muted">Approval</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-text-muted">Policy</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-text-muted">Status</th>
                <th className="text-right px-4 py-2.5 text-xs font-medium text-text-muted">Calls</th>
              </tr>
            </thead>
            <tbody>
              {tools.map((tool) => (
                <tr key={tool.name} className="border-b border-border-subtle hover:bg-bg-elevated transition-colors">
                  <td className="px-4 py-3 font-mono text-xs font-medium">{tool.name}</td>
                  <td className="px-4 py-3 text-xs text-text-secondary">{tool.category}</td>
                  <td className="px-4 py-3">
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${riskColors[tool.risk] ?? ''}`}>
                      {tool.risk}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    {tool.requires_approval ? (
                      <Badge variant="decision" decision="ESCALATE" size="sm">Required</Badge>
                    ) : (
                      <span className="text-xs text-text-muted">No</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-xs text-text-secondary">{tool.policy}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5">
                      <Shield className="w-3 h-3 text-allow" />
                      <span className="text-xs text-allow">Protected</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-right font-mono text-xs text-text-muted">{tool.calls_today}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </PageState>
    </div>
  )
}
