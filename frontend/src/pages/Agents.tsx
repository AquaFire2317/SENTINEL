import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Bot, ShieldCheck, Plug } from 'lucide-react'
import { Card } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { Modal } from '../components/ui/Modal'
import { PageState } from '../components/ui/PageState'
import { api } from '../api/client'
import { useApi } from '../lib/useApi'
import type { AgentInfo } from '../types'

export function Agents() {
  const { data, error, loading, reload } = useApi(() => api.getAgents(), [])
  const [inspecting, setInspecting] = useState<AgentInfo | null>(null)
  const navigate = useNavigate()
  const agents = data?.agents ?? []

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Bot className="w-5 h-5 text-accent" />
        <h1 className="text-xl font-bold">Agents</h1>
        {agents.length > 0 && (
          <span className="text-xs font-mono text-text-muted bg-bg-elevated px-2 py-0.5 rounded">
            {agents.length} connected
          </span>
        )}
      </div>

      <PageState loading={loading} error={error} onRetry={reload}>
        {agents.length === 0 ? (
          <Card>
            <div className="text-center py-16">
              <Bot className="w-10 h-10 text-text-muted mx-auto mb-3" />
              <p className="text-text-secondary text-sm">No agents connected yet.</p>
              <p className="text-text-muted text-xs mt-1">
                Configure a model provider to connect a guarded agent.
              </p>
              <Button className="mt-4" onClick={() => navigate('/integrations')}>
                <Plug className="w-4 h-4" /> Configure Provider
              </Button>
            </div>
          </Card>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {agents.map((agent) => (
              <Card key={agent.id}>
                <div className="flex items-start gap-3 mb-4">
                  <div className="w-10 h-10 rounded-lg bg-accent-dim flex items-center justify-center">
                    <Bot className="w-5 h-5 text-accent" />
                  </div>
                  <div className="flex-1">
                    <h3 className="font-semibold text-sm">{agent.name}</h3>
                    <div className="flex items-center gap-1.5 mt-1">
                      <div className="w-2 h-2 rounded-full bg-allow" />
                      <span className="text-xs text-allow capitalize">{agent.status}</span>
                    </div>
                  </div>
                </div>

                <div className="space-y-2 text-xs mb-4">
                  <div className="flex justify-between">
                    <span className="text-text-muted">Provider</span>
                    <span className="text-text-secondary font-mono">{agent.provider}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-text-muted">Model</span>
                    <span className="text-text-secondary font-mono truncate max-w-[60%]" title={agent.model}>
                      {agent.model}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-text-muted">Risk</span>
                    <Badge variant="risk" risk={agent.risk_profile} size="sm">{agent.risk_profile}</Badge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-text-muted">Policy</span>
                    <span className="text-text-secondary">{agent.policy_set}</span>
                  </div>
                </div>

                <div className="mb-4">
                  <div className="text-xs text-text-muted mb-1.5">Tools</div>
                  <div className="flex flex-wrap gap-1">
                    {agent.tools.map((tool) => (
                      <span key={tool} className="text-[10px] font-mono bg-bg-elevated border border-border rounded px-1.5 py-0.5">
                        {tool}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="flex gap-2">
                  <Button variant="secondary" size="sm" className="flex-1" onClick={() => setInspecting(agent)}>
                    Inspect
                  </Button>
                  <Button variant="ghost" size="sm" onClick={() => navigate('/settings')}>
                    Configure
                  </Button>
                </div>
              </Card>
            ))}
          </div>
        )}
      </PageState>

      <Modal open={inspecting !== null} onClose={() => setInspecting(null)} title={inspecting?.name ?? 'Agent'}>
        {inspecting && (
          <div className="space-y-4 text-sm">
            <div className="flex items-center gap-2 text-allow">
              <ShieldCheck className="w-4 h-4" />
              <span className="font-medium">Protected by SENTINEL</span>
            </div>
            <div className="space-y-2">
              <Row label="Agent ID" value={inspecting.id} />
              <Row label="Status" value={inspecting.status} />
              <Row label="Provider" value={inspecting.provider} />
              <Row label="Model" value={inspecting.model} />
              <Row label="Policy set" value={inspecting.policy_set} />
              {inspecting.secured_by && <Row label="Enforcement" value={inspecting.secured_by} />}
            </div>
            <div>
              <div className="text-xs text-text-muted mb-1.5">Gated tools</div>
              <div className="flex flex-wrap gap-1">
                {inspecting.tools.map((tool) => (
                  <span key={tool} className="text-[10px] font-mono bg-bg-elevated border border-border rounded px-1.5 py-0.5">
                    {tool}
                  </span>
                ))}
              </div>
            </div>
          </div>
        )}
      </Modal>
    </div>
  )
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-4 py-1 border-b border-border-subtle last:border-0">
      <span className="text-text-muted text-xs">{label}</span>
      <span className="font-mono text-xs text-right break-all">{value}</span>
    </div>
  )
}
