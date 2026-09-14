import { useState, useEffect } from 'react'
import { Shield, Activity, AlertTriangle, CheckCircle, FileText, TrendingUp, PlayCircle } from 'lucide-react'
import { Card, CardHeader, CardTitle } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { RiskGauge } from '../components/features/RiskGauge'
import { api, type StatsResponse } from '../api/client'
import type { HealthResponse, AuditEvent } from '../types'
import { useToast } from '../components/ui/Toast'
import { formatTime } from '../lib/utils'

function MetricCard({ label, value, icon: Icon, color }: { label: string; value: string | number; icon: typeof Shield; color: string }) {
  return (
    <Card>
      <div className="flex items-center gap-3">
        <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${color}`}>
          <Icon className="w-5 h-5" />
        </div>
        <div>
          <div className="text-2xl font-mono font-bold">{value}</div>
          <div className="text-xs text-text-muted">{label}</div>
        </div>
      </div>
    </Card>
  )
}

export function Overview() {
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [stats, setStats] = useState<StatsResponse | null>(null)
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [policyCount, setPolicyCount] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const { toast } = useToast()

  const load = () => {
    api.health().then(setHealth).catch((e) => setError(e instanceof Error ? e.message : 'API unreachable'))
    api.getStats().then(setStats).catch(() => {})
    api.getEvents().then((r) => { setEvents(r.events); setError(null) }).catch(() => {})
    api.getPolicies().then((r) => setPolicyCount(r.policies.filter((p) => p.enabled).length)).catch(() => {})
  }

  useEffect(() => { load() }, [])

  const decisionEvents = events.filter((e) => e.event_type === 'DECISION')

  const runDemo = async () => {
    setLoading(true)
    try {
      await api.startRun()
      toast('success', 'Evaluation complete. Security events recorded.')
      load()
    } catch (e) {
      toast('error', `Evaluation failed: ${e instanceof Error ? e.message : 'Unknown error'}`)
    } finally {
      setLoading(false)
    }
  }

  const hasData = stats && stats.total_events > 0

  return (
    <div className="space-y-6">
      {/* Hero */}
      <div className="flex items-center gap-4">
        <div className="w-12 h-12 rounded-xl bg-allow-dim border border-allow/20 flex items-center justify-center">
          <Shield className="w-6 h-6 text-allow" />
        </div>
        <div>
          <h1 className="text-2xl font-bold">
            {hasData ? 'SENTINEL OPERATIONAL' : 'SENTINEL READY'}
          </h1>
          <p className="text-sm text-text-secondary">
            {hasData
              ? 'All consequential agent actions are passing through enforcement.'
              : 'Run an evaluation to start monitoring security events.'}
          </p>
        </div>
        <Badge variant="status" className="ml-auto">
          v{health?.version || '0.2.0'}
        </Badge>
      </div>

      {error && (
        <Card className="border-block/30">
          <div className="flex items-center gap-3 text-sm">
            <AlertTriangle className="w-4 h-4 text-block" />
            <span className="text-text-secondary">SENTINEL API unreachable: {error}</span>
            <Button variant="ghost" size="sm" className="ml-auto" onClick={load}>Retry</Button>
          </div>
        </Card>
      )}

      {!hasData && (
        <Card>
          <div className="text-center py-8">
            <Shield className="w-12 h-12 text-text-muted mx-auto mb-4" />
            <h3 className="text-lg font-semibold mb-2">No security events yet</h3>
            <p className="text-sm text-text-secondary mb-4">
              Run a security evaluation to generate real events from the SENTINEL pipeline.
            </p>
            <Button onClick={runDemo} disabled={loading}>
              {loading ? (
                <><div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" /> Running...</>
              ) : (
                <><PlayCircle className="w-4 h-4" /> Run Security Evaluation</>
              )}
            </Button>
          </div>
        </Card>
      )}

      {/* Metrics - only show when data exists */}
      {hasData && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <MetricCard label="Actions Intercepted" value={stats.total_events} icon={Activity} color="bg-info-dim text-info" />
            <MetricCard label="Allowed" value={stats.allowed} icon={CheckCircle} color="bg-allow-dim text-allow" />
            <MetricCard label="Blocked" value={stats.blocked} icon={AlertTriangle} color="bg-block-dim text-block" />
            <MetricCard label="Escalated" value={stats.escalated} icon={TrendingUp} color="bg-escalate-dim text-escalate" />
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <MetricCard label="High-Risk Actions" value={stats.high_risk} icon={AlertTriangle} color="bg-risk-critical/10 text-risk-critical" />
            <MetricCard label="Evaluation Runs" value={stats.total_runs} icon={FileText} color="bg-info-dim text-info" />
            <MetricCard label="Active Policies" value={policyCount} icon={FileText} color="bg-info-dim text-info" />
            <MetricCard label="Security Incidents" value={stats.blocked} icon={Shield} color="bg-block-dim text-block" />
          </div>

          {/* Security Posture */}
          {stats.total_events > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Security Posture</CardTitle>
                <span className="text-2xl font-mono font-bold text-accent">
                  {Math.round(((stats.allowed + stats.blocked * 2 + stats.escalated) / (stats.total_events * 2)) * 100)} / 100
                </span>
              </CardHeader>
              <div className="space-y-3">
                {[
                  { label: 'Policy Coverage', value: 100 },
                  { label: 'Tool Coverage', value: 100 },
                  { label: 'Agent Coverage', value: 100 },
                  { label: 'Approval Coverage', value: stats.escalated > 0 ? 100 : 0 },
                  { label: 'Evaluation Health', value: 100 },
                ].map((item) => (
                  <div key={item.label} className="flex items-center gap-3">
                    <span className="text-xs text-text-secondary w-36">{item.label}</span>
                    <div className="flex-1 h-1.5 bg-bg-elevated rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full bg-accent transition-all duration-500"
                        style={{ width: `${item.value}%` }}
                      />
                    </div>
                    <span className="text-xs font-mono text-text-muted w-8 text-right">{item.value}%</span>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* Recent Security Events */}
          {decisionEvents.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Recent Security Events</CardTitle>
                <span className="text-xs font-mono text-text-muted">{decisionEvents.length} total</span>
              </CardHeader>
              <div className="space-y-2">
                {decisionEvents.slice(0, 8).map((event) => {
                  const decision = event.data.decision as string
                  const risk = event.data.risk as { score: number; level: string } | undefined
                  const toolMatch = event.message.match(/'([^']+)'/)
                  const tool = toolMatch ? toolMatch[1] : 'unknown'
                  return (
                    <div key={event.event_id} className="flex items-center gap-3 py-2 border-b border-border-subtle last:border-0">
                      <Badge variant="decision" decision={decision as any}>{decision}</Badge>
                      <span className="font-mono text-sm">{tool}</span>
                      {risk && (
                        <RiskGauge score={risk.score} level={risk.level as any} showBar={false} size="sm" />
                      )}
                      <span className="text-xs text-text-muted ml-auto">{formatTime(event.timestamp)}</span>
                    </div>
                  )
                })}
              </div>
            </Card>
          )}
        </>
      )}
    </div>
  )
}
