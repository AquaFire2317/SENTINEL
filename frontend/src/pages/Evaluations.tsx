import { useState } from 'react'
import { ClipboardList, Play, Shield, Eye } from 'lucide-react'
import { Card, CardHeader, CardTitle } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { Modal } from '../components/ui/Modal'
import { PageState } from '../components/ui/PageState'
import { DecisionBadge } from '../components/features/DecisionBadge'
import { RiskGauge } from '../components/features/RiskGauge'
import { api } from '../api/client'
import { useApi } from '../lib/useApi'
import { useToast } from '../components/ui/Toast'
import type { RunResult } from '../types'

export function Evaluations() {
  const scenarios = useApi(() => api.getScenarios(), [])
  const runs = useApi(() => api.getRuns(), [])
  const regressions = useApi(() => api.getRegressions(), [])
  const stats = useApi(() => api.getStats(), [])
  const [selectedScenario, setSelectedScenario] = useState('')
  const [running, setRunning] = useState(false)
  const [detail, setDetail] = useState<RunResult | null>(null)
  const { toast } = useToast()

  const reloadAll = () => {
    runs.reload()
    regressions.reload()
    stats.reload()
  }

  const runEvaluation = async () => {
    setRunning(true)
    try {
      const result = await api.startRun(selectedScenario || undefined)
      toast('success', `Evaluation complete: security score ${result.report.security_score}`)
      reloadAll()
    } catch (e) {
      toast('error', `Evaluation failed: ${e instanceof Error ? e.message : 'Unknown error'}`)
    } finally {
      setRunning(false)
    }
  }

  const openRun = async (runId: string) => {
    try {
      setDetail(await api.getRun(runId))
    } catch (e) {
      toast('error', `Could not load run: ${e instanceof Error ? e.message : 'Unknown error'}`)
    }
  }

  const runList = runs.data?.runs ?? []
  const regressionCases = regressions.data?.cases ?? []
  const s = stats.data

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-3">
          <ClipboardList className="w-5 h-5 text-accent" />
          <h1 className="text-xl font-bold">Evaluations</h1>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={selectedScenario}
            onChange={(e) => setSelectedScenario(e.target.value)}
            className="h-9 px-3 bg-bg-elevated border border-border rounded-md text-sm text-text focus:outline-none focus:border-accent"
          >
            <option value="">Canonical attack</option>
            {(scenarios.data?.scenarios ?? []).map((sc) => (
              <option key={sc.scenario_id} value={sc.scenario_id}>{sc.name}</option>
            ))}
          </select>
          <Button onClick={runEvaluation} disabled={running}>
            {running ? (
              <><div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" /> Running...</>
            ) : (
              <><Play className="w-4 h-4" /> Run Evaluation</>
            )}
          </Button>
        </div>
      </div>

      {s && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Metric value={s.total_runs} label="Evaluations Run" color="text-accent" />
          <Metric value={s.allowed} label="Allowed" color="text-allow" />
          <Metric value={s.blocked} label="Blocked" color="text-block" />
          <Metric value={s.escalated} label="Escalated" color="text-escalate" />
        </div>
      )}

      <PageState loading={runs.loading} error={runs.error} onRetry={runs.reload}>
        <Card>
          <CardHeader>
            <CardTitle>Evaluation Runs</CardTitle>
            <span className="text-xs font-mono text-text-muted">{runList.length} recorded</span>
          </CardHeader>
          {runList.length === 0 ? (
            <p className="text-sm text-text-secondary">No evaluations run yet. Run one above.</p>
          ) : (
            <div className="space-y-2">
              {runList.map((run) => (
                <div key={run.run_id} className="flex items-center gap-3 py-2 border-b border-border-subtle last:border-0">
                  <DecisionBadge decision={run.decision} />
                  <span className="text-sm font-mono truncate">{run.scenario_id}</span>
                  <span className="text-xs text-text-muted hidden md:inline">{run.run_id}</span>
                  <span className="text-xs text-text-muted ml-auto">score {run.security_score}</span>
                  <Button variant="ghost" size="sm" onClick={() => openRun(run.run_id)}>
                    <Eye className="w-3 h-3" /> View
                  </Button>
                </div>
              ))}
            </div>
          )}
        </Card>
      </PageState>

      <Card>
        <CardHeader>
          <CardTitle>Regression Cases</CardTitle>
          <span className="text-xs font-mono text-text-muted">{regressionCases.length} recorded</span>
        </CardHeader>
        {regressionCases.length === 0 ? (
          <p className="text-sm text-text-secondary">No regression cases recorded yet.</p>
        ) : (
          <div className="space-y-2">
            {regressionCases.map((r) => (
              <div key={r.scenario_id} className="flex items-center gap-3 py-2 border-b border-border-subtle last:border-0">
                <Shield className="w-4 h-4 text-allow shrink-0" />
                <span className="text-sm font-mono">{r.scenario_id}</span>
                <span className="text-xs text-text-muted ml-auto">{r.name}</span>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Modal open={detail !== null} onClose={() => setDetail(null)} title="Evaluation Report" className="max-w-2xl">
        {detail && (
          <div className="space-y-4">
            <div className="flex items-center gap-4 flex-wrap">
              <DecisionBadge decision={detail.report.decision} />
              <RiskGauge score={detail.report.risk_score} level={detail.report.risk_level} showBar={false} />
              <Badge variant="status" size="sm">security score {detail.report.security_score}</Badge>
              <Badge variant="status" size="sm">retest {detail.report.retest.status}</Badge>
            </div>
            <div className="text-xs font-mono text-text-muted break-all">{detail.run_id}</div>
            <p className="text-sm text-text-secondary">{detail.report.explanation}</p>
            <div>
              <div className="text-xs text-text-muted mb-1.5">Mitigation rules applied</div>
              <ul className="space-y-1">
                {detail.report.mitigation.rules.map((rule) => (
                  <li key={rule} className="text-xs text-text-secondary flex gap-2">
                    <Shield className="w-3 h-3 text-allow mt-0.5 shrink-0" /> {rule}
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <div className="text-xs text-text-muted mb-1.5">Audit trail ({detail.report.audit.length} events)</div>
              <div className="max-h-56 overflow-y-auto space-y-1">
                {detail.report.audit.map((event) => (
                  <div key={event.event_id} className="text-[11px] font-mono text-text-muted flex gap-2">
                    <span className="text-text-secondary shrink-0">{event.event_type}</span>
                    <span className="truncate">{event.message}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </Modal>
    </div>
  )
}

function Metric({ value, label, color }: { value: number; label: string; color: string }) {
  return (
    <Card>
      <div className="text-center">
        <div className={`text-3xl font-mono font-bold mb-1 ${color}`}>{value}</div>
        <div className="text-xs text-text-muted">{label}</div>
      </div>
    </Card>
  )
}
