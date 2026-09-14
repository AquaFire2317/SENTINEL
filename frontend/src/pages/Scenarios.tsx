import { useState } from 'react'
import { Beaker, Play, Shield, AlertTriangle } from 'lucide-react'
import { Card, CardHeader, CardTitle } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { PageState } from '../components/ui/PageState'
import { SecurityPipeline } from '../components/features/SecurityPipeline'
import { DecisionBadge } from '../components/features/DecisionBadge'
import { RiskGauge } from '../components/features/RiskGauge'
import { api } from '../api/client'
import { useApi } from '../lib/useApi'
import { useToast } from '../components/ui/Toast'
import type { RunResult, Scenario } from '../types'

export function Scenarios() {
  const { data, error, loading, reload } = useApi(() => api.getScenarios(), [])
  const [running, setRunning] = useState<string | null>(null)
  const [result, setResult] = useState<RunResult | null>(null)
  const [step, setStep] = useState(-1)
  const { toast } = useToast()
  const scenarios: Scenario[] = data?.scenarios ?? []

  const runScenario = async (scenarioId: string) => {
    setRunning(scenarioId)
    setResult(null)
    setStep(0)
    try {
      const res = await api.startRun(scenarioId)
      setResult(res)
      toast('success', `Scenario complete: ${res.report.decision}`)
      for (let i = 0; i <= 7; i++) {
        setStep(i)
        await new Promise((r) => setTimeout(r, 220))
      }
    } catch (e) {
      setStep(-1)
      toast('error', `Scenario failed: ${e instanceof Error ? e.message : 'Unknown error'}`)
    } finally {
      setRunning(null)
    }
  }

  const active = scenarios.find((s) => s.scenario_id === running)
  const report = result?.report

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Beaker className="w-5 h-5 text-accent" />
        <h1 className="text-xl font-bold">Scenario Lab</h1>
      </div>
      <p className="text-sm text-text-secondary">
        Test SENTINEL against realistic agent attacks. Run scenarios to see the security pipeline in action.
      </p>

      <PageState loading={loading} error={error} onRetry={reload}>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {scenarios.map((s) => {
            const isRunning = running === s.scenario_id
            return (
              <Card key={s.scenario_id} hover className="relative">
                <div className="flex items-start gap-3 mb-3">
                  <div className="w-10 h-10 rounded-lg bg-block-dim flex items-center justify-center">
                    <AlertTriangle className="w-5 h-5 text-block" />
                  </div>
                  <div className="flex-1">
                    <h3 className="font-semibold text-sm">{s.name}</h3>
                    <p className="text-xs text-text-muted">{s.attack_type}</p>
                  </div>
                </div>
                <p className="text-xs text-text-secondary mb-4">{s.description}</p>
                <div className="flex items-center justify-between gap-2">
                  <Badge variant="status" className="text-[10px] truncate">
                    {s.expected_result || 'Expected: BLOCK'}
                  </Badge>
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => runScenario(s.scenario_id)}
                    disabled={running !== null}
                  >
                    {isRunning ? (
                      <><div className="w-3 h-3 border-2 border-accent border-t-transparent rounded-full animate-spin" /> Running...</>
                    ) : (
                      <><Play className="w-3 h-3" /> Run</>
                    )}
                  </Button>
                </div>
              </Card>
            )
          })}
        </div>
      </PageState>

      {active && (
        <Card>
          <CardHeader>
            <CardTitle>Attack Replay: {active.name}</CardTitle>
          </CardHeader>
          <SecurityPipeline currentStep={step} decision={report?.decision} />
          <div className="mt-4 text-center">
            <p className="text-sm text-text-secondary">
              {!report && 'Running scenario through the security pipeline...'}
              {report && step < 7 && 'Tracing enforcement path...'}
              {report && step >= 7 && (report.attack_detected
                ? 'Attack observed and contained. No unauthorized side effect occurred.'
                : 'Scenario completed. No attack was observed.')}
            </p>
          </div>
        </Card>
      )}

      {report && (
        <Card className={report.attack_detected ? 'border-allow/20' : 'border-border'}>
          <div className="text-center py-6">
            <Shield className={`w-12 h-12 mx-auto mb-4 ${report.attack_detected ? 'text-allow' : 'text-info'}`} />
            {report.attack_detected ? (
              <>
                <h2 className="text-2xl font-bold mb-2">THE AGENT WAS COMPROMISED.</h2>
                <h2 className="text-2xl font-bold text-allow mb-4">SENTINEL WAS NOT.</h2>
              </>
            ) : (
              <h2 className="text-2xl font-bold mb-4">NO ATTACK OBSERVED</h2>
            )}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 max-w-2xl mx-auto mt-6">
              <div>
                <div className="text-xs text-text-muted mb-1">Decision</div>
                <DecisionBadge decision={report.decision} />
              </div>
              <div>
                <div className="text-xs text-text-muted mb-1">Risk</div>
                <RiskGauge score={report.risk_score} level={report.risk_level} showBar={false} />
              </div>
              <div>
                <div className="text-xs text-text-muted mb-1">Attack Detected</div>
                {report.attack_detected ? (
                  <Badge variant="decision" decision="BLOCK" size="sm">YES</Badge>
                ) : (
                  <Badge variant="status" size="sm">NO</Badge>
                )}
              </div>
              <div>
                <div className="text-xs text-text-muted mb-1">Side Effect</div>
                {report.attack_detected ? (
                  <Badge variant="decision" decision="BLOCK" size="sm">PREVENTED</Badge>
                ) : (
                  <Badge variant="status" size="sm">NONE</Badge>
                )}
              </div>
            </div>
            {report.explanation && (
              <p className="text-sm text-text-secondary mt-6 max-w-lg mx-auto">{report.explanation}</p>
            )}
          </div>
        </Card>
      )}
    </div>
  )
}
