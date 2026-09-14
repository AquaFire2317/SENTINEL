import { useState, useEffect, useCallback } from 'react'
import { Activity, RefreshCw, PlayCircle, AlertTriangle } from 'lucide-react'
import { Card, CardHeader, CardTitle } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { RiskGauge } from '../components/features/RiskGauge'
import { formatTime } from '../lib/utils'
import { api } from '../api/client'
import { useToast } from '../components/ui/Toast'
import type { AuditEvent } from '../types'

function EventInspector({ event }: { event: AuditEvent }) {
  const decision = String(event.data?.decision || '')
  const risk = event.data?.risk as { score: number; level: string } | undefined

  return (
    <Card className="sticky top-6">
      <CardHeader>
        <CardTitle>Event Inspector</CardTitle>
      </CardHeader>
      <div className="space-y-4">
        <div>
          <div className="text-xs text-text-muted mb-1">Event Type</div>
          <div className="font-mono text-sm">{event.event_type}</div>
        </div>
        <div>
          <div className="text-xs text-text-muted mb-1">Message</div>
          <div className="text-sm text-text-secondary">{event.message}</div>
        </div>
        {decision && (
          <div>
            <div className="text-xs text-text-muted mb-1">Decision</div>
            <Badge variant="decision" decision={decision as any}>{decision}</Badge>
          </div>
        )}
        {risk && typeof risk === 'object' && 'score' in risk && (
          <div>
            <div className="text-xs text-text-muted mb-1">Risk</div>
            <RiskGauge score={risk.score} level={risk.level as any} />
          </div>
        )}
        <div>
          <div className="text-xs text-text-muted mb-1">Run ID</div>
          <div className="font-mono text-xs">{event.run_id}</div>
        </div>
        <div>
          <div className="text-xs text-text-muted mb-1">Full Data</div>
          <pre className="text-xs font-mono bg-bg-elevated border border-border rounded p-2 overflow-x-auto max-h-40">
            {JSON.stringify(event.data, null, 2)}
          </pre>
        </div>
      </div>
    </Card>
  )
}

export function LiveMonitor() {
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null)
  const { toast } = useToast()

  const refresh = useCallback(async (showSpinner = true) => {
    if (showSpinner) setLoading(true)
    try {
      const data = await api.getEvents()
      setEvents(data.events)
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unknown error')
    } finally {
      if (showSpinner) setLoading(false)
    }
  }, [])

  useEffect(() => {
    refresh()
    const interval = setInterval(() => refresh(false), 10000)
    return () => clearInterval(interval)
  }, [refresh])

  const runDemo = async () => {
    setLoading(true)
    try {
      await api.startRun()
      toast('success', 'Evaluation complete.')
      refresh()
    } catch (e) {
      toast('error', `Failed: ${e instanceof Error ? e.message : 'Unknown error'}`)
    } finally {
      setLoading(false)
    }
  }

  const hasData = events.length > 0

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Activity className="w-5 h-5 text-accent" />
          <h1 className="text-xl font-bold">Live Monitor</h1>
          {hasData && (
            <span className="text-xs font-mono text-text-muted bg-bg-elevated px-2 py-0.5 rounded">
              {events.length} events
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={() => refresh()} disabled={loading}>
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </Button>
        </div>
      </div>

      {error && (
        <Card className="border-block/30">
          <div className="flex items-center gap-3 text-sm">
            <AlertTriangle className="w-4 h-4 text-block" />
            <span className="text-text-secondary">{error}</span>
            <Button variant="ghost" size="sm" className="ml-auto" onClick={() => refresh()}>Retry</Button>
          </div>
        </Card>
      )}

      {!hasData && (
        <Card>
          <div className="text-center py-12">
            <Activity className="w-8 h-8 text-text-muted mx-auto mb-3" />
            <p className="text-text-secondary text-sm mb-4">No security events yet.</p>
            <Button onClick={runDemo} disabled={loading} size="sm">
              {loading ? 'Running...' : <><PlayCircle className="w-4 h-4" /> Run Evaluation</>}
            </Button>
          </div>
        </Card>
      )}

      {hasData && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Event Stream */}
          <div className="lg:col-span-2 space-y-2">
            {events.map((event) => {
              const decision = event.data?.decision as string | undefined
              const risk = event.data?.risk as { score: number; level: string } | undefined
              const toolMatch = event.message.match(/'([^']+)'/)
              const tool = toolMatch ? toolMatch[1] : event.message
              const isSelected = selectedEvent?.event_id === event.event_id

              return (
                <div
                  key={event.event_id}
                  onClick={() => setSelectedEvent(event)}
                  className={`flex items-center gap-4 p-4 rounded-lg border transition-colors cursor-pointer ${
                    isSelected
                      ? 'bg-bg-elevated border-accent/30'
                      : 'bg-bg-card border-border hover:border-border-subtle hover:bg-bg-elevated'
                  }`}
                >
                  {decision && (
                    <Badge variant="decision" decision={decision as any}>{decision}</Badge>
                  )}
                  <div className="flex-1 min-w-0">
                    <div className="font-mono text-sm font-medium truncate">{tool}</div>
                    <div className="text-xs text-text-muted truncate">{String(event.event_type)}</div>
                  </div>
                  {risk && (
                    <RiskGauge score={risk.score} level={risk.level as any} showBar={false} size="sm" />
                  )}
                  <div className="text-xs text-text-muted shrink-0">
                    {formatTime(event.timestamp)}
                  </div>
                </div>
              )
            })}
          </div>

          {/* Detail Panel */}
          <div className="lg:col-span-1">
            {selectedEvent ? (
              <EventInspector event={selectedEvent} />
            ) : (
              <Card className="sticky top-6">
                <div className="text-center py-12">
                  <Activity className="w-8 h-8 text-text-muted mx-auto mb-3" />
                  <p className="text-text-secondary text-sm">Select an event to inspect</p>
                </div>
              </Card>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
