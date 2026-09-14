import { useState, useEffect, useCallback } from 'react'
import { FileText, Search, RefreshCw, Download, PlayCircle, AlertTriangle } from 'lucide-react'
import { Card } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { RiskGauge } from '../components/features/RiskGauge'
import { Modal } from '../components/ui/Modal'
import { formatTime } from '../lib/utils'
import { api } from '../api/client'
import { useToast } from '../components/ui/Toast'
import type { AuditEvent } from '../types'

export function AuditLog() {
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [filterDecision, setFilterDecision] = useState<string>('all')
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null)
  const { toast } = useToast()

  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      const data = await api.getEvents()
      setEvents(data.events)
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unknown error')
    }
    setLoading(false)
  }, [])

  useEffect(() => { refresh() }, [refresh])

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

  const filtered = events.filter((e) => {
    const decision = (e.data?.decision as string) || ''
    const toolMatch = e.message.match(/'([^']+)'/)
    const tool = toolMatch ? toolMatch[1] : ''

    const matchesSearch = !search ||
      e.message.toLowerCase().includes(search.toLowerCase()) ||
      tool.toLowerCase().includes(search.toLowerCase()) ||
      e.event_type.toLowerCase().includes(search.toLowerCase())
    const matchesDecision = filterDecision === 'all' || decision === filterDecision
    return matchesSearch && matchesDecision
  })

  const exportCsv = () => {
    const headers = ['Event ID', 'Type', 'Decision', 'Risk Score', 'Risk Level', 'Message', 'Run ID', 'Timestamp']
    const rows = filtered.map((e) => {
      const decision = (e.data?.decision as string) || ''
      const risk = e.data?.risk as { score: number; level: string } | undefined
      return [
        e.event_id, e.event_type, decision,
        risk ? String(risk.score) : '',
        risk ? risk.level : '',
        `"${e.message.replace(/"/g, '""')}"`,
        e.run_id, e.timestamp,
      ]
    })
    const csv = [headers, ...rows].map((r) => r.join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'sentinel-audit.csv'
    a.click()
    URL.revokeObjectURL(url)
  }

  const hasData = events.length > 0

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <FileText className="w-5 h-5 text-accent" />
          <h1 className="text-xl font-bold">Audit Log</h1>
          {hasData && (
            <span className="text-xs font-mono text-text-muted bg-bg-elevated px-2 py-0.5 rounded">
              {filtered.length} events
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {hasData && (
            <Button variant="ghost" size="sm" onClick={exportCsv}>
              <Download className="w-4 h-4" />
              Export
            </Button>
          )}
          <Button variant="ghost" size="sm" onClick={refresh} disabled={loading}>
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </Button>
        </div>
      </div>

      {error && (
        <Card className="border-block/30">
          <div className="flex items-center gap-3 text-sm">
            <AlertTriangle className="w-4 h-4 text-block" />
            <span className="text-text-secondary">{error}</span>
            <Button variant="ghost" size="sm" className="ml-auto" onClick={refresh}>Retry</Button>
          </div>
        </Card>
      )}

      {!hasData && !error && (
        <Card>
          <div className="text-center py-16">
            <FileText className="w-10 h-10 text-text-muted mx-auto mb-3" />
            <p className="text-text-secondary text-sm mb-4">No audit events found.</p>
            <Button onClick={runDemo} disabled={loading} size="sm">
              {loading ? 'Running...' : <><PlayCircle className="w-4 h-4" /> Run Evaluation</>}
            </Button>
          </div>
        </Card>
      )}

      {hasData && (
        <>
          {/* Filters */}
          <div className="flex items-center gap-3">
            <div className="relative flex-1 max-w-sm">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search events..."
                className="w-full h-9 pl-9 pr-3 bg-bg-card border border-border rounded-md text-sm text-text focus:outline-none focus:border-accent placeholder:text-text-muted"
              />
            </div>
            <select
              value={filterDecision}
              onChange={(e) => setFilterDecision(e.target.value)}
              className="h-9 px-3 bg-bg-card border border-border rounded-md text-sm text-text focus:outline-none focus:border-accent"
            >
              <option value="all">All decisions</option>
              <option value="ALLOW">ALLOW</option>
              <option value="BLOCK">BLOCK</option>
              <option value="ESCALATE">ESCALATE</option>
            </select>
          </div>

          {/* Table */}
          <div className="border border-border rounded-lg overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-bg-elevated border-b border-border">
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-text-muted">Event Type</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-text-muted">Decision</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-text-muted">Risk</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-text-muted">Message</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-text-muted">Time</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((event) => {
                  const decision = (event.data?.decision as string) || null
                  const risk = event.data?.risk as { score: number; level: string } | undefined
                  return (
                    <tr
                      key={event.event_id}
                      onClick={() => setSelectedEvent(event)}
                      className="border-b border-border-subtle hover:bg-bg-elevated cursor-pointer transition-colors"
                    >
                      <td className="px-4 py-3 font-mono text-xs">{event.event_type}</td>
                      <td className="px-4 py-3">
                        {decision ? (
                          <Badge variant="decision" decision={decision as any}>{decision}</Badge>
                        ) : (
                          <span className="text-xs text-text-muted">-</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        {risk ? (
                          <RiskGauge score={risk.score} level={risk.level as any} showBar={false} size="sm" />
                        ) : (
                          <span className="text-xs text-text-muted">-</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-xs text-text-secondary max-w-[300px] truncate">{event.message}</td>
                      <td className="px-4 py-3 text-xs text-text-muted">{formatTime(event.timestamp)}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* Detail Modal */}
      <Modal open={!!selectedEvent} onClose={() => setSelectedEvent(null)} title="Event Details">
        {selectedEvent && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <div className="text-xs text-text-muted mb-1">Event Type</div>
                <div className="font-mono text-sm">{selectedEvent.event_type}</div>
              </div>
              <div>
                <div className="text-xs text-text-muted mb-1">Run ID</div>
                <div className="font-mono text-xs">{selectedEvent.run_id}</div>
              </div>
            </div>
            <div>
              <div className="text-xs text-text-muted mb-1">Message</div>
              <div className="text-sm text-text-secondary">{selectedEvent.message}</div>
            </div>
            <div>
              <div className="text-xs text-text-muted mb-1">Full Data</div>
              <pre className="text-xs font-mono bg-bg-elevated border border-border rounded p-2 overflow-x-auto max-h-60">
                {JSON.stringify(selectedEvent.data, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </Modal>
    </div>
  )
}
