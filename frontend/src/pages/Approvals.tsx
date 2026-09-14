import { useState, useEffect, useCallback } from 'react'
import { CheckSquare, RefreshCw, RotateCcw } from 'lucide-react'
import { Card } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { PageState } from '../components/ui/PageState'
import { ApprovalCard } from '../components/features/ApprovalCard'
import { api } from '../api/client'
import { useToast } from '../components/ui/Toast'
import type { ApprovalRecord } from '../types'

export function Approvals() {
  const [pending, setPending] = useState<ApprovalRecord[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [actionId, setActionId] = useState<string | null>(null)
  const { toast } = useToast()

  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      const data = await api.getApprovals()
      setPending(data.pending)
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unknown error')
    }
    setLoading(false)
  }, [])

  useEffect(() => { refresh() }, [refresh])

  const handleReset = async () => {
    setLoading(true)
    try {
      await api.resetAgent()
      toast('success', 'Demo agent reset. Run it again to generate new approvals.')
      await refresh()
    } catch (e) {
      toast('error', `Reset failed: ${e instanceof Error ? e.message : 'Unknown error'}`)
    } finally {
      setLoading(false)
    }
  }

  const handleApprove = async (id: string) => {
    setActionId(id)
    try {
      await api.decideApproval(id, 'APPROVE')
      toast('success', 'Approval recorded. Permit issued.')
      refresh()
    } catch (e) {
      toast('error', `Approval failed: ${e instanceof Error ? e.message : 'Unknown error'}`)
    } finally {
      setActionId(null)
    }
  }

  const handleReject = async (id: string) => {
    setActionId(id)
    try {
      await api.decideApproval(id, 'REJECT')
      toast('info', 'Action rejected.')
      refresh()
    } catch (e) {
      toast('error', `Rejection failed: ${e instanceof Error ? e.message : 'Unknown error'}`)
    } finally {
      setActionId(null)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <CheckSquare className="w-5 h-5 text-escalate" />
          <h1 className="text-xl font-bold">Approval Queue</h1>
          <span className="text-xs font-mono text-text-muted bg-bg-elevated px-2 py-0.5 rounded">
            {pending.length} pending
          </span>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={handleReset} disabled={loading}>
            <RotateCcw className="w-4 h-4" /> Reset demo
          </Button>
          <Button variant="ghost" size="sm" onClick={refresh} disabled={loading}>
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </Button>
        </div>
      </div>

      <PageState loading={loading && pending.length === 0} error={error} onRetry={refresh}>
        {pending.length === 0 ? (
          <Card>
            <div className="text-center py-16">
              <CheckSquare className="w-10 h-10 text-text-muted mx-auto mb-3" />
              <p className="text-text-secondary text-sm">No pending approvals.</p>
              <p className="text-text-muted text-xs mt-1">
                When an agent action is escalated, it will appear here for human review.
              </p>
            </div>
          </Card>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {pending.map((record) => (
              <ApprovalCard
                key={record.approval_id}
                record={record}
                onApprove={handleApprove}
                onReject={handleReject}
                loading={actionId === record.approval_id}
              />
            ))}
          </div>
        )}
      </PageState>
    </div>
  )
}
