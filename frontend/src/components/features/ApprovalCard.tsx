import type { ApprovalRecord } from '../../types'
import { Card } from '../ui/Card'
import { Button } from '../ui/Button'
import { Badge } from '../ui/Badge'
import { formatMoney, formatTime } from '../../lib/utils'
import { ShoppingCart, Mail, Clock } from 'lucide-react'

interface ApprovalCardProps {
  record: ApprovalRecord
  onApprove: (id: string) => void
  onReject: (id: string) => void
  loading?: boolean
}

function toolIcon(tool: string) {
  if (tool.includes('purchase')) return ShoppingCart
  if (tool.includes('email')) return Mail
  return ShoppingCart
}

export function ApprovalCard({ record, onApprove, onReject, loading }: ApprovalCardProps) {
  const Icon = toolIcon(record.tool_name)
  const amount = record.arguments.unit_price && record.arguments.quantity
    ? (record.arguments.unit_price as number) * (record.arguments.quantity as number)
    : undefined

  return (
    <Card className="border-escalate/20">
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-escalate-dim flex items-center justify-center">
            <Icon className="w-5 h-5 text-escalate" />
          </div>
          <div>
            <div className="font-mono text-sm font-semibold">{record.tool_name}</div>
            <div className="text-xs text-text-muted">{String(record.arguments.supplier_id || 'N/A')}</div>
          </div>
        </div>
        <Badge variant="risk" risk={record.risk_level}>
          {record.risk_score}
        </Badge>
      </div>

      {amount && (
        <div className="text-2xl font-mono font-bold text-text mb-2">
          {formatMoney(amount)}
        </div>
      )}

      <div className="text-sm text-text-secondary mb-3">
        {record.reasons[0] || 'Requires human approval'}
      </div>

      <div className="flex items-center gap-2 text-xs text-text-muted mb-4">
        <Clock className="w-3 h-3" />
        {formatTime(record.created_at)}
      </div>

      <div className="flex gap-2">
        <Button
          variant="success"
          size="sm"
          onClick={() => onApprove(record.approval_id)}
          disabled={loading}
          className="flex-1"
        >
          Approve
        </Button>
        <Button
          variant="danger"
          size="sm"
          onClick={() => onReject(record.approval_id)}
          disabled={loading}
          className="flex-1"
        >
          Reject
        </Button>
      </div>
    </Card>
  )
}
