import { cn } from '../../lib/utils'
import type { Decision } from '../../types'
import { CheckCircle, XCircle, AlertTriangle } from 'lucide-react'

interface DecisionBadgeProps {
  decision: Decision
  size?: 'sm' | 'md' | 'lg'
  showLabel?: boolean
}

const config = {
  ALLOW: { icon: CheckCircle, color: 'text-allow', bg: 'bg-allow-dim', border: 'border-allow/30', label: 'ALLOWED' },
  BLOCK: { icon: XCircle, color: 'text-block', bg: 'bg-block-dim', border: 'border-block/30', label: 'BLOCKED' },
  ESCALATE: { icon: AlertTriangle, color: 'text-escalate', bg: 'bg-escalate-dim', border: 'border-escalate/30', label: 'ESCALATED' },
}

export function DecisionBadge({ decision, size = 'md', showLabel = true }: DecisionBadgeProps) {
  const c = config[decision]
  const Icon = c.icon
  return (
    <span className={cn('inline-flex items-center gap-1.5 font-mono font-semibold border rounded-md', c.color, c.bg, c.border, {
      'text-xs px-1.5 py-0.5': size === 'sm',
      'text-sm px-2 py-1': size === 'md',
      'text-base px-3 py-1.5': size === 'lg',
    })}>
      <Icon className={cn({ 'w-3 h-3': size === 'sm', 'w-4 h-4': size === 'md', 'w-5 h-5': size === 'lg' })} />
      {showLabel && c.label}
    </span>
  )
}
