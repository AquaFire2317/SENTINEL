import { cn } from '../../lib/utils'
import type { Decision, RiskLevel } from '../../types'

interface BadgeProps {
  children: React.ReactNode
  variant?: 'default' | 'decision' | 'risk' | 'status'
  decision?: Decision
  risk?: RiskLevel
  size?: 'sm' | 'md'
  className?: string
}

export function Badge({ children, variant = 'default', decision, risk, size = 'md', className }: BadgeProps) {
  let classes = cn(
    'inline-flex items-center gap-1 font-mono font-medium rounded-md border',
    size === 'sm' ? 'text-[10px] px-1.5 py-0.5' : 'text-xs px-2 py-0.5',
    className
  )

  if (variant === 'decision' && decision) {
    classes = cn(classes, {
      'bg-allow-dim text-allow border-allow/30': decision === 'ALLOW',
      'bg-block-dim text-block border-block/30': decision === 'BLOCK',
      'bg-escalate-dim text-escalate border-escalate/30': decision === 'ESCALATE',
    })
  } else if (variant === 'risk' && risk) {
    classes = cn(classes, {
      'bg-risk-low/10 text-risk-low border-risk-low/30': risk === 'LOW',
      'bg-risk-medium/10 text-risk-medium border-risk-medium/30': risk === 'MEDIUM',
      'bg-risk-high/10 text-risk-high border-risk-high/30': risk === 'HIGH',
      'bg-risk-critical/10 text-risk-critical border-risk-critical/30': risk === 'CRITICAL',
    })
  } else {
    classes = cn(classes, 'bg-bg-elevated text-text-secondary border-border')
  }

  return <span className={classes}>{children}</span>
}
