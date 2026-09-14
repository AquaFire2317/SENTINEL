import { cn } from '../../lib/utils'
import type { RiskLevel } from '../../types'

interface RiskGaugeProps {
  score: number
  level: RiskLevel
  showBar?: boolean
  size?: 'sm' | 'md' | 'lg'
}

const levelColors: Record<RiskLevel, string> = {
  LOW: 'text-risk-low',
  MEDIUM: 'text-risk-medium',
  HIGH: 'text-risk-high',
  CRITICAL: 'text-risk-critical',
}

const barColors: Record<RiskLevel, string> = {
  LOW: 'bg-risk-low',
  MEDIUM: 'bg-risk-medium',
  HIGH: 'bg-risk-high',
  CRITICAL: 'bg-risk-critical',
}

export function RiskGauge({ score, level, showBar = true, size = 'md' }: RiskGaugeProps) {
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-baseline gap-2">
        <span className={cn('font-mono font-bold', levelColors[level], {
          'text-lg': size === 'sm',
          'text-2xl': size === 'md',
          'text-3xl': size === 'lg',
        })}>
          {score}
        </span>
        <span className={cn('font-mono text-xs uppercase', levelColors[level])}>{level}</span>
      </div>
      {showBar && (
        <div className="h-1.5 bg-bg-elevated rounded-full overflow-hidden w-full">
          <div
            className={cn('h-full rounded-full transition-all duration-700', barColors[level])}
            style={{ width: `${Math.min(score, 100)}%` }}
          />
        </div>
      )}
    </div>
  )
}
