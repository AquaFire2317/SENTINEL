import { cn } from '../../lib/utils'
import type { Decision } from '../../types'
import { Bot, Shield, Gauge, FileText, Stamp, Wrench, Zap, Ban } from 'lucide-react'

interface SecurityPipelineProps {
  currentStep: number
  decision?: Decision
  steps?: string[]
}

const defaultSteps = ['AGENT', 'SENTINEL', 'RISK', 'POLICY', 'DECISION', 'PERMIT', 'TOOL', 'SIDE EFFECT']
const stepIcons = [Bot, Shield, Gauge, FileText, Stamp, Wrench, Zap, Ban]

export function SecurityPipeline({ currentStep, decision, steps }: SecurityPipelineProps) {
  const labels = steps && steps.length ? steps : defaultSteps
  return (
    <div className="flex items-center gap-1 overflow-x-auto py-3">
      {labels.map((label, i) => {
        const Icon = stepIcons[i] || Zap
        const active = i <= currentStep
        const isCurrent = i === currentStep
        const isDecision = label === 'DECISION'

        return (
          <div key={label} className="flex items-center">
            <div className={cn(
              'flex flex-col items-center gap-1 px-2 py-1.5 rounded-md transition-all duration-300 min-w-[60px]',
              isCurrent && 'bg-accent-dim border border-accent/30',
              active && !isCurrent && 'opacity-100',
              !active && 'opacity-30',
            )}>
              <Icon className={cn('w-4 h-4', active ? 'text-accent' : 'text-text-muted')} />
              <span className={cn('text-[10px] font-mono', active ? 'text-text' : 'text-text-muted')}>{label}</span>
              {isDecision && decision && (
                <span className={cn('text-[10px] font-mono font-bold', {
                  'text-allow': decision === 'ALLOW',
                  'text-block': decision === 'BLOCK',
                  'text-escalate': decision === 'ESCALATE',
                })}>
                  {decision}
                </span>
              )}
            </div>
            {i < labels.length - 1 && (
              <div className={cn('w-4 h-px mx-0.5', active ? 'bg-accent/40' : 'bg-border')} />
            )}
          </div>
        )
      })}
    </div>
  )
}
