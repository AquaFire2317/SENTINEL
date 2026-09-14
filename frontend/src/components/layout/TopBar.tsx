import { cn } from '../../lib/utils'
import { Bell, ChevronDown } from 'lucide-react'
import { useState } from 'react'
import { useToast } from '../ui/Toast'

type Environment = 'local' | 'demo' | 'production'

interface TopBarProps {
  environment?: Environment
  provider?: string
  model?: string
  connected?: boolean
  onEnvironmentChange?: (environment: Environment) => void
}

const ENVIRONMENTS: Environment[] = ['local', 'demo', 'production']

export function TopBar({
  environment = 'local',
  provider = 'Local',
  model = 'Deterministic',
  connected = true,
  onEnvironmentChange,
}: TopBarProps) {
  const [envOpen, setEnvOpen] = useState(false)
  const { toast } = useToast()

  const envColors: Record<Environment, string> = {
    local: 'text-accent bg-accent-dim',
    demo: 'text-escalate bg-escalate-dim',
    production: 'text-info bg-info-dim',
  }

  return (
    <header className="h-14 border-b border-border bg-bg-card flex items-center justify-between px-5 shrink-0">
      <div className="flex items-center gap-4">
        <div className="relative">
          <button
            onClick={() => setEnvOpen(!envOpen)}
            className={cn('flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono font-semibold', envColors[environment])}
          >
            {environment.toUpperCase()}
            <ChevronDown className="w-3 h-3" />
          </button>
          {envOpen && (
            <div className="absolute top-full left-0 mt-1 bg-bg-elevated border border-border rounded-md shadow-lg z-50 py-1 min-w-[120px]">
              {ENVIRONMENTS.map((env) => (
                <button
                  key={env}
                  onClick={() => { onEnvironmentChange?.(env); setEnvOpen(false) }}
                  className={cn('w-full text-left px-3 py-1.5 text-xs hover:bg-bg-hover', env === environment ? 'text-accent' : 'text-text-secondary')}
                >
                  {env.toUpperCase()}
                </button>
              ))}
            </div>
          )}
        </div>

        <div className="flex items-center gap-2 text-xs">
          <div className={cn('w-2 h-2 rounded-full', connected ? 'bg-allow' : 'bg-block')} />
          <span className="text-text-secondary font-medium">
            {connected ? 'SENTINEL OPERATIONAL' : 'API UNREACHABLE'}
          </span>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <div className="text-xs text-text-muted font-mono max-w-[220px] truncate" title={`${provider} · ${model}`}>
          {provider} &middot; {model}
        </div>

        <button
          onClick={() => toast('info', 'No new security notifications.')}
          className="relative p-1.5 rounded-md hover:bg-bg-hover text-text-muted hover:text-text transition-colors"
          aria-label="Notifications"
        >
          <Bell className="w-4 h-4" />
        </button>
      </div>
    </header>
  )
}
