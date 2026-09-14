import { AlertTriangle, Loader2 } from 'lucide-react'
import type { ReactNode } from 'react'
import { Card } from './Card'
import { Button } from './Button'

interface PageStateProps {
  loading?: boolean
  error?: string | null
  onRetry?: () => void
  children: ReactNode
}

/**
 * Renders a loading spinner or an error card with retry before showing content.
 * Used by data-backed pages so failures are visible instead of silent.
 */
export function PageState({ loading, error, onRetry, children }: PageStateProps) {
  if (loading) {
    return (
      <Card>
        <div className="flex items-center justify-center gap-3 py-16 text-text-secondary text-sm">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading...
        </div>
      </Card>
    )
  }

  if (error) {
    return (
      <Card className="border-block/30">
        <div className="text-center py-12">
          <AlertTriangle className="w-10 h-10 text-block mx-auto mb-3" />
          <p className="text-sm font-semibold mb-1">Could not reach the SENTINEL API</p>
          <p className="text-xs text-text-muted mb-4 max-w-md mx-auto">{error}</p>
          {onRetry && (
            <Button variant="secondary" size="sm" onClick={onRetry}>
              Retry
            </Button>
          )}
        </div>
      </Card>
    )
  }

  return <>{children}</>
}
