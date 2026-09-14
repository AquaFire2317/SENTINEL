import { Component, type ReactNode } from 'react'
import { Shield, RefreshCw } from 'lucide-react'
import { Button } from './ui/Button'

interface Props {
  children: ReactNode
}

interface State {
  hasError: boolean
  error: Error | null
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('SENTINEL ErrorBoundary:', error, info)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-bg p-6">
          <div className="w-full max-w-md text-center">
            <div className="w-16 h-16 rounded-2xl bg-block-dim border border-block/20 flex items-center justify-center mx-auto mb-6">
              <Shield className="w-8 h-8 text-block" />
            </div>
            <h1 className="text-xl font-bold mb-2">Something went wrong</h1>
            <p className="text-sm text-text-secondary mb-6">
              The SENTINEL UI encountered an unexpected error.
            </p>
            <pre className="text-xs font-mono bg-bg-card border border-border rounded p-3 mb-6 text-text-muted overflow-x-auto text-left">
              {this.state.error?.message || 'Unknown error'}
            </pre>
            <Button onClick={() => { this.setState({ hasError: false, error: null }); window.location.reload() }}>
              <RefreshCw className="w-4 h-4" />
              Reload Application
            </Button>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}
