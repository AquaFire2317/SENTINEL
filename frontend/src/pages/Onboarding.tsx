import { useMemo, useState } from 'react'
import { Shield, Loader2, CheckCircle, AlertCircle, ArrowRight } from 'lucide-react'
import { Button } from '../components/ui/Button'
import { Card } from '../components/ui/Card'
import { useAuth } from '../providers/AuthProvider'
import { api } from '../api/client'
import { useApi } from '../lib/useApi'

interface OnboardingProps {
  onComplete: () => void
}

const FALLBACK_PROVIDERS = [
  { id: 'openrouter', name: 'OpenRouter', models: ['openai/gpt-4o-mini'], description: 'Gateway to many models' },
  { id: 'anthropic', name: 'Anthropic', models: ['claude-3-7-sonnet-latest'], description: 'Claude models' },
  { id: 'openai', name: 'OpenAI', models: ['gpt-4o-mini'], description: 'OpenAI models' },
  { id: 'bedrock', name: 'AWS Bedrock', models: ['us.anthropic.claude-3-5-sonnet-20241022-v2:0'], description: 'Amazon Bedrock' },
]

export function Onboarding({ onComplete }: OnboardingProps) {
  const { settings, updateSettings } = useAuth()
  const { data } = useApi(() => api.getProviders(), [])
  const [provider, setProvider] = useState(settings.provider || '')
  const [model, setModel] = useState(settings.model || '')
  const [customModel, setCustomModel] = useState('')
  const [testing, setTesting] = useState(false)
  const [backendReachable, setBackendReachable] = useState<boolean | null>(null)

  const providers = useMemo(
    () => data?.providers.map((p) => ({ id: p.id, name: p.name, models: p.models, description: p.description })) ?? FALLBACK_PROVIDERS,
    [data]
  )
  const selected = providers.find((p) => p.id === provider)
  const models = selected?.models ?? []
  const finalModel = models.length ? model : customModel

  const handleTest = async () => {
    setTesting(true)
    setBackendReachable(null)
    try {
      await api.health()
      setBackendReachable(true)
    } catch {
      setBackendReachable(false)
    } finally {
      setTesting(false)
    }
  }

  const finish = (demo: boolean) => {
    updateSettings({
      provider: demo ? 'local' : provider,
      model: demo ? 'Deterministic planner' : finalModel,
      api_key_set: false,
      demo_mode: demo,
      environment: demo ? 'demo' : 'production',
    })
    onComplete()
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-bg p-6">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="w-16 h-16 rounded-2xl bg-accent/10 border border-accent/20 flex items-center justify-center mx-auto mb-4">
            <Shield className="w-8 h-8 text-accent" />
          </div>
          <h1 className="text-3xl font-bold tracking-tight mb-2">SENTINEL</h1>
          <p className="text-text-secondary text-sm">Secure autonomous AI before it reaches the real world.</p>
        </div>

        <Card className="p-6">
          <div className="mb-4">
            <label className="block text-xs font-medium text-text-secondary mb-1.5">Provider</label>
            <select
              value={provider}
              onChange={(e) => { setProvider(e.target.value); setModel(''); setCustomModel('') }}
              className="w-full h-9 px-3 bg-bg-elevated border border-border rounded-md text-sm text-text focus:outline-none focus:border-accent"
            >
              <option value="">Select provider...</option>
              {providers.map((p) => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
          </div>

          <div className="mb-4">
            <label className="block text-xs font-medium text-text-secondary mb-1.5">Model</label>
            {models.length ? (
              <select
                value={model}
                onChange={(e) => setModel(e.target.value)}
                className="w-full h-9 px-3 bg-bg-elevated border border-border rounded-md text-sm text-text focus:outline-none focus:border-accent"
              >
                <option value="">Select model...</option>
                {models.map((m) => (
                  <option key={m} value={m}>{m}</option>
                ))}
              </select>
            ) : (
              <input
                type="text"
                value={customModel}
                onChange={(e) => setCustomModel(e.target.value)}
                placeholder="Enter model ID..."
                className="w-full h-9 px-3 bg-bg-elevated border border-border rounded-md text-sm text-text font-mono focus:outline-none focus:border-accent placeholder:text-text-muted"
              />
            )}
          </div>

          <p className="text-[11px] text-text-muted mb-4 bg-bg-elevated border border-border-subtle rounded-md p-2.5">
            The model provider and its API key are configured on the SENTINEL server
            (<span className="font-mono">SENTINEL_MODEL_PROVIDER</span>,
            <span className="font-mono"> SENTINEL_MODEL_API_KEY</span>). This selection is stored
            as your dashboard preference.
          </p>

          <div className="mb-4">
            <Button
              variant="secondary"
              onClick={handleTest}
              disabled={!provider || testing}
              className="w-full"
            >
              {testing ? (
                <><Loader2 className="w-4 h-4 animate-spin" /> Testing...</>
              ) : backendReachable === true ? (
                <><CheckCircle className="w-4 h-4 text-allow" /> Backend reachable</>
              ) : backendReachable === false ? (
                <><AlertCircle className="w-4 h-4 text-block" /> Backend unreachable</>
              ) : (
                'Test backend connection'
              )}
            </Button>
          </div>

          <Button onClick={() => finish(false)} disabled={!provider} className="w-full">
            Enter SENTINEL
            <ArrowRight className="w-4 h-4" />
          </Button>
        </Card>

        <div className="text-center mt-4">
          <button onClick={() => finish(true)} className="text-xs text-text-muted hover:text-accent transition-colors">
            Continue in Demo Mode
          </button>
        </div>
      </div>
    </div>
  )
}
