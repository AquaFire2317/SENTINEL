import { useState } from 'react'
import { Globe, CheckCircle, AlertCircle, Plug, Settings } from 'lucide-react'
import { Card } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { Modal } from '../components/ui/Modal'
import { PageState } from '../components/ui/PageState'
import { api } from '../api/client'
import { useApi } from '../lib/useApi'
import { useAuth } from '../providers/AuthProvider'
import type { ProviderInfo } from '../types'

export function Integrations() {
  const { data, error, loading, reload } = useApi(() => api.getProviders(), [])
  const { settings, updateSettings } = useAuth()
  const [selected, setSelected] = useState<ProviderInfo | null>(null)
  const providers = data?.providers ?? []

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Globe className="w-5 h-5 text-accent" />
        <h1 className="text-xl font-bold">Integrations</h1>
      </div>
      <p className="text-sm text-text-secondary">
        SENTINEL is provider-agnostic: any Strands-supported model can be guarded. The active
        provider is configured on the server via environment variables.
      </p>

      <PageState loading={loading} error={error} onRetry={reload}>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {providers.map((provider) => (
            <Card key={provider.id} hover={provider.active}>
              <div className="flex items-start gap-3 mb-3">
                <div className="w-10 h-10 rounded-lg bg-bg-elevated flex items-center justify-center">
                  <Plug className="w-5 h-5 text-accent" />
                </div>
                <div className="flex-1 min-w-0">
                  <h3 className="font-semibold text-sm truncate">{provider.name}</h3>
                  <p className="text-xs text-text-muted line-clamp-2">{provider.description}</p>
                </div>
                {provider.active && (
                  <Badge variant="decision" decision="ALLOW" size="sm">Active</Badge>
                )}
              </div>

              <div className="flex items-center gap-2 text-xs mb-2">
                {provider.configured ? (
                  <><CheckCircle className="w-3 h-3 text-allow" /> <span className="text-allow">Configured</span></>
                ) : provider.sdk_installed ? (
                  <><AlertCircle className="w-3 h-3 text-escalate" /> <span className="text-escalate">SDK ready · needs config</span></>
                ) : (
                  <><AlertCircle className="w-3 h-3 text-text-muted" /> <span className="text-text-muted">SDK not installed</span></>
                )}
              </div>

              {provider.default_model && (
                <div className="text-[10px] font-mono text-text-muted mb-3 truncate" title={provider.default_model}>
                  default: {provider.default_model}
                </div>
              )}

              <Button
                variant={provider.active ? 'primary' : 'secondary'}
                size="sm"
                className="w-full"
                onClick={() => setSelected(provider)}
              >
                {provider.active ? <><Settings className="w-3 h-3" /> Configure</> : <><Plug className="w-3 h-3" /> Set up</>}
              </Button>
            </Card>
          ))}
        </div>
      </PageState>

      <Modal open={selected !== null} onClose={() => setSelected(null)} title={selected?.name ?? 'Provider'}>
        {selected && (
          <div className="space-y-4 text-sm">
            <p className="text-text-secondary">{selected.description}</p>
            <div className="bg-bg-elevated rounded-md p-3 space-y-2">
              <div className="text-[10px] text-text-muted">SERVER ENVIRONMENT</div>
              <Code line={`SENTINEL_MODEL_PROVIDER=${selected.id}`} />
              <Code line={`SENTINEL_MODEL_ID=${selected.default_model || '<model-id>'}`} />
              {selected.requires_api_key && <Code line="SENTINEL_MODEL_API_KEY=<your-key>" />}
              {selected.supports_base_url && <Code line="SENTINEL_MODEL_BASE_URL=<optional-endpoint>" />}
            </div>
            {selected.sdk && !selected.sdk_installed && (
              <p className="text-xs text-escalate">
                Install the SDK first: <code className="font-mono">pip install {selected.sdk}</code>
              </p>
            )}
            <Button
              className="w-full"
              onClick={() => {
                updateSettings({ provider: selected.id, model: selected.default_model || '' })
                setSelected(null)
              }}
            >
              Use {selected.name} in this dashboard
            </Button>
            {settings.provider && (
              <p className="text-[10px] text-text-muted text-center">
                Dashboard preference: {settings.provider}
              </p>
            )}
          </div>
        )}
      </Modal>
    </div>
  )
}

function Code({ line }: { line: string }) {
  return (
    <code className="block text-[11px] font-mono text-text-secondary break-all bg-bg px-2 py-1 rounded border border-border-subtle">
      {line}
    </code>
  )
}
