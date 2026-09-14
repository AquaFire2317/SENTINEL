import { useState } from 'react'
import { Settings as SettingsIcon, Save, RefreshCw } from 'lucide-react'
import { Card, CardHeader, CardTitle } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { PageState } from '../components/ui/PageState'
import { api, backendUrl } from '../api/client'
import { useApi } from '../lib/useApi'
import { useAuth } from '../providers/AuthProvider'
import env from '../lib/env'

export function SettingsPage() {
  const { settings, updateSettings } = useAuth()
  const { data, error, loading, reload } = useApi(() => api.getConfig(), [])
  const [backend, setBackend] = useState(() => backendUrl.get())
  const [saved, setSaved] = useState(false)

  const handleSave = () => {
    backendUrl.set(backend)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
    reload()
  }

  const model = data?.model

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <SettingsIcon className="w-5 h-5 text-accent" />
          <h1 className="text-xl font-bold">Settings</h1>
        </div>
        <Button onClick={handleSave}>
          {saved ? 'Saved!' : <><Save className="w-4 h-4" /> Save Changes</>}
        </Button>
      </div>

      <PageState loading={loading} error={error} onRetry={reload}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Card>
            <CardHeader>
              <CardTitle>General</CardTitle>
            </CardHeader>
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-text-secondary mb-1.5">Environment</label>
                <select
                  value={settings.environment}
                  onChange={(e) => updateSettings({ environment: e.target.value as typeof settings.environment })}
                  className="w-full h-9 px-3 bg-bg-elevated border border-border rounded-md text-sm text-text focus:outline-none focus:border-accent"
                >
                  <option value="local">Local</option>
                  <option value="demo">Demo</option>
                  <option value="production">Production</option>
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium text-text-secondary mb-1.5">Backend URL</label>
                <input
                  type="text"
                  value={backend}
                  onChange={(e) => setBackend(e.target.value)}
                  placeholder={env.API_BASE}
                  className="w-full h-9 px-3 bg-bg-elevated border border-border rounded-md text-sm text-text font-mono focus:outline-none focus:border-accent"
                />
                <p className="text-[10px] text-text-muted mt-1">
                  Leave blank to use the same origin ({env.API_BASE}).
                </p>
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-sm text-text">Demo Mode</div>
                  <div className="text-xs text-text-muted">Use fixtures instead of a live model</div>
                </div>
                <button
                  onClick={() => updateSettings({ demo_mode: !settings.demo_mode })}
                  className={`w-10 h-5 rounded-full transition-colors ${settings.demo_mode ? 'bg-accent' : 'bg-bg-elevated border border-border'}`}
                >
                  <div className={`w-4 h-4 rounded-full bg-white transition-transform ${settings.demo_mode ? 'translate-x-[22px]' : 'translate-x-0.5'}`} />
                </button>
              </div>
            </div>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Model Provider (server)</CardTitle>
              <Button variant="ghost" size="sm" onClick={reload}>
                <RefreshCw className="w-3 h-3" />
              </Button>
            </CardHeader>
            <div className="space-y-3 text-sm">
              <Row label="Provider" value={model?.provider_name || '—'} />
              <Row label="Provider id" value={model?.provider || '—'} mono />
              <Row label="Model" value={model?.model_id || '—'} mono />
              <Row label="API key" value={model?.api_key_set ? 'configured' : 'not set'} />
              <Row label="SDK installed" value={model?.sdk_installed ? 'yes' : 'no'} />
              {model?.base_url && <Row label="Base URL" value={model.base_url} mono />}
            </div>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Security</CardTitle>
            </CardHeader>
            <div className="space-y-3 text-sm">
              <Row label="Policy Engine" value={`active (${data?.policy_version || 'v'})`} />
              <Row label="Permit System" value="HMAC-SHA256, single-use" />
              <Row label="Allowlisted tools" value={`${data?.allowlisted_tools.length ?? 0}`} />
              <Row label="Side-effect tools" value={`${data?.side_effect_tools.length ?? 0}`} />
              <Row label="Durable audit" value={data?.persistence.durable ? 'DynamoDB' : 'in-memory'} />
              <Row label="Orchestration" value={data?.orchestration.step_functions ? 'Step Functions' : 'synchronous'} />
            </div>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>About</CardTitle>
            </CardHeader>
            <div className="space-y-3 text-sm">
              <Row label="Version" value={data?.version || env.APP_VERSION} mono />
              <Row label="Environment" value={data?.environment || '—'} mono />
              <Row label="AWS Region" value={data?.aws_region || '—'} mono />
              <Row label="License" value="MIT" />
            </div>
          </Card>
        </div>
      </PageState>
    </div>
  )
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex justify-between py-2 border-b border-border-subtle last:border-0 gap-4">
      <span className="text-text-secondary shrink-0">{label}</span>
      <span className={`text-right break-all ${mono ? 'font-mono' : ''}`}>{value}</span>
    </div>
  )
}
