import { Outlet } from 'react-router-dom'
import { Sidebar } from './Sidebar'
import { TopBar } from './TopBar'
import { useAuth } from '../../providers/AuthProvider'
import { api } from '../../api/client'
import { useApi } from '../../lib/useApi'

export function AppShell() {
  const { settings, updateSettings } = useAuth()
  const health = useApi(() => api.health(), [])
  const config = useApi(() => api.getConfig(), [])

  const provider = config.data?.model.provider_name || settings.provider || 'Not configured'
  const model = config.data?.model.model_id || settings.model || 'None'
  const connected = health.data?.status === 'healthy'

  return (
    <div className="flex h-screen overflow-hidden bg-bg">
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0">
        <TopBar
          environment={settings.environment}
          provider={provider}
          model={model}
          connected={connected}
          onEnvironmentChange={(environment) => updateSettings({ environment })}
        />
        <main className="flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
