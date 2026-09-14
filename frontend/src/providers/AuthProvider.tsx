import { createContext, useContext, useState, useCallback, type ReactNode } from 'react'
import type { AppSettings } from '../types'

interface AuthContextValue {
  settings: AppSettings
  updateSettings: (partial: Partial<AppSettings>) => void
  isConfigured: boolean
}

const defaultSettings: AppSettings = {
  provider: '',
  model: '',
  api_key_set: false,
  backend_url: '/api',
  demo_mode: true,
  environment: 'demo',
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState<AppSettings>(() => {
    try {
      const saved = localStorage.getItem('sentinel_settings')
      return saved ? { ...defaultSettings, ...JSON.parse(saved) } : defaultSettings
    } catch {
      return defaultSettings
    }
  })

  const updateSettings = useCallback((partial: Partial<AppSettings>) => {
    setSettings((prev) => {
      const next = { ...prev, ...partial }
      try {
        localStorage.setItem('sentinel_settings', JSON.stringify(next))
      } catch { /* ignore */ }
      return next
    })
  }, [])

  const isConfigured = settings.api_key_set || settings.demo_mode

  return (
    <AuthContext.Provider value={{ settings, updateSettings, isConfigured }}>
      {children}
    </AuthContext.Provider>
  )
}
