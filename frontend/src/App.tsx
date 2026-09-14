import { useState } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './providers/AuthProvider'
import { ToastProvider } from './components/ui/Toast'
import { ErrorBoundary } from './components/ErrorBoundary'
import { CommandPalette } from './components/CommandPalette'
import { AppShell } from './components/layout/AppShell'
import { Onboarding } from './pages/Onboarding'
import { Overview } from './pages/Overview'
import { LiveMonitor } from './pages/LiveMonitor'
import { Agents } from './pages/Agents'
import { Approvals } from './pages/Approvals'
import { Scenarios } from './pages/Scenarios'
import { Tools } from './pages/Tools'
import { AuditLog } from './pages/AuditLog'
import { Evaluations } from './pages/Evaluations'
import { Integrations } from './pages/Integrations'
import { SettingsPage } from './pages/Settings'
import { Policies } from './pages/Policies'

function AppRoutes() {
  const { isConfigured } = useAuth()
  const [onboarded, setOnboarded] = useState(isConfigured)

  if (!onboarded) {
    return <Onboarding onComplete={() => setOnboarded(true)} />
  }

  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route path="/" element={<Overview />} />
        <Route path="/monitor" element={<LiveMonitor />} />
        <Route path="/agents" element={<Agents />} />
        <Route path="/security" element={<Policies />} />
        <Route path="/approvals" element={<Approvals />} />
        <Route path="/scenarios" element={<Scenarios />} />
        <Route path="/tools" element={<Tools />} />
        <Route path="/audit" element={<AuditLog />} />
        <Route path="/evaluations" element={<Evaluations />} />
        <Route path="/integrations" element={<Integrations />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}

export default function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <AuthProvider>
          <ToastProvider>
            <CommandPalette />
            <AppRoutes />
          </ToastProvider>
        </AuthProvider>
      </BrowserRouter>
    </ErrorBoundary>
  )
}
