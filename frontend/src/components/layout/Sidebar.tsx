import { Link, useLocation } from 'react-router-dom'
import { cn } from '../../lib/utils'
import {
  LayoutDashboard, Activity, Bot, Shield, CheckSquare,
  Beaker, Wrench, FileText, ClipboardList, Settings, Globe,
  ChevronLeft, ChevronRight
} from 'lucide-react'
import { useState } from 'react'

const navItems = [
  { path: '/', label: 'Overview', icon: LayoutDashboard },
  { path: '/monitor', label: 'Live Monitor', icon: Activity },
  { path: '/agents', label: 'Agents', icon: Bot },
  { path: '/security', label: 'Security', icon: Shield },
  { path: '/approvals', label: 'Approvals', icon: CheckSquare },
  { path: '/scenarios', label: 'Scenarios', icon: Beaker },
  { path: '/tools', label: 'Tools', icon: Wrench },
  { path: '/audit', label: 'Audit Log', icon: FileText },
  { path: '/evaluations', label: 'Evaluations', icon: ClipboardList },
  { path: '/integrations', label: 'Integrations', icon: Globe },
  { path: '/settings', label: 'Settings', icon: Settings },
]

export function Sidebar() {
  const location = useLocation()
  const [collapsed, setCollapsed] = useState(false)

  return (
    <aside className={cn(
      'flex flex-col h-screen bg-bg-card border-r border-border transition-all duration-200',
      collapsed ? 'w-16' : 'w-56'
    )}>
      <div className="flex items-center gap-2 px-4 h-14 border-b border-border shrink-0">
        <div className="w-7 h-7 rounded-md bg-accent flex items-center justify-center">
          <Shield className="w-4 h-4 text-bg" />
        </div>
        {!collapsed && (
          <span className="text-sm font-bold tracking-wide">SENTINEL</span>
        )}
      </div>

      <nav className="flex-1 overflow-y-auto py-3 px-2">
        {navItems.map((item) => {
          const Icon = item.icon
          const active = location.pathname === item.path
          return (
            <Link
              key={item.path}
              to={item.path}
              className={cn(
                'flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors mb-0.5',
                active
                  ? 'bg-accent-dim text-accent font-medium'
                  : 'text-text-secondary hover:text-text hover:bg-bg-hover'
              )}
            >
              <Icon className="w-4 h-4 shrink-0" />
              {!collapsed && <span>{item.label}</span>}
            </Link>
          )
        })}
      </nav>

      <button
        onClick={() => setCollapsed(!collapsed)}
        className="flex items-center justify-center h-10 border-t border-border text-text-muted hover:text-text hover:bg-bg-hover transition-colors"
      >
        {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
      </button>
    </aside>
  )
}
