import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, LayoutDashboard, Activity, Bot, Shield, CheckSquare, Beaker, Wrench, FileText, ClipboardList, Globe, Settings } from 'lucide-react'
import { cn } from '../lib/utils'

interface Command {
  id: string
  label: string
  icon: typeof Search
  action: () => void
}

export function CommandPalette() {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState(0)
  const navigate = useNavigate()

  const commands: Command[] = [
    { id: 'overview', label: 'Go to Overview', icon: LayoutDashboard, action: () => { navigate('/'); setOpen(false) } },
    { id: 'monitor', label: 'Go to Live Monitor', icon: Activity, action: () => { navigate('/monitor'); setOpen(false) } },
    { id: 'agents', label: 'Go to Agents', icon: Bot, action: () => { navigate('/agents'); setOpen(false) } },
    { id: 'security', label: 'Go to Security', icon: Shield, action: () => { navigate('/security'); setOpen(false) } },
    { id: 'approvals', label: 'Go to Approvals', icon: CheckSquare, action: () => { navigate('/approvals'); setOpen(false) } },
    { id: 'scenarios', label: 'Go to Scenarios', icon: Beaker, action: () => { navigate('/scenarios'); setOpen(false) } },
    { id: 'tools', label: 'Go to Tools', icon: Wrench, action: () => { navigate('/tools'); setOpen(false) } },
    { id: 'audit', label: 'Go to Audit Log', icon: FileText, action: () => { navigate('/audit'); setOpen(false) } },
    { id: 'evaluations', label: 'Go to Evaluations', icon: ClipboardList, action: () => { navigate('/evaluations'); setOpen(false) } },
    { id: 'integrations', label: 'Go to Integrations', icon: Globe, action: () => { navigate('/integrations'); setOpen(false) } },
    { id: 'settings', label: 'Go to Settings', icon: Settings, action: () => { navigate('/settings'); setOpen(false) } },
    { id: 'run-demo', label: 'Run Security Demo', icon: Beaker, action: () => { navigate('/scenarios'); setOpen(false) } },
  ]

  const filtered = commands.filter((c) =>
    c.label.toLowerCase().includes(query.toLowerCase())
  )

  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault()
      setOpen((prev) => !prev)
      setQuery('')
      setSelected(0)
    }
  }, [])

  useEffect(() => {
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [handleKeyDown])

  useEffect(() => {
    setSelected(0)
  }, [query])

  const handleKeyDownInPalette = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setSelected((s) => Math.min(s + 1, filtered.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setSelected((s) => Math.max(s - 1, 0))
    } else if (e.key === 'Enter' && filtered[selected]) {
      filtered[selected].action()
    } else if (e.key === 'Escape') {
      setOpen(false)
    }
  }

  if (!open) return null

  return (
    <div
      className="fixed inset-0 z-[100] flex items-start justify-center pt-[20vh] bg-black/60 backdrop-blur-sm"
      onClick={() => setOpen(false)}
    >
      <div
        className="w-full max-w-lg mx-4 bg-bg-card border border-border rounded-lg shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-3 px-4 h-12 border-b border-border">
          <Search className="w-4 h-4 text-text-muted" />
          <input
            autoFocus
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDownInPalette}
            placeholder="Type a command..."
            className="flex-1 bg-transparent text-sm text-text outline-none placeholder:text-text-muted"
          />
          <kbd className="text-[10px] font-mono text-text-muted bg-bg-elevated border border-border rounded px-1.5 py-0.5">
            ESC
          </kbd>
        </div>
        <div className="max-h-64 overflow-y-auto py-1">
          {filtered.map((cmd, i) => {
            const Icon = cmd.icon
            return (
              <button
                key={cmd.id}
                onClick={cmd.action}
                className={cn(
                  'w-full flex items-center gap-3 px-4 py-2 text-sm text-left transition-colors',
                  i === selected ? 'bg-accent-dim text-accent' : 'text-text-secondary hover:bg-bg-hover hover:text-text'
                )}
              >
                <Icon className="w-4 h-4 shrink-0" />
                {cmd.label}
              </button>
            )
          })}
          {filtered.length === 0 && (
            <div className="px-4 py-6 text-center text-sm text-text-muted">No commands found</div>
          )}
        </div>
      </div>
    </div>
  )
}
