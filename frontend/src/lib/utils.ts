import { clsx, type ClassValue } from 'clsx'
import type { Decision, RiskLevel } from '../types'

export function cn(...inputs: ClassValue[]) {
  return clsx(inputs)
}

export function decisionColor(d: Decision): string {
  switch (d) {
    case 'ALLOW': return 'text-allow bg-allow-dim border-allow/30'
    case 'BLOCK': return 'text-block bg-block-dim border-block/30'
    case 'ESCALATE': return 'text-escalate bg-escalate-dim border-escalate/30'
  }
}

export function decisionIcon(d: Decision): string {
  switch (d) {
    case 'ALLOW': return '\u2713'
    case 'BLOCK': return '\u2717'
    case 'ESCALATE': return '\u26A0'
  }
}

export function riskColor(r: RiskLevel): string {
  switch (r) {
    case 'LOW': return 'text-risk-low'
    case 'MEDIUM': return 'text-risk-medium'
    case 'HIGH': return 'text-risk-high'
    case 'CRITICAL': return 'text-risk-critical'
  }
}

export function riskBg(r: RiskLevel): string {
  switch (r) {
    case 'LOW': return 'bg-risk-low/10 text-risk-low'
    case 'MEDIUM': return 'bg-risk-medium/10 text-risk-medium'
    case 'HIGH': return 'bg-risk-high/10 text-risk-high'
    case 'CRITICAL': return 'bg-risk-critical/10 text-risk-critical'
  }
}

export function formatTime(ts: string): string {
  try {
    const d = new Date(ts)
    return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
  } catch {
    return ts
  }
}

export function formatMoney(amount: number): string {
  return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: 0 }).format(amount)
}
