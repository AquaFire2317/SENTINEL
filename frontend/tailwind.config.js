/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: {
          DEFAULT: '#09090b',
          card: '#111113',
          elevated: '#18181b',
          hover: '#1f1f23',
          active: '#27272a',
        },
        border: {
          DEFAULT: '#27272a',
          subtle: '#1f1f23',
        },
        text: {
          DEFAULT: '#fafafa',
          secondary: '#a1a1aa',
          muted: '#71717a',
        },
        accent: {
          DEFAULT: '#00c896',
          dim: 'rgba(0, 200, 150, 0.12)',
        },
        allow: {
          DEFAULT: '#22c55e',
          dim: 'rgba(34, 197, 94, 0.1)',
        },
        block: {
          DEFAULT: '#ef4444',
          dim: 'rgba(239, 68, 68, 0.1)',
        },
        escalate: {
          DEFAULT: '#f59e0b',
          dim: 'rgba(245, 158, 11, 0.1)',
        },
        info: {
          DEFAULT: '#3b82f6',
          dim: 'rgba(59, 130, 246, 0.1)',
        },
        risk: {
          low: '#22c55e',
          medium: '#f59e0b',
          high: '#f97316',
          critical: '#ef4444',
        },
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      keyframes: {
        'slide-in': {
          from: { opacity: '0', transform: 'translateX(1rem)' },
          to: { opacity: '1', transform: 'translateX(0)' },
        },
      },
      animation: {
        'slide-in': 'slide-in 0.18s ease-out',
      },
    },
  },
  plugins: [],
}
