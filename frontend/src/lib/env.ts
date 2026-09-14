const env = {
  API_BASE: import.meta.env.VITE_API_BASE || '/api',
  APP_TITLE: 'SENTINEL',
  APP_VERSION: '0.3.0',
  DEMO_MODE_DEFAULT: true,
} as const

export default env
