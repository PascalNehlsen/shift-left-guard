export type Severity = 'low' | 'medium' | 'high' | 'critical'

export type Finding = {
  id: string
  severity: Severity
  title: string
  fix: string
  line: number
  snippet: string
}

export type GuardEvent = {
  at: number
  file: string
  action: 'blocked' | 'flagged' | 'warned' | 'fixed' | 'let-through' | 'cloud'
  findings: { id: string; severity: Severity; title: string; line: number }[]
  note?: string
}

export type Totals = { blocked: number; warned: number; fixed: number; cloud: number }

declare module 'claude-code' {
  interface PluginState {
    'shift-left-guard': {
      events: GuardEvent[]
      totals: Totals
      /** Rule ids still blocked per file, cleared when a clean write follows. */
      pending: Record<string, { ids: string[]; attempts: number; key: string }>
      isPaused: boolean
      isBandHidden: boolean
    }
  }
}
