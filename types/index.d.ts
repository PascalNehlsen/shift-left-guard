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
  /** Lines the fix took out (or the offending line, while blocked) and put in. */
  diff?: { minus: string[]; plus: string[] }
}

export type Totals = { blocked: number; warned: number; fixed: number; cloud: number }

export type Audit = {
  at: number
  top: string
  score: number
  grade: 'A' | 'B' | 'C' | 'D' | 'F'
  scanned: number
  isTruncated: boolean
  counts: Record<Severity, number>
  findings: { path: string; id: string; severity: Severity; title: string; line: number }[]
}

declare module 'claude-code' {
  interface PluginState {
    'shift-left-guard': {
      events: GuardEvent[]
      totals: Totals
      /** Rule ids still blocked per file, cleared when a clean write follows. */
      pending: Record<string, { ids: string[]; attempts: number; key: string; line?: number; window?: string[] }>
      isPaused: boolean
      isBandHidden: boolean
      /** What the guard did to each tool call, by tool_use_id, for the 🛡 mark on its transcript row. */
      verdicts: Record<string, { action: GuardEvent['action'] | 'clean'; ids: string[] }>
      /** The last /guard audit of this session. */
      audit: Audit | null
    }
  }
}
