// Standalone scanner: the same rules as the mod, for a pre-commit hook or CI.
//   node guard-scan.mjs                  scan staged changes (pre-commit)
//   node guard-scan.mjs --all            audit every tracked file as it is on disk (CI)
//   node guard-scan.mjs path/to/file ...  audit the given files as they are on disk
//   node guard-scan.mjs --block-at=medium
// Exits 1 when a finding at or above --block-at (default high) is found.
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'

import type { Finding, Severity } from '../types'
import { formatFindings, introduced, rank, scan } from '../hooks/rules'

const args = process.argv.slice(2)
const paths = args.filter(a => !a.startsWith('--'))
const isAll = args.includes('--all') || paths.length > 0
const blockAt = (args.find(a => a.startsWith('--block-at='))?.split('=')[1] ?? 'high') as Severity | 'never'

const git = (...argv: string[]) => {
  try {
    return execFileSync('git', argv, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] })
  } catch {
    return undefined
  }
}

const readFile = (path: string) => {
  try {
    return readFileSync(path, 'utf8')
  } catch {
    return undefined
  }
}

const isText = (text: string) => text.length < 1_000_000 && !text.includes('\0')

const files = (paths.length > 0 ? paths.join('\0') : isAll ? git('ls-files', '-z') : git('diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z'))
  ?.split('\0')
  .filter(Boolean)

if (files === undefined) {
  console.error('shift-left-guard: not a git repository')
  process.exit(2)
}

const color = process.stdout.isTTY ? (code: number, text: string) => `\x1b[${code}m${text}\x1b[0m` : (_: number, text: string) => text

let blocking = 0
let other = 0
for (const path of files) {
  const after = isAll ? readFile(path) : git('show', `:${path}`)
  if (after === undefined || !isText(after)) continue
  const found: Finding[] = isAll ? scan(path, after) : introduced(scan(path, git('show', `HEAD:${path}`) ?? ''), scan(path, after))
  if (found.length === 0) continue
  const stop = found.filter(f => rank(f.severity) >= rank(blockAt))
  blocking += stop.length
  other += found.length - stop.length
  console.log(formatFindings(path, found))
  console.log()
}

if (blocking > 0) {
  console.log(color(31, `🛡 shift-left-guard: ${blocking} issue(s) at or above ${blockAt}. Commit stopped.`))
  console.log(color(2, '   Fix them, silence a line with `# guard:ignore <ID>`, or skip once with `git commit --no-verify`.'))
  process.exit(1)
}
if (other > 0) console.log(color(33, `🛡 shift-left-guard: ${other} lower-severity issue(s), not blocking.`))
