// Standalone scanner: the same rules as the mod, for a pre-commit hook or CI.
//   node guard-scan.mjs                  scan staged changes (pre-commit)
//   node guard-scan.mjs --all            audit every tracked file as it is on disk (CI)
//   node guard-scan.mjs path/to/file ...  audit the given files as they are on disk
//   node guard-scan.mjs --block-at=medium
//   node guard-scan.mjs --all --format=sarif > guard.sarif   for GitHub code scanning
//   node guard-scan.mjs --all --badge     also print the README badge for the score
// Exits 1 when a finding at or above --block-at (default high) is found.
// Reads the repository's .guard.json (team rules, disabled rules) like the mod does.
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'

import type { Finding, Severity } from '../types'
import { CONFIG_FILE, RULES, badgeMarkdown, envFinding, formatFindings, introduced, isEnvFile, parseConfig, rank, scan, scoreOf } from '../hooks/rules'

const args = process.argv.slice(2)
const paths = args.filter(a => !a.startsWith('--'))
const isAll = args.includes('--all') || paths.length > 0
const blockAt = (args.find(a => a.startsWith('--block-at='))?.split('=')[1] ?? 'high') as Severity | 'never'
const format = args.find(a => a.startsWith('--format='))?.split('=')[1] ?? 'text'
if (format !== 'text' && format !== 'sarif') {
  console.error(`shift-left-guard: unknown --format=${format} (text or sarif)`)
  process.exit(2)
}

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

const top = git('rev-parse', '--show-toplevel')?.trim()
const { config, errors } = parseConfig(top === undefined ? undefined : readFile(`${top}/${CONFIG_FILE}`))
for (const error of errors) console.error(`shift-left-guard: ${CONFIG_FILE}: ${error}`)

const color = process.stdout.isTTY ? (code: number, text: string) => `\x1b[${code}m${text}\x1b[0m` : (_: number, text: string) => text

let blocking = 0
let other = 0
const results: { path: string; finding: Finding }[] = []
for (const path of files) {
  const after = isAll ? readFile(path) : git('show', `:${path}`)
  if (after === undefined || !isText(after)) continue
  const found: Finding[] = isAll ? scan(path, after, config) : introduced(scan(path, git('show', `HEAD:${path}`) ?? '', config), scan(path, after, config))
  // A listed env file is tracked or staged, so it is on its way into the repository.
  if (isEnvFile(path) && !config.disabled.has('SEC004')) found.unshift(envFinding(path))
  if (found.length === 0) continue
  const stop = found.filter(f => rank(f.severity) >= rank(blockAt))
  blocking += stop.length
  other += found.length - stop.length
  results.push(...found.map(finding => ({ path, finding })))
  if (format === 'text') {
    console.log(formatFindings(path, found))
    console.log()
  }
}

if (format === 'sarif') {
  const level = (s: Severity) => (s === 'critical' || s === 'high' ? 'error' : s === 'medium' ? 'warning' : 'note')
  const rules = [...RULES, ...config.rules]
  const used = [...new Set(results.map(r => r.finding.id))]
  console.log(
    JSON.stringify(
      {
        $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
        version: '2.1.0',
        runs: [
          {
            tool: {
              driver: {
                name: 'shift-left-guard',
                informationUri: 'https://github.com/PascalNehlsen/shift-left-guard',
                rules: used.map(id => {
                  const rule = rules.find(r => r.id === id)
                  return {
                    id,
                    shortDescription: { text: rule?.title ?? id },
                    help: { text: rule?.fix ?? '' },
                    defaultConfiguration: { level: level(rule?.severity ?? 'medium') },
                    properties: { 'security-severity': { critical: '9.5', high: '7.5', medium: '5.0', low: '2.0' }[rule?.severity ?? 'medium'] },
                  }
                }),
              },
            },
            results: results.map(({ path, finding }) => ({
              ruleId: finding.id,
              ruleIndex: used.indexOf(finding.id),
              level: level(finding.severity),
              message: { text: `${finding.title}. Fix: ${finding.fix}` },
              locations: [{ physicalLocation: { artifactLocation: { uri: path }, region: { startLine: finding.line } } }],
            })),
          },
        ],
      },
      null,
      2,
    ),
  )
  process.exit(blocking > 0 ? 1 : 0)
}

if (isAll) {
  const { score, grade } = scoreOf(results.map(r => r.finding))
  console.log(color(grade <= 'B' ? 32 : grade === 'C' ? 33 : 31, `🛡 Security score: ${score}/100 · grade ${grade}`))
  if (args.includes('--badge')) console.log(badgeMarkdown(grade))
}

if (blocking > 0) {
  console.log(color(31, `🛡 shift-left-guard: ${blocking} issue(s) at or above ${blockAt}. Commit stopped.`))
  console.log(color(2, '   Fix them, silence a line with `# guard:ignore <ID>`, or skip once with `git commit --no-verify`.'))
  process.exit(1)
}
if (other > 0) console.log(color(33, `🛡 shift-left-guard: ${other} lower-severity issue(s), not blocking.`))
