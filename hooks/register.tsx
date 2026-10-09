import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register, ToolCallResult } from 'claude-code'

import type { Finding, GuardEvent, Severity, Totals } from '../types'
import {
  CONFIG_FILE,
  EXPLAIN,
  RULES,
  applyEdit,
  blastRadius,
  destructive,
  envFinding,
  formatFindings,
  introduced,
  isEnvFile,
  parseConfig,
  rank,
  scan,
  shown,
} from './rules'
import type { GuardConfig } from './rules'

const events = atom({ plugin: 'shift-left-guard', key: 'events' } as const, [])
const totals = atom({ plugin: 'shift-left-guard', key: 'totals' } as const, { blocked: 0, warned: 0, fixed: 0, cloud: 0 })
const pending = atom({ plugin: 'shift-left-guard', key: 'pending' } as const, {})
const isPaused = atom({ plugin: 'shift-left-guard', key: 'isPaused' } as const, false)
const isBandHidden = atom({ plugin: 'shift-left-guard', key: 'isBandHidden' } as const, false)
const verdicts = atom({ plugin: 'shift-left-guard', key: 'verdicts' } as const, {})

const LIFETIME = 'lifetime'
const MAX_ATTEMPTS = 2
const PANE = 'shift-left-guard-report'
const MAX_SHELL_FILES = 40
const MAX_FILE_BYTES = 1_000_000

type $ = EngineInterface
type Opts = { blockAt: Severity | 'never'; explain: boolean }
type Verdict = GuardEvent['action'] | 'clean'

const MAX_VERDICTS = 200
const DIFF_CONTEXT = 3

/** Marks a tool call's transcript row with what the guard did to it. */
const mark = async ($: $, toolUseId: string | undefined, action: Verdict, ids: readonly string[] = []) => {
  if (toolUseId === undefined) return
  await update($, verdicts, v => Object.fromEntries([...Object.entries(v), [toolUseId, { action, ids: [...ids] }]].slice(-MAX_VERDICTS)))
}

/** The lines around a finding, so the band can show what the fix changed. */
const windowAt = (text: string, line: number) => text.split(/\r?\n/).slice(Math.max(0, line - 1 - DIFF_CONTEXT), line + DIFF_CONTEXT)

/**
 * The lines the fix took out of the blocked version and the ones it put in,
 * near where the finding was: the band's before/after.
 */
const diffOf = (id: string, blocked: readonly string[] | undefined, line: number | undefined, fixed: string) => {
  if (blocked === undefined || line === undefined) return undefined
  const now = fixed.split(/\r?\n/).slice(Math.max(0, line - 1 - DIFF_CONTEXT - 2), line + DIFF_CONTEXT + 2)
  const show = (l: string) => shown({ id, snippet: l.trim() }).slice(0, 120)
  const minus = blocked.filter(l => l.trim() !== '' && !now.includes(l)).slice(0, 3).map(show)
  const plus = now.filter(l => l.trim() !== '' && !blocked.includes(l)).slice(0, 3).map(show)
  return minus.length + plus.length === 0 ? undefined : { minus, plus }
}

const lessonFor = (opts: Opts) =>
  opts.explain ? ['Learning mode is on: in your reply, explain to the user in one or two plain sentences why each finding matters (see "why:").'] : []

const shortPath = (path: string) => path.split(/[\\/]/).slice(-3).join('/')

const statusLine = (t: Totals) => {
  const parts = [
    t.blocked && `${t.blocked} caught`,
    t.fixed && `${t.fixed} fixed`,
    t.warned && `${t.warned} warned`,
    t.cloud && `${t.cloud} cloud`,
  ].filter(Boolean)
  return parts.length === 0 ? undefined : `🛡 ${parts.join(' · ')}`
}

const record = async ($: $, event: GuardEvent, delta: Partial<Totals>) => {
  await update($, events, list => [...list, event].slice(-50))
  const next = await update($, totals, t => ({
    blocked: t.blocked + (delta.blocked ?? 0),
    warned: t.warned + (delta.warned ?? 0),
    fixed: t.fixed + (delta.fixed ?? 0),
    cloud: t.cloud + (delta.cloud ?? 0),
  }))
  await update($, isBandHidden, () => false)
  $.ui.status(statusLine(next))
  const lifetime = ((await $.store.get(LIFETIME)) ?? {}) as Partial<Totals>
  await $.store.set(LIFETIME, {
    blocked: (lifetime.blocked ?? 0) + (delta.blocked ?? 0),
    warned: (lifetime.warned ?? 0) + (delta.warned ?? 0),
    fixed: (lifetime.fixed ?? 0) + (delta.fixed ?? 0),
    cloud: (lifetime.cloud ?? 0) + (delta.cloud ?? 0),
  })
}

const brief = (findings: readonly Finding[]) =>
  findings.map(({ id, severity, title, line }) => ({ id, severity, title, line }))

const keyOf = (findings: readonly Finding[]) =>
  findings
    .map(f => `${f.id}:${f.snippet}`)
    .sort()
    .join('|')

const git = async ($: $, args: readonly string[], cwd?: string) => {
  const ran = await $.process.run(['git', ...args], { cwd, timeoutMs: 10_000 }).catch(() => undefined)
  return ran?.exitCode === 0 ? ran.stdout : undefined
}

const dirOf = (path: string) => path.replace(/[\\/][^\\/]*$/, '') || '/'

/** Repository roots by directory: a file's repo does not change within a session. */
const roots = new Map<string, string | undefined>()
const reportedConfigErrors = new Set<string>()

const repoOf = async ($: $, path: string) => {
  const dir = dirOf(path)
  if (!roots.has(dir)) {
    const top = (await git($, ['rev-parse', '--show-toplevel'], dir))?.trim() ?? (await git($, ['rev-parse', '--show-toplevel']))?.trim()
    roots.set(dir, top || undefined)
  }
  return roots.get(dir)
}

/** The repository's `.guard.json`, read on every check so an edit to it applies at once. */
const configOf = async ($: $, top: string | undefined): Promise<GuardConfig> => {
  if (top === undefined) return parseConfig(undefined).config
  const { config, errors } = parseConfig(await $.fs.read(`${top}/${CONFIG_FILE}`).catch(() => undefined))
  for (const error of errors) {
    if (reportedConfigErrors.has(error)) continue
    reportedConfigErrors.add(error)
    $.ui.toast(`🛡 ${CONFIG_FILE}: ${error}`)
  }
  return config
}

/** Scans `after` against `before` with the repo's config, plus the git-ignore check for a new env file. */
const findingsFor = async ($: $, path: string, before: string, after: string, top: string | undefined) => {
  const config = await configOf($, top)
  const found = introduced(scan(path, before, config), scan(path, after, config))
  if (before === '' && top !== undefined && isEnvFile(path) && !config.disabled.has('SEC004')) {
    const ignored = await $.process.run(['git', 'check-ignore', '-q', path], { cwd: top, timeoutMs: 10_000 }).catch(() => undefined)
    if (ignored?.exitCode === 1) found.unshift(envFinding(path))
  }
  return found
}

/** Judges the file as it will stand after the call; answers the call. */
async function guard(
  $: $,
  opts: Opts,
  path: string,
  after: string | undefined,
  run: () => Promise<ToolCallResult>,
  toolUseId?: string,
): Promise<ToolCallResult> {
  if (after === undefined || (await read($, isPaused))) return run()
  const { blockAt } = opts

  const before = await $.fs.read(path).catch(() => '')
  const found = await findingsFor($, path, before, after, await repoOf($, path))
  const blocking = found.filter(f => rank(f.severity) >= rank(blockAt))
  const warnings = found.filter(f => rank(f.severity) < rank(blockAt))
  const open = (await read($, pending))[path]

  if (blocking.length > 0) {
    const key = keyOf(blocking)
    const attempts = open?.key === key ? open.attempts + 1 : 1

    if (attempts <= MAX_ATTEMPTS) {
      const line = blocking[0]?.line ?? 1
      await update($, pending, p => ({ ...p, [path]: { ids: blocking.map(f => f.id), attempts, key, line, window: windowAt(after, line) } }))
      await record(
        $,
        { at: Date.now(), file: path, action: 'blocked', findings: brief(blocking), diff: { minus: [shown(blocking[0]!).slice(0, 120)], plus: [] } },
        { blocked: blocking.length },
      )
      await mark($, toolUseId, 'blocked', blocking.map(f => f.id))
      if (blocking.some(f => f.severity === 'critical')) {
        $.ui.toast(`🛡 Blocked a critical issue in ${shortPath(path)}: ${blocking[0]?.title}`)
      }
      return {
        deny: [
          `shift-left-guard stopped this write: it would introduce ${blocking.length} security issue(s) in ${path}.`,
          formatFindings(path, blocking, opts.explain),
          'Fix these and write the file again. Keep the rest of your change as it was.',
          ...lessonFor(opts),
          'If a finding is a false positive, explain why to the user; add a `# guard:ignore <ID>` comment only when the user agrees.',
        ].join('\n\n'),
      }
    }

    // Same findings again after the retries: let it through, loudly.
    await update($, pending, ({ [path]: _, ...rest }) => rest)
    await record(
      $,
      { at: Date.now(), file: path, action: 'let-through', findings: brief(blocking), note: 'same findings after retries' },
      { warned: blocking.length },
    )
    $.ui.toast(`🛡 Let ${shortPath(path)} through with ${blocking.length} open issue(s): see /guard`)
    await mark($, toolUseId, 'let-through', blocking.map(f => f.id))
    const ran = await run()
    return ran.deny === undefined && !ran.isError
      ? {
          ...ran,
          context: [
            ...(ran.context ?? []),
            `shift-left-guard let this write through with unresolved issues. Tell the user about them:\n${formatFindings(path, blocking, opts.explain)}`,
          ],
        }
      : ran
  }

  const ran = await run()
  if (ran.deny !== undefined || ran.isError) return ran

  if (open !== undefined) {
    await update($, pending, ({ [path]: _, ...rest }) => rest)
    const fixed = RULES.filter(r => open.ids.includes(r.id)).map(r => ({ id: r.id, severity: r.severity, title: r.title, line: 0 }))
    const diff = diffOf(open.ids[0] ?? '', open.window, open.line, after)
    await record($, { at: Date.now(), file: path, action: 'fixed', findings: fixed, diff }, { fixed: open.ids.length })
    await mark($, toolUseId, 'fixed', open.ids)
  }

  if (warnings.length === 0) {
    if (open === undefined) await mark($, toolUseId, 'clean')
    return ran
  }

  await record($, { at: Date.now(), file: path, action: 'warned', findings: brief(warnings) }, { warned: warnings.length })
  await mark($, toolUseId, 'warned', warnings.map(f => f.id))
  return {
    ...ran,
    context: [
      ...(ran.context ?? []),
      `shift-left-guard noticed lower-severity issues in ${path}. Fix them if it fits the task, otherwise mention them to the user:\n${formatFindings(path, warnings, opts.explain)}`,
    ],
  }
}

/**
 * After a shell command: scans the files it changed (anything git sees as
 * modified or new, touched since the command started) against HEAD, and
 * hands Claude what the command introduced. The write already happened, so
 * this cannot refuse it: it records the findings and asks for a fix.
 */
async function checkShellWrites(
  $: $,
  opts: Opts,
  startedAt: number,
  ran: ToolCallResult,
  toolUseId?: string,
): Promise<ToolCallResult> {
  if (ran.deny !== undefined || (await read($, isPaused))) return ran
  const { blockAt } = opts
  const flagged: string[] = []

  const top = (await git($, ['rev-parse', '--show-toplevel']))?.trim()
  if (!top) return ran
  const listed = await git($, ['ls-files', '-z', '--modified', '--others', '--exclude-standard'], top)
  if (!listed) return ran

  const notes: string[] = []
  const open = await read($, pending)
  const paths = [...new Set(listed.split('\0').filter(Boolean))].slice(0, 500)
  let checked = 0

  for (const rel of paths) {
    if (checked >= MAX_SHELL_FILES) break
    const path = `${top}/${rel}`
    const stat = await $.fs.stat(path).catch(() => undefined)
    if (stat === undefined || stat.kind !== 'file' || stat.size > MAX_FILE_BYTES || stat.mtimeMs < startedAt - 1000) continue
    checked += 1

    const after = await $.fs.read(path).catch(() => undefined)
    if (after === undefined || after.includes('\0')) continue
    const before = (await git($, ['show', `HEAD:${rel}`], top)) ?? ''
    const found = await findingsFor($, path, before, after, top)
    const blocking = found.filter(f => rank(f.severity) >= rank(blockAt))

    if (blocking.length > 0) {
      const line = blocking[0]?.line ?? 1
      await update($, pending, p => ({
        ...p,
        [path]: { ids: blocking.map(f => f.id), attempts: 1, key: keyOf(blocking), line, window: windowAt(after, line) },
      }))
      await record(
        $,
        { at: Date.now(), file: path, action: 'flagged', findings: brief(blocking), diff: { minus: [shown(blocking[0]!).slice(0, 120)], plus: [] } },
        { blocked: blocking.length },
      )
      flagged.push(...blocking.map(f => f.id))
      if (blocking.some(f => f.severity === 'critical')) {
        $.ui.toast(`🛡 A shell command wrote a critical issue to ${shortPath(path)}: ${blocking[0]?.title}`)
      }
      notes.push(formatFindings(path, blocking, opts.explain))
    } else if (open[path] !== undefined) {
      const was = open[path]!
      await update($, pending, ({ [path]: _, ...rest }) => rest)
      const fixed = RULES.filter(r => was.ids.includes(r.id)).map(r => ({ id: r.id, severity: r.severity, title: r.title, line: 0 }))
      const diff = diffOf(was.ids[0] ?? '', was.window, was.line, after)
      await record($, { at: Date.now(), file: path, action: 'fixed', findings: fixed, diff }, { fixed: was.ids.length })
    }
  }

  if (notes.length === 0) return ran
  await mark($, toolUseId, 'flagged', flagged)
  return {
    ...ran,
    context: [
      ...(ran.context ?? []),
      [
        'shift-left-guard: this shell command wrote security issues to disk. The files are already changed, so fix them now, before anything else.',
        'Use the Edit tool for the fix so the guard checks it before it lands.',
        ...lessonFor(opts),
        ...notes,
      ].join('\n\n'),
    ],
  }
}

const HOOK_LINE = (blockAt: string) =>
  `node "$(git rev-parse --git-dir)/shift-left-guard/guard-scan.mjs" --block-at=${blockAt} || exit 1`

/** Copies the bundled scanner into .git and wires it as a pre-commit hook. */
async function installHook($: $, blockAt: string): Promise<string> {
  const gitDir = (await git($, ['rev-parse', '--absolute-git-dir']))?.trim()
  if (!gitDir) return 'Not inside a git repository.'

  const scanner = await $.fs.read(`${$.plugin.root}/bin/guard-scan.mjs`)
  await $.fs.write(`${gitDir}/shift-left-guard/guard-scan.mjs`, scanner)
  const line = HOOK_LINE(blockAt === 'never' ? 'critical' : blockAt)

  // Claude Code runs git with core.hooksPath=/dev/null in "command" scope so its
  // own git calls skip hooks. Only a repo/user/system setting means the hooks live elsewhere.
  const hooksPath = (await git($, ['config', '--show-scope', '--get-all', 'core.hooksPath']))
    ?.split('\n')
    .map(l => l.split('\t'))
    .filter(([scope, value]) => scope !== 'command' && value)
    .at(-1)?.[1]
    ?.trim()
  if (hooksPath) {
    return [
      `Scanner copied to ${gitDir}/shift-left-guard/. This repo uses core.hooksPath (${hooksPath}, e.g. husky), so add this line to its pre-commit hook yourself:`,
      '',
      `  ${line}`,
    ].join('\n')
  }

  const hook = `${gitDir}/hooks/pre-commit`
  const existing = await $.fs.read(hook).catch(() => undefined)
  if (existing !== undefined && !existing.includes('shift-left-guard')) {
    return [
      `Scanner copied, but ${hook} already exists and was left alone. Add this line to it:`,
      '',
      `  ${line}`,
    ].join('\n')
  }

  await $.fs.write(hook, `#!/bin/sh\n# shift-left-guard: scans staged changes with the same rules Claude is held to.\n# Skip once with: git commit --no-verify\n${line}\n`)
  await $.process.run(['chmod', '+x', hook])
  return [
    `Pre-commit hook installed: ${hook}`,
    `Every commit in this repo is now scanned (blocking at ${blockAt === 'never' ? 'critical' : blockAt}), whoever wrote the change.`,
    'Skip once with `git commit --no-verify`; remove by deleting the hook file.',
  ].join('\n')
}

const BADGE: Record<Verdict, (ids: string) => [string | undefined, string]> = {
  blocked: ids => ['red', `blocked ${ids}`],
  flagged: ids => ['red', `wrote ${ids}, fixing`],
  fixed: ids => ['green', `fixed ${ids}`],
  warned: ids => ['yellow', `noted ${ids}`],
  'let-through': ids => ['yellow', `let through ${ids}`],
  cloud: () => ['magenta', 'cloud guard'],
  clean: () => [undefined, 'clean'],
}

const ACTION_LABEL: Record<GuardEvent['action'], string> = {
  blocked: '⛔ blocked',
  flagged: '⚠ shell wrote',
  fixed: '✔ fixed',
  warned: '• noted',
  'let-through': '⚠ let through',
  cloud: '☁ cloud',
}

export const register: Register = (on, options) => {
  const blockAt = (options.blockAt ?? 'high') as Severity | 'never'
  const cloudGuard = (options.cloudGuard ?? 'ask') as 'ask' | 'deny' | 'off'
  const opts: Opts = { blockAt, explain: options.explain === true }
  /** Destructive commands the user approved in the guard's own dialog, so the permission check does not ask twice. */
  const approved = new Set<string>()

  const failClosed = { deny: 'shift-left-guard could not check this write, so it was stopped. Try again, or run /guard pause.' }

  on('tool.call', { tool: 'Write' }, ($, e, next) => guard($, opts, e.file_path, e.content, () => next(e), e.tool_use_id)).catch(($, e, next) =>
    next.called ? next(e) : failClosed,
  )

  on('tool.call', { tool: 'Edit' }, async ($, e, next) => {
    const before = await $.fs.read(e.file_path).catch(() => undefined)
    const after = before === undefined ? undefined : applyEdit(before, e.old_string, e.new_string, e.replace_all)
    return guard($, opts, e.file_path, after, () => next(e), e.tool_use_id)
  }).catch(($, e, next) => (next.called ? next(e) : failClosed))

  on('tool.call', { tool: 'Bash' }, async ($, e, next) => {
    const hit = cloudGuard === 'ask' ? destructive(e.command) : undefined
    if (hit !== undefined) {
      const radius = blastRadius(e.command)
      const answer = await $.ui
        .ask(
          [
            `☁ ${hit.reason}${hit.isProd ? ' against PRODUCTION' : ''}`,
            '',
            `  ${e.command.length > 200 ? `${e.command.slice(0, 200)}…` : e.command}`,
            '',
            ...radius.map(r => `${r.label}: ${r.value}`),
            `Undo: ${hit.undo}`,
            '',
            'Run this command?',
          ].join('\n'),
          { header: 'Cloud guard', options: hit.isProd ? ['Cancel', 'Run it'] : ['Run it', 'Cancel'] },
        )
        // Dismissed, or no one to ask: the permission check below still asks.
        .catch(() => undefined)
      if (answer !== undefined && answer !== 'Run it') {
        await record(
          $,
          { at: Date.now(), file: e.command.slice(0, 120), action: 'cloud', findings: [], note: `${hit.reason}: declined by the user` },
          { cloud: 1 },
        )
        await mark($, e.tool_use_id, 'cloud')
        return {
          deny: 'The user declined this destructive command in the shift-left-guard dialog. Do not retry it or work around it; ask the user how they want to proceed.',
        }
      }
      if (answer === 'Run it' && e.tool_use_id !== undefined) approved.add(e.tool_use_id)
    }
    const startedAt = Date.now()
    const ran = await next(e)
    return checkShellWrites($, opts, startedAt, ran, e.tool_use_id)
    // The command already ran, so a failing scan hands Claude its result as is.
  }).catch(($, e, next) => next(e))

  on('tool.check', { tool: 'Bash' }, async ($, e, next) => {
    const verdict = await next(e)
    const command = (e.input as { command?: unknown } | undefined)?.command
    if (cloudGuard === 'off' || verdict.decision === 'deny' || typeof command !== 'string') return verdict

    const hit = destructive(command)
    if (hit === undefined) return verdict

    const where = hit.isProd ? ' against PRODUCTION' : ''
    const isApproved = e.tool_use_id !== undefined && approved.delete(e.tool_use_id)
    if (e.tool_use_id !== undefined) {
      await record(
        $,
        {
          at: Date.now(),
          file: command.slice(0, 120),
          action: 'cloud',
          findings: [],
          note: `${hit.reason}${where} (${isApproved ? 'approved by the user' : cloudGuard})`,
        },
        { cloud: 1 },
      )
      await mark($, e.tool_use_id, 'cloud')
    }
    if (isApproved) return verdict
    return cloudGuard === 'deny'
      ? {
          decision: 'deny',
          reason: `shift-left-guard: ${hit.reason}${where} is not run by Claude. Show the user the exact command and let them run it themselves with \`! <command>\` after review.`,
        }
      : { decision: 'ask', reason: `shift-left-guard: ${hit.reason}${where}. Review before allowing.` }
    // A failing check leaves the engine's own verdict standing.
  }).catch(($, e, next) => next(e))

  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: 'guard',
      description: 'Shift-Left Guard: report, findings pane, rules, pre-commit hook, pause or resume',
      argumentHint: '[report|pane|rules|install-hook|pause|resume]',
    })
    $.ui.status(statusLine(await read($, totals)))
    return next(e)
  })

  on('command.run', { command: 'guard' }, async ($, e) => {
    const arg = e.args.trim().toLowerCase()

    if (arg === 'pause' || arg === 'resume') {
      await update($, isPaused, () => arg === 'pause')
      $.ui.status(arg === 'pause' ? '🛡 paused' : statusLine(await read($, totals)))
      return { text: arg === 'pause' ? 'Shift-Left Guard paused for this session.' : 'Shift-Left Guard is watching again.' }
    }

    if (arg === 'pane') {
      await $.ui.open({ id: PANE, title: 'Shift-Left Guard' })
      return { text: 'Findings pane opened.' }
    }

    if (arg === 'install-hook') {
      return { text: await installHook($, blockAt) }
    }

    if (arg === 'rules') {
      return {
        text: [
          `Shift-Left Guard rules (blocking at ${blockAt}, cloud guard ${cloudGuard}):`,
          ...RULES.map(r => `  ${r.id.padEnd(7)} ${r.severity.padEnd(8)} ${r.title}`),
          '',
          'Silence one line with `# guard:ignore <ID>` on it or the line above.',
        ].join('\n'),
      }
    }

    const t = await read($, totals)
    const list = await read($, events)
    const lifetime = ((await $.store.get(LIFETIME)) ?? {}) as Partial<Totals>
    const paused = await read($, isPaused)
    const lines = list
      .slice(-15)
      .map(ev => {
        const what = ev.findings.map(f => f.id).join(', ')
        return `  ${ev.action.padEnd(11)} ${shortPath(ev.file)}${what ? `  ${what}` : ''}${ev.note ? `  (${ev.note})` : ''}`
      })

    return {
      text: [
        `🛡 Shift-Left Guard${paused ? ' (paused)' : ''}`,
        `This session: ${t.blocked} caught · ${t.fixed} fixed by Claude · ${t.warned} warned · ${t.cloud} cloud commands checked`,
        `All time:     ${lifetime.blocked ?? 0} caught · ${lifetime.fixed ?? 0} fixed · ${lifetime.warned ?? 0} warned · ${lifetime.cloud ?? 0} cloud`,
        '',
        ...(lines.length > 0 ? ['Recent:', ...lines] : ['Nothing caught yet.']),
      ].join('\n'),
    }
  })

  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    const list = await read($, events)
    const last = list.at(-1)
    if (e.props.hasSurvey || last === undefined || (await read($, isBandHidden))) return next(e)

    const { Box, Button, Text } = $.ui.resolve(e)
    const ids = last.findings.map(f => f.id).join(', ')
    const file = shortPath(last.file)
    const [color, text] =
      last.action === 'blocked'
        ? ['red', `blocked ${last.findings.length} issue(s) in ${file} (${ids}), Claude is fixing`]
        : last.action === 'flagged'
          ? ['red', `a shell command wrote ${ids} to ${file}, Claude is fixing`]
        : last.action === 'fixed'
          ? ['green', `Claude fixed ${ids} in ${file}`]
          : last.action === 'let-through'
            ? ['yellow', `let ${file} through with open issues (${ids}), see /guard`]
            : last.action === 'warned'
              ? ['yellow', `noted ${ids} in ${file}`]
              : ['magenta', `${last.note}: ${last.file.slice(0, 60)}`]

    const diff = last.diff
    return (
      <Box flexDirection="column">
        <Box>
          <Text bold>🛡 Shift-Left Guard </Text>
          <Text color={color}>{text} </Text>
          <Button key="report" label="Report" onPress={() => $.ui.open({ id: PANE, title: 'Shift-Left Guard' })} />
          <Text> </Text>
          <Button key="hide" label="Hide" onPress={() => update($, isBandHidden, () => true)} />
        </Box>
        {diff?.minus.map((l, i) => (
          <Text key={`m${i}`} color="red">
            {'   - '}
            {l}
          </Text>
        ))}
        {diff?.plus.map((l, i) => (
          <Text key={`p${i}`} color="green">
            {'   + '}
            {l}
          </Text>
        ))}
      </Box>
    )
  })

  on('ui.render', { component: 'ToolUse' }, async ($, e, next) => {
    const verdict = (await read($, verdicts))[e.props.tool_use_id]
    if (verdict === undefined) return next(e)
    const { Box, Text } = $.ui.resolve(e)
    const ids = verdict.ids.join(', ')
    const [color, label] = BADGE[verdict.action as Verdict](ids)
    return (
      <Box>
        {await next(e)}
        <Text color={color} dimColor={verdict.action === 'clean'}>
          {'  🛡 '}
          {label}
        </Text>
      </Box>
    )
  })

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const { Box, Text } = $.ui.resolve(e)
    const t = await read($, totals)
    const list = (await read($, events)).slice().reverse()
    const room = Math.max(4, (e.viewport?.rows ?? 30) - 6)

    const rows = list.flatMap(ev => [
      <Text key={`h${ev.at}${ev.file}`} bold>
        {ACTION_LABEL[ev.action]} <Text dimColor>{ev.action === 'cloud' ? ev.note : shortPath(ev.file)}</Text>
      </Text>,
      ...ev.findings.map(f => {
        const rule = RULES.find(r => r.id === f.id)
        const where = f.line > 0 ? `:${f.line}` : ''
        return (
          <Box key={`f${ev.at}${ev.file}${f.id}${f.line}`} flexDirection="column" paddingLeft={2}>
            <Text>
              {f.id} {f.severity}
              {where} {f.title}
            </Text>
            {(ev.action === 'blocked' || ev.action === 'flagged' || ev.action === 'let-through') && rule && (
              <Text dimColor>→ {rule.fix}</Text>
            )}
            {opts.explain && EXPLAIN[f.id] && (
              <Text dimColor>
                ? {EXPLAIN[f.id]!.why} (CWE-{EXPLAIN[f.id]!.cwe})
              </Text>
            )}
          </Box>
        )
      }),
    ])

    return (
      <Box flexDirection="column">
        <Text>
          {t.blocked} caught · {t.fixed} fixed · {t.warned} warned · {t.cloud} cloud
        </Text>
        <Text> </Text>
        {rows.length === 0 ? <Text dimColor>Nothing caught yet.</Text> : rows.slice(0, room)}
      </Box>
    )
  })
}
