import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register, ToolCallResult } from 'claude-code'

import type { Finding, GuardEvent, Severity, Totals } from '../types'
import { RULES, applyEdit, destructive, formatFindings, introduced, rank, scan } from './rules'

const events = atom({ plugin: 'shift-left-guard', key: 'events' } as const, [])
const totals = atom({ plugin: 'shift-left-guard', key: 'totals' } as const, { blocked: 0, warned: 0, fixed: 0, cloud: 0 })
const pending = atom({ plugin: 'shift-left-guard', key: 'pending' } as const, {})
const isPaused = atom({ plugin: 'shift-left-guard', key: 'isPaused' } as const, false)
const isBandHidden = atom({ plugin: 'shift-left-guard', key: 'isBandHidden' } as const, false)

const LIFETIME = 'lifetime'
const MAX_ATTEMPTS = 2
const PANE = 'shift-left-guard-report'
const MAX_SHELL_FILES = 40
const MAX_FILE_BYTES = 1_000_000

type $ = EngineInterface

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

/** Judges the file as it will stand after the call; answers the call. */
async function guard(
  $: $,
  blockAt: Severity | 'never',
  path: string,
  after: string | undefined,
  run: () => Promise<ToolCallResult>,
): Promise<ToolCallResult> {
  if (after === undefined || (await read($, isPaused))) return run()

  const before = await $.fs.read(path).catch(() => '')
  const found = introduced(scan(path, before), scan(path, after))
  const blocking = found.filter(f => rank(f.severity) >= rank(blockAt))
  const warnings = found.filter(f => rank(f.severity) < rank(blockAt))
  const open = (await read($, pending))[path]

  if (blocking.length > 0) {
    const key = keyOf(blocking)
    const attempts = open?.key === key ? open.attempts + 1 : 1

    if (attempts <= MAX_ATTEMPTS) {
      await update($, pending, p => ({ ...p, [path]: { ids: blocking.map(f => f.id), attempts, key } }))
      await record($, { at: Date.now(), file: path, action: 'blocked', findings: brief(blocking) }, { blocked: blocking.length })
      if (blocking.some(f => f.severity === 'critical')) {
        $.ui.toast(`🛡 Blocked a critical issue in ${shortPath(path)}: ${blocking[0]?.title}`)
      }
      return {
        deny: [
          `shift-left-guard stopped this write: it would introduce ${blocking.length} security issue(s) in ${path}.`,
          formatFindings(path, blocking),
          'Fix these and write the file again. Keep the rest of your change as it was.',
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
    const ran = await run()
    return ran.deny === undefined && !ran.isError
      ? {
          ...ran,
          context: [
            ...(ran.context ?? []),
            `shift-left-guard let this write through with unresolved issues. Tell the user about them:\n${formatFindings(path, blocking)}`,
          ],
        }
      : ran
  }

  const ran = await run()
  if (ran.deny !== undefined || ran.isError) return ran

  if (open !== undefined) {
    await update($, pending, ({ [path]: _, ...rest }) => rest)
    const fixed = RULES.filter(r => open.ids.includes(r.id)).map(r => ({ id: r.id, severity: r.severity, title: r.title, line: 0 }))
    await record($, { at: Date.now(), file: path, action: 'fixed', findings: fixed }, { fixed: open.ids.length })
  }

  if (warnings.length === 0) return ran

  await record($, { at: Date.now(), file: path, action: 'warned', findings: brief(warnings) }, { warned: warnings.length })
  return {
    ...ran,
    context: [
      ...(ran.context ?? []),
      `shift-left-guard noticed lower-severity issues in ${path}. Fix them if it fits the task, otherwise mention them to the user:\n${formatFindings(path, warnings)}`,
    ],
  }
}

const git = async ($: $, args: readonly string[], cwd?: string) => {
  const ran = await $.process.run(['git', ...args], { cwd, timeoutMs: 10_000 }).catch(() => undefined)
  return ran?.exitCode === 0 ? ran.stdout : undefined
}

/**
 * After a shell command: scans the files it changed (anything git sees as
 * modified or new, touched since the command started) against HEAD, and
 * hands Claude what the command introduced. The write already happened, so
 * this cannot refuse it: it records the findings and asks for a fix.
 */
async function checkShellWrites(
  $: $,
  blockAt: Severity | 'never',
  startedAt: number,
  ran: ToolCallResult,
): Promise<ToolCallResult> {
  if (ran.deny !== undefined || (await read($, isPaused))) return ran

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
    const found = introduced(scan(path, before), scan(path, after))
    const blocking = found.filter(f => rank(f.severity) >= rank(blockAt))

    if (blocking.length > 0) {
      await update($, pending, p => ({ ...p, [path]: { ids: blocking.map(f => f.id), attempts: 1, key: keyOf(blocking) } }))
      await record($, { at: Date.now(), file: path, action: 'flagged', findings: brief(blocking) }, { blocked: blocking.length })
      if (blocking.some(f => f.severity === 'critical')) {
        $.ui.toast(`🛡 A shell command wrote a critical issue to ${shortPath(path)}: ${blocking[0]?.title}`)
      }
      notes.push(formatFindings(path, blocking))
    } else if (open[path] !== undefined) {
      const ids = open[path]?.ids ?? []
      await update($, pending, ({ [path]: _, ...rest }) => rest)
      const fixed = RULES.filter(r => ids.includes(r.id)).map(r => ({ id: r.id, severity: r.severity, title: r.title, line: 0 }))
      await record($, { at: Date.now(), file: path, action: 'fixed', findings: fixed }, { fixed: ids.length })
    }
  }

  if (notes.length === 0) return ran
  return {
    ...ran,
    context: [
      ...(ran.context ?? []),
      [
        'shift-left-guard: this shell command wrote security issues to disk. The files are already changed, so fix them now, before anything else.',
        'Use the Edit tool for the fix so the guard checks it before it lands.',
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

  const failClosed = { deny: 'shift-left-guard could not check this write, so it was stopped. Try again, or run /guard pause.' }

  on('tool.call', { tool: 'Write' }, ($, e, next) => guard($, blockAt, e.file_path, e.content, () => next(e))).catch(($, e, next) =>
    next.called ? next(e) : failClosed,
  )

  on('tool.call', { tool: 'Edit' }, async ($, e, next) => {
    const before = await $.fs.read(e.file_path).catch(() => undefined)
    const after = before === undefined ? undefined : applyEdit(before, e.old_string, e.new_string, e.replace_all)
    return guard($, blockAt, e.file_path, after, () => next(e))
  }).catch(($, e, next) => (next.called ? next(e) : failClosed))

  on('tool.call', { tool: 'Bash' }, async ($, e, next) => {
    const startedAt = Date.now()
    const ran = await next(e)
    return checkShellWrites($, blockAt, startedAt, ran)
    // The command already ran, so a failing scan hands Claude its result as is.
  }).catch(($, e, next) => next(e))

  on('tool.check', { tool: 'Bash' }, async ($, e, next) => {
    const verdict = await next(e)
    const command = (e.input as { command?: unknown } | undefined)?.command
    if (cloudGuard === 'off' || verdict.decision === 'deny' || typeof command !== 'string') return verdict

    const hit = destructive(command)
    if (hit === undefined) return verdict

    const where = hit.isProd ? ' against PRODUCTION' : ''
    if (e.tool_use_id !== undefined) {
      await record(
        $,
        { at: Date.now(), file: command.slice(0, 120), action: 'cloud', findings: [], note: `${hit.reason}${where} (${cloudGuard})` },
        { cloud: 1 },
      )
    }
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

    return (
      <Box>
        <Text bold>🛡 Shift-Left Guard </Text>
        <Text color={color}>{text} </Text>
        <Button key="report" label="Report" onPress={() => $.ui.open({ id: PANE, title: 'Shift-Left Guard' })} />
        <Text> </Text>
        <Button key="hide" label="Hide" onPress={() => update($, isBandHidden, () => true)} />
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
