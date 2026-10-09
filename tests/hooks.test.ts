import { describe, expect, mock, test } from 'claude-code/testing'
import type { On } from 'claude-code'

const WORKFLOW = '/repo/.github/workflows/ci.yml'
const UNSAFE = 'permissions: { contents: read }\njobs:\n  b:\n    steps:\n      - run: echo "${{ github.event.issue.title }}"\n'
const SAFE = 'permissions: { contents: read }\njobs:\n  b:\n    steps:\n      - env:\n          T: ${{ github.event.issue.title }}\n        run: echo "$T"\n'

/** A disk of one directory, and Write/Edit tools that write to it. */
const fakeDisk = (on: On, files: Record<string, string> = {}) => {
  const writes: string[] = []
  mock.store(on)
  on('ui.status', () => ({ value: undefined }))
  on('ui.toast', () => ({ value: undefined }))
  on('ui.render', ($, e) => h($.ui.resolve(e).Box, null) as never)
  on('fs.read', ($, e) => {
    const text = e.path.endsWith('/bin/guard-scan.mjs') ? '// scanner' : files[e.path]
    return text === undefined ? { deny: `ENOENT: ${e.path}` } : { value: text }
  })
  on('tool.call', { tool: 'Write' }, ($, e) => {
    files[e.file_path] = e.content
    writes.push(e.file_path)
    return { result: { type: 'create', filePath: e.file_path, content: e.content } as never }
  })
  on('tool.call', { tool: 'Edit' }, ($, e) => {
    files[e.file_path] = (files[e.file_path] ?? '').replace(e.old_string, e.new_string)
    writes.push(e.file_path)
    return { result: {} as never }
  })
  return { files, writes }
}

describe('write guard', () => {
  test('blocks an injection, then records the fix', async ($, on) => {
    const disk = fakeDisk(on)

    const blocked = await $.tool.call({ tool: 'Write', file_path: WORKFLOW, content: UNSAFE })
    expect(blocked.deny ?? blocked.text ?? '').toContain('GHA003')
    expect(disk.writes).toEqual([])

    const fixed = await $.tool.call({ tool: 'Write', file_path: WORKFLOW, content: SAFE })
    expect(fixed.deny).toBeUndefined()
    expect(disk.writes).toEqual([WORKFLOW])

    const report = await $.command.run({ command: 'guard', args: '' } as never)
    expect(report.text).toContain('This session: 1 caught · 1 fixed by Claude')
  })

  test('lets the same findings through after two retries, with a note', async ($, on) => {
    const disk = fakeDisk(on)
    for (let i = 0; i < 2; i++) {
      const r = await $.tool.call({ tool: 'Write', file_path: WORKFLOW, content: UNSAFE })
      expect(r.deny ?? r.text ?? '').toContain('stopped this write')
    }
    const third = await $.tool.call({ tool: 'Write', file_path: WORKFLOW, content: UNSAFE })
    expect(third.deny).toBeUndefined()
    expect(third.context?.join('\n')).toContain('unresolved issues')
    expect(disk.writes).toEqual([WORKFLOW])
  })

  test('an Edit is judged on the whole file, legacy issues ignored', async ($, on) => {
    const path = '/repo/Dockerfile'
    const disk = fakeDisk(on, { [path]: 'FROM node:latest\nCMD ["node"]\n' })

    const harmless = await $.tool.call({ tool: 'Edit', file_path: path, old_string: 'CMD', new_string: 'EXPOSE 3000\nCMD' })
    expect(harmless.deny).toBeUndefined()

    const leaky = await $.tool.call({ tool: 'Edit', file_path: path, old_string: 'CMD', new_string: 'ENV DB_PASSWORD=hunter2\nCMD' })
    expect(leaky.deny ?? leaky.text ?? '').toContain('DKR003')
    expect(disk.files[path]).not.toContain('hunter2')
  })

  test('lower severities pass with a note to Claude', async ($, on) => {
    fakeDisk(on)
    const r = await $.tool.call({ tool: 'Write', file_path: '/repo/Dockerfile', content: 'FROM node:22\nCMD ["node"]\n' })
    expect(r.deny).toBeUndefined()
    expect(r.context?.join('\n')).toContain('DKR002')
  })

  test('blockAt=low blocks root containers too', { options: { blockAt: 'low' } }, async ($, on) => {
    fakeDisk(on)
    const r = await $.tool.call({ tool: 'Write', file_path: '/repo/Dockerfile', content: 'FROM node:22\nCMD ["node"]\n' })
    expect(r.deny ?? r.text ?? '').toContain('DKR002')
  })

  test('/guard pause lets everything through', async ($, on) => {
    const disk = fakeDisk(on)
    await $.command.run({ command: 'guard', args: 'pause' } as never)
    const r = await $.tool.call({ tool: 'Write', file_path: WORKFLOW, content: UNSAFE })
    expect(r.deny).toBeUndefined()
    expect(disk.writes).toEqual([WORKFLOW])
  })
})

describe('cloud guard', () => {
  test('asks before terraform destroy, leaves plan alone', async ($, on) => {
    on('tool.check', () => ({ decision: 'allow' }))
    const destroy = await $.tool.check({ tool: 'Bash', input: { command: 'terraform destroy -auto-approve' } })
    expect(destroy.decision).toBe('ask')
    const plan = await $.tool.check({ tool: 'Bash', input: { command: 'terraform plan' } })
    expect(plan.decision).toBe('allow')
  })

  test('deny mode refuses and names production', { options: { cloudGuard: 'deny' } }, async ($, on) => {
    on('tool.check', () => ({ decision: 'allow' }))
    const r = await $.tool.check({ tool: 'Bash', input: { command: 'gcloud sql instances delete db-prod' } })
    expect(r.decision).toBe('deny')
    expect(r.reason).toContain('PRODUCTION')
  })
})

/** Answers the guard's dialog as the user would. */
const answerDialog = (on: On, label: string) => {
  const asked: string[] = []
  on('tool.call', { tool: 'AskUserQuestion' }, ($, e) => {
    const question = e.questions[0]!.question
    asked.push(question)
    return { result: { questions: e.questions, answers: { [question]: label } } as never }
  })
  return asked
}

describe('blast-radius dialog', () => {
  test('names the target, and an approval is not asked again by the permission check', async ($, on) => {
    fakeDisk(on)
    const asked = answerDialog(on, 'Run it')
    on('tool.check', () => ({ decision: 'allow' }))
    on('tool.call', { tool: 'Bash' }, () => ({ result: { stdout: '', stderr: '', interrupted: false } as never }))
    const command = 'gcloud sql instances delete db --project=acme-prod'
    const r = await $.tool.call({ tool: 'Bash', command, tool_use_id: 'tu-1' } as never)
    expect(asked[0]).toContain('PRODUCTION')
    expect(asked[0]).toContain('project: acme-prod')
    expect(r.deny).toBeUndefined()
    const approved = await $.tool.check({ tool: 'Bash', input: { command }, tool_use_id: 'tu-1' } as never)
    expect(approved.decision).toBe('allow')
    const other = await $.tool.check({ tool: 'Bash', input: { command }, tool_use_id: 'tu-2' } as never)
    expect(other.decision).toBe('ask')
  })

  test('a declined command never runs', async ($, on) => {
    fakeDisk(on)
    answerDialog(on, 'Cancel')
    let ran = 0
    on('tool.call', { tool: 'Bash' }, () => {
      ran += 1
      return { result: { stdout: '', stderr: '', interrupted: false } as never }
    })
    const r = await $.tool.call(bash('terraform destroy -auto-approve'))
    expect(r.deny ?? r.text ?? '').toContain('declined')
    expect(ran).toBe(0)
  })
})

describe('transcript row', () => {
  test('marks a blocked and a clean write on every surface', async ($, on) => {
    fakeDisk(on)
    on('ui.render', { component: 'ToolUse' }, ($, e) => h($.ui.resolve(e).Text, null, `Write(${e.props.tool})`) as never)
    await $.tool.call({ tool: 'Write', file_path: WORKFLOW, content: UNSAFE, tool_use_id: 'tu-bad' } as never)
    await $.tool.call({ tool: 'Write', file_path: '/repo/README.md', content: 'hi', tool_use_id: 'tu-ok' } as never)
    for (const surface of ['terminal', 'desktop'] as const) {
      const row = (id: string) =>
        $.ui.mount({ plugin: 'shift-left-guard', surface, component: 'ToolUse', props: { tool_use_id: id, tool: 'Write' } as never })
      const bad = await row('tu-bad')
      expect(await bad.find({ type: 'Text', text: /blocked GHA003/ })).toBeDefined()
      await bad.unmount()
      const ok = await row('tu-ok')
      expect(await ok.find({ type: 'Text', text: /clean/ })).toBeDefined()
      await ok.unmount()
    }
  })
})

describe('band', () => {
  test('shows the last interception on every surface', async ($, on) => {
    fakeDisk(on)
    for (const surface of ['terminal', 'desktop'] as const) {
      await $.tool.call({ tool: 'Write', file_path: WORKFLOW, content: UNSAFE })
      const ui = await $.ui.mount({
        plugin: 'shift-left-guard',
        surface,
        component: 'AbovePrompt',
        props: { hasSurvey: false } as never,
      })
      expect(await ui.find({ type: 'Text', text: /blocked 1 issue/ })).toBeDefined()
      await ui.press({ key: 'hide' })
      expect(await ui.find({ type: 'Text', text: /blocked/ })).toBeUndefined()
      await $.tool.call({ tool: 'Write', file_path: WORKFLOW, content: SAFE })
      expect(await ui.find({ type: 'Text', text: /Claude fixed GHA003/ })).toBeDefined()
      expect(await ui.find({ type: 'Text', text: /- .*run: echo "\$\{\{ github\.event\.issue\.title/ })).toBeDefined()
      expect(await ui.find({ type: 'Text', text: /\+ .*T: \$\{\{ github\.event\.issue\.title/ })).toBeDefined()
      await ui.unmount()
    }
  })
})

/** A repo at /repo whose git answers from the in-memory disk. */
const fakeRepo = (on: On, files: Record<string, string>, head: Record<string, string> = {}, hooksPath = '', remote = '') => {
  const disk = fakeDisk(on, files)
  const runs: string[][] = []
  on('fs.stat', ($, e) =>
    files[e.path] === undefined
      ? { deny: 'ENOENT' }
      : { value: { kind: 'file', size: files[e.path]!.length, mtimeMs: Date.now(), isLink: false } as never },
  )
  on('fs.write', ($, e) => {
    files[e.path] = e.text
    return { value: undefined }
  })
  on('process.run', ($, e) => {
    const argv = e.argv as readonly string[]
    runs.push([...argv])
    const ok = (stdout: string) => ({ value: { exitCode: 0, stdout, stderr: '', isStdoutTruncated: false, isStderrTruncated: false } })
    const fail = { value: { exitCode: 1, stdout: '', stderr: '', isStdoutTruncated: false, isStderrTruncated: false } }
    const [cmd, a, b] = argv
    if (cmd !== 'git') return ok('')
    if (a === 'rev-parse' && b === '--show-toplevel') return ok('/repo\n')
    if (a === 'rev-parse' && b === '--absolute-git-dir') return ok('/repo/.git\n')
    if (a === 'remote') return remote ? ok(`${remote}\n`) : fail
    if (a === 'config') return ok(`command\t/dev/null\n${hooksPath ? `local\t${hooksPath}\n` : ''}`)
    if (a === 'ls-files') {
      const rels = Object.keys(files).filter(f => f.startsWith('/repo/') && !f.startsWith('/repo/.git/')).map(f => f.slice(6))
      return ok(rels.join('\0'))
    }
    if (a === 'status') {
      const rels = Object.keys(files).filter(f => f.startsWith('/repo/') && !f.startsWith('/repo/.git/')).map(f => f.slice(6))
      return ok(rels.map(r => `${head[r] === undefined ? 'A ' : ' M'} ${r}`).join('\0'))
    }
    if (a === 'show') {
      const rel = (b ?? '').replace(/^HEAD:/, '')
      return head[rel] === undefined ? fail : ok(head[rel]!)
    }
    return fail
  })
  return { ...disk, runs }
}

const bash = (command: string) => ({ tool: 'Bash' as const, command })

describe('shell writes', () => {
  test('a heredoc that writes an injection is flagged right after the command', async ($, on) => {
    const files: Record<string, string> = {}
    fakeRepo(on, files)
    let writes = UNSAFE
    on('tool.call', { tool: 'Bash' }, () => {
      files['/repo/.github/workflows/ci.yml'] = writes
      return { result: { stdout: '', stderr: '', interrupted: false } as never }
    })
    const r = await $.tool.call(bash('cat > .github/workflows/ci.yml <<EOF ...'))
    expect(r.context?.join('\n')).toContain('GHA003')
    expect(r.context?.join('\n')).toContain('already changed')

    writes = SAFE
    await $.tool.call(bash('sed -i ... .github/workflows/ci.yml'))
    const report = await $.command.run({ command: 'guard', args: '' } as never)
    expect(report.text).toContain('1 caught · 1 fixed')
  })

  test('issues already in HEAD are not reported', async ($, on) => {
    const files: Record<string, string> = { '/repo/.github/workflows/ci.yml': UNSAFE }
    fakeRepo(on, files, { '.github/workflows/ci.yml': UNSAFE })
    on('tool.call', { tool: 'Bash' }, () => ({ result: { stdout: '', stderr: '', interrupted: false } as never }))
    const r = await $.tool.call(bash('ls'))
    expect(r.context ?? []).toEqual([])
  })

  test('a failing scan keeps the command result and does not run it twice', async ($, on) => {
    fakeDisk(on, { '/repo/a.yml': UNSAFE })
    on('process.run', () => ({
      value: { exitCode: 0, stdout: '/repo\0a.yml', stderr: '', isStdoutTruncated: false, isStderrTruncated: false },
    }))
    on('fs.stat', () => ({ value: null as never }))
    let runs = 0
    on('tool.call', { tool: 'Bash' }, () => {
      runs += 1
      return { result: { stdout: 'done', stderr: '', interrupted: false } as never }
    })
    const r = await $.tool.call(bash('ls'))
    expect(r.deny).toBeUndefined()
    expect((r.result as { stdout?: string } | undefined)?.stdout).toBe('done')
    expect(runs).toBe(1)
  })
})

describe('commit gate', () => {
  test('a finding a shell command wrote blocks Claude committing until the file is fixed', async ($, on) => {
    const files: Record<string, string> = {}
    fakeRepo(on, files)
    on('tool.check', () => ({ decision: 'allow' }))
    on('tool.call', { tool: 'Bash' }, () => {
      files['/repo/.github/workflows/ci.yml'] = UNSAFE
      return { result: { stdout: '', stderr: '', interrupted: false } as never }
    })
    const r = await $.tool.call(bash('cp templates/ci.yml .github/workflows/'))
    expect(r.context?.join('\n')).toContain('does not cover writing a vulnerability')

    const commit = await $.tool.check({ tool: 'Bash', input: { command: 'git add -A && git commit -m "add ci"' } })
    expect(commit.decision).toBe('deny')
    expect(commit.reason).toContain('.github/workflows/ci.yml: GHA003')
    expect((await $.tool.check({ tool: 'Bash', input: { command: 'git status' } })).decision).toBe('allow')

    files['/repo/.github/workflows/ci.yml'] = SAFE
    expect((await $.tool.check({ tool: 'Bash', input: { command: 'git commit -m "add ci"' } })).decision).toBe('allow')
  })

  test('copying and committing in one command is split, so the guard sees the file in between', async ($, on) => {
    fakeRepo(on, {})
    on('tool.check', () => ({ decision: 'allow' }))
    const r = await $.tool.check({ tool: 'Bash', input: { command: 'cp templates/ci.yml .github/workflows/ && git add -A && git commit -m ci' } })
    expect(r.decision).toBe('deny')
    expect(r.reason).toContain('separate command')
  })

  test('a blocked Write never reached the disk, so it does not block committing', async ($, on) => {
    fakeRepo(on, {})
    on('tool.check', () => ({ decision: 'allow' }))
    const r = await $.tool.call({ tool: 'Write', file_path: WORKFLOW, content: UNSAFE })
    expect(r.deny ?? '').toContain('GHA003')
    expect((await $.tool.check({ tool: 'Bash', input: { command: 'git push' } })).decision).toBe('allow')
  })

  test('/guard pause lifts the gate', async ($, on) => {
    const files: Record<string, string> = {}
    fakeRepo(on, files)
    on('tool.check', () => ({ decision: 'allow' }))
    on('tool.call', { tool: 'Bash' }, () => {
      files['/repo/.github/workflows/ci.yml'] = UNSAFE
      return { result: { stdout: '', stderr: '', interrupted: false } as never }
    })
    await $.tool.call(bash('cp a b'))
    await $.command.run({ command: 'guard', args: 'pause' } as never)
    expect((await $.tool.check({ tool: 'Bash', input: { command: 'gh pr create --fill' } })).decision).toBe('allow')
  })
})

describe('repository config', () => {
  test('.guard.json adds team rules and switches built-ins off for Write', async ($, on) => {
    const files: Record<string, string> = {
      '/repo/.guard.json': JSON.stringify({
        rules: [{ id: 'ACME001', severity: 'high', title: 'Internal registry only', fix: 'Use registry.acme.io', pattern: '^FROM (?!registry\\.acme\\.io)' }],
        disable: ['GHA003'],
      }),
    }
    const disk = fakeRepo(on, files)
    const injected = await $.tool.call({ tool: 'Write', file_path: WORKFLOW, content: UNSAFE })
    expect(injected.deny).toBeUndefined()
    const docker = await $.tool.call({ tool: 'Write', file_path: '/repo/Dockerfile', content: 'FROM node:22\nUSER app\n' })
    expect(docker.deny ?? '').toContain('ACME001')
    expect(disk.writes).toEqual([WORKFLOW])
  })

  test('a new .env that git does not ignore is stopped', async ($, on) => {
    const disk = fakeRepo(on, {})
    const r = await $.tool.call({ tool: 'Write', file_path: '/repo/.env', content: 'DEBUG=1\n' })
    expect(r.deny ?? '').toContain('SEC004')
    expect(disk.writes).toEqual([])
  })
})

describe('audit', () => {
  test('scores the repository and hands the fix to the prompt and the pane', async ($, on) => {
    const files: Record<string, string> = {
      '/repo/.github/workflows/ci.yml': UNSAFE,
      '/repo/Dockerfile': 'FROM node:latest\nUSER app\n',
      '/repo/README.md': '# hi\n',
    }
    fakeRepo(on, files)
    on('ui.open', () => ({ value: { isPlaced: true } as never }))
    const filled: string[] = []
    on('prompt.fill', ($, e) => {
      filled.push(e.text)
      return { isFilled: true } as never
    })
    const r = await $.command.run({ command: 'guard', args: 'audit' } as never)
    expect(r.text).toContain('Security score: 87/100 · grade B')
    expect(r.text).toContain('GHA003')
    const fix = await $.command.run({ command: 'guard', args: 'fix' } as never)
    expect(fix.text).toContain('Press Enter')
    expect(filled[0]).toContain('.github/workflows/ci.yml:5 GHA003 (high)')
    const badge = await $.command.run({ command: 'guard', args: 'badge' } as never)
    expect(badge.text).toContain('shift--left--guard-B-green')
    expect(files['/repo/.github/shift-left-guard.json']).toBeUndefined()

    for (const surface of ['terminal', 'desktop'] as const) {
      const pane = await $.ui.mount({
        plugin: 'shift-left-guard',
        surface,
        component: 'Pane',
        requestId: 'shift-left-guard-report',
        props: {} as never,
      } as never)
      expect(await pane.find({ type: 'Text', text: /Grade B · 87\/100/ })).toBeDefined()
      await pane.press({ key: 'fix' })
      await pane.unmount()
    }
    expect(filled.length).toBe(3)
  })
})

describe('live badge', () => {
  test('/guard badge writes the badge file, and the next audit keeps it current', async ($, on) => {
    const files: Record<string, string> = { '/repo/Dockerfile': 'FROM node:latest\nUSER app\n' }
    fakeRepo(on, files, {}, '', 'git@github.com:acme/api.git')
    on('ui.open', () => ({ value: { isPlaced: true } as never }))
    const badge = await $.command.run({ command: 'guard', args: 'badge' } as never)
    expect(badge.text).toContain('img.shields.io/endpoint?url=')
    expect(badge.text).toContain(encodeURIComponent('acme/api/main/.github/shift-left-guard.json'))
    expect(JSON.parse(files['/repo/.github/shift-left-guard.json']!).message).toBe('A · 97/100')
    files['/repo/Dockerfile'] = 'FROM node:latest\nENV API_KEY=abc123\n'
    const audit = await $.command.run({ command: 'guard', args: 'audit' } as never)
    expect(audit.text).toContain('Badge updated')
    expect(JSON.parse(files['/repo/.github/shift-left-guard.json']!).message).toBe('B · 84/100')
  })
})

describe('install-hook', () => {
  test('writes the scanner and a pre-commit hook', async ($, on) => {
    const files: Record<string, string> = {}
    const repo = fakeRepo(on, files)
    const r = await $.command.run({ command: 'guard', args: 'install-hook' } as never)
    expect(r.text).toContain('Pre-commit hook installed')
    expect(files['/repo/.git/shift-left-guard/guard-scan.mjs']).toBe('// scanner')
    expect(files['/repo/.git/hooks/pre-commit']).toContain('--block-at=high')
    expect(repo.runs).toContainEqual(['chmod', '+x', '/repo/.git/hooks/pre-commit'])
  })

  test('leaves a foreign pre-commit hook alone', async ($, on) => {
    const files: Record<string, string> = { '/repo/.git/hooks/pre-commit': '#!/bin/sh\nnpx lint-staged\n' }
    fakeRepo(on, files)
    const r = await $.command.run({ command: 'guard', args: 'install-hook' } as never)
    expect(r.text).toContain('already exists')
    expect(files['/repo/.git/hooks/pre-commit']).toBe('#!/bin/sh\nnpx lint-staged\n')
  })

  test('tells husky users what to add', async ($, on) => {
    const files: Record<string, string> = {}
    fakeRepo(on, files, {}, '.husky/_')
    const r = await $.command.run({ command: 'guard', args: 'install-hook' } as never)
    expect(r.text).toContain('core.hooksPath')
    expect(files['/repo/.git/hooks/pre-commit']).toBeUndefined()
  })
})

describe('report pane', () => {
  test('lists findings with their fix', async ($, on) => {
    fakeDisk(on)
    await $.tool.call({ tool: 'Write', file_path: WORKFLOW, content: UNSAFE })
    for (const surface of ['terminal', 'desktop'] as const) {
      const ui = await $.ui.mount({
        plugin: 'shift-left-guard',
        surface,
        component: 'Pane',
        requestId: 'shift-left-guard-report',
        props: {} as never,
      } as never)
      expect(await ui.find({ type: 'Text', text: /GHA003 high:5 Script injection/ })).toBeDefined()
      expect(await ui.find({ type: 'Text', text: /Move the expression into `env:`/ })).toBeDefined()
      await ui.unmount()
    }
  })
})
