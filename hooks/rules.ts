import type { Finding, Severity } from '../types'

export type FileKind = 'workflow' | 'dockerfile' | 'terraform' | 'kubernetes' | 'other'

export const SEVERITIES: readonly Severity[] = ['low', 'medium', 'high', 'critical']

export const rank = (severity: Severity | 'never'): number =>
  severity === 'never' ? Infinity : SEVERITIES.indexOf(severity)

type Rule = {
  id: string
  kind: FileKind | 'any'
  severity: Severity
  title: string
  fix: string
  /** Line-level rules: the line and its 0-based index; return true to flag. */
  line?: (line: string, ctx: LineContext) => boolean
  /** File-level rules: return the 0-based line to flag, or -1. */
  file?: (lines: readonly string[]) => number
}

type LineContext = { inRunBlock: boolean; text: string; lines: readonly string[]; index: number }

const FULL_SHA = /^[0-9a-f]{40}$/

const INJECTABLE =
  /\$\{\{\s*(github\.head_ref|github\.event\.(issue|pull_request|comment|review|review_comment|discussion|discussion_comment|head_commit|commits|pages)\b[^}]*\.(title|body|head_ref|ref|label|name|email|message|page_name|default_branch))\s*\}\}/

const SECRET_NAME = /(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)/i

const isComment = (line: string) => /^\s*#/.test(line)

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
    title: 'Script injection: untrusted event data in run:',
    fix: 'Move the expression into `env:` (e.g. `env: TITLE: ${{ github.event.issue.title }}`) and use `"$TITLE"` in the script.',
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
    title: 'Secret interpolated directly into run:',
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
      const users = lines.map((l, i) => [i, /^\s*USER\s+(\S+)/i.exec(l)?.[1]] as const).filter(([, u]) => u)
      const last = users.at(-1)
      if (last === undefined) {
        const from = lines.findLastIndex(l => /^\s*FROM\s/i.test(l))
        return from
      }
      return last[1] === 'root' || last[1] === '0' || last[1]?.startsWith('0:') ? last[0] : -1
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
      return m !== null && SECRET_NAME.test(m[2] ?? '') && m[3] !== undefined && m[3].trim() !== ''
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
    line: line => /\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b/.test(line),
  },

  // Terraform: GCP, AWS, Azure
  {
    id: 'TF001',
    kind: 'terraform',
    severity: 'high',
    title: 'Open to the whole internet (0.0.0.0/0)',
    fix: 'Restrict source ranges to known CIDRs, a load balancer or IAP (GCP: 35.235.240.0/20), or use private networking.',
    line: line => /(0\.0\.0\.0\/0|::\/0)/.test(line) && !/egress|destination/i.test(line) && !isComment(line),
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
    severity: 'high',
    title: 'Database reachable from a public IP',
    fix: 'Use private IP / private endpoints. GCP Cloud SQL: `ipv4_enabled = false` + `private_network`; AWS RDS: `publicly_accessible = false`.',
    line: line => !isComment(line) && /(publicly_accessible|ipv4_enabled)\s*=\s*true/.test(line),
  },
  {
    id: 'TF005',
    kind: 'terraform',
    severity: 'critical',
    title: 'Hard-coded secret in Terraform',
    fix: 'Reference a secret manager (`google_secret_manager_secret_version`, `aws_secretsmanager_secret_version`, `azurerm_key_vault_secret`) or a `sensitive = true` variable; generate passwords with `random_password`.',
    line: line =>
      !isComment(line) &&
      /^\s*\w*(password|secret|token|api_key|private_key|access_key)\w*\s*=\s*"(?!\$\{)[^"]{4,}"/i.test(line) &&
      !/(_name|_id|_arn|_version|_ref)\s*=/.test(line),
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
    line: line => {
      const m = /^\s*-?\s*image:\s*['"]?([^'"\s]+)/.exec(line)
      const image = m?.[1]
      if (image === undefined || image.includes('@sha256:') || image.includes('{{')) return false
      const tag = image.split('/').pop()!.split(':')[1]
      return tag === undefined || tag === 'latest'
    },
  },

  // Secrets: every file
  {
    id: 'SEC001',
    kind: 'any',
    severity: 'critical',
    title: 'Private key',
    fix: 'Remove the key from the file, rotate it, and load it from a secret manager or a mounted secret at runtime.',
    line: line => /-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY( BLOCK)?-----/.test(line),
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
]

const base = (path: string) => path.split(/[\\/]/).pop() ?? path

export const classify = (path: string, text: string): FileKind => {
  const name = base(path)
  if (/\.github[\\/](workflows[\\/][^\\/]+|actions[\\/].+[\\/]action)\.ya?ml$/.test(path)) return 'workflow'
  if (/^(Dockerfile|Containerfile)(\..+)?$|\.(dockerfile|containerfile)$/i.test(name)) return 'dockerfile'
  if (/\.tf$/.test(name)) return 'terraform'
  if (/\.ya?ml$/.test(name) && /^apiVersion:/m.test(text) && /^kind:/m.test(text)) return 'kubernetes'
  return 'other'
}

const SKIP_SECRETS = /\.(lock|min\.js|map|svg|png|jpe?g|gif|pdf)$|(^|[\\/])(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|poetry\.lock)$/

/** `# guard:ignore` or `# guard:ignore GHA001` on the line itself or the line above. */
const isIgnored = (lines: readonly string[], index: number, id: string) =>
  [lines[index], lines[index - 1]].some(l => {
    const m = /guard:ignore(?:\s+([A-Z0-9, ]+))?/.exec(l ?? '')
    return m !== null && (m[1] === undefined || m[1].split(/[\s,]+/).includes(id))
  })

export const scan = (path: string, text: string): Finding[] => {
  const kind = classify(path, text)
  const lines = text.split(/\r?\n/)
  const findings: Finding[] = []
  const rules = RULES.filter(r => r.kind === kind || (r.kind === 'any' && !SKIP_SECRETS.test(path)))

  const add = (rule: Rule, index: number) => {
    if (isIgnored(lines, index, rule.id)) return
    findings.push({
      id: rule.id,
      severity: rule.severity,
      title: rule.title,
      fix: rule.fix,
      line: index + 1,
      snippet: (lines[index] ?? '').trim().slice(0, 160),
    })
  }

  let runIndent = -1
  lines.forEach((line, index) => {
    const indent = line.length - line.trimStart().length
    const run = /^(\s*)(-\s*)?run:\s*(.*)$/.exec(line)
    let inRunBlock = false
    if (run) {
      inRunBlock = true
      runIndent = /^[|>]/.test(run[3] ?? '') ? indent : -1
    } else if (runIndent >= 0) {
      if (line.trim() === '' || indent > runIndent) inRunBlock = true
      else runIndent = -1
    }
    for (const rule of rules) {
      if (rule.line?.(line, { inRunBlock, text, lines, index })) add(rule, index)
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
const SECRET_RULES = new Set(['SEC001', 'SEC002', 'DKR003', 'TF005'])

/** Keeps the first 3 characters of each value and masks the rest. */
export const mask = (line: string) =>
  line
    .replace(/([=:]\s*["']?)([^"'\s,;)]{4,})/g, (_, lead: string, value: string) => `${lead}${value.slice(0, 3)}****`)
    .replace(/\b([A-Za-z0-9_-]{3})[A-Za-z0-9_\-+/]{12,}/g, '$1****')

export const formatFindings = (path: string, findings: readonly Finding[]) =>
  findings
    .map(f => {
      const shown = SECRET_RULES.has(f.id) ? mask(f.snippet) : f.snippet
      return `${ICON[f.severity]} ${f.id} [${f.severity}] ${base(path)}:${f.line}: ${f.title}\n   ${shown}\n   fix: ${f.fix}`
    })
    .join('\n')

// Destructive cloud / cluster commands for the Bash guard.
const DESTRUCTIVE: readonly [RegExp, string][] = [
  [/\bterraform\s+(destroy\b|apply\b.*-auto-approve|state\s+rm\b|force-unlock\b)/, 'Terraform change without a reviewed plan'],
  [/\b(tofu)\s+(destroy\b|apply\b.*-auto-approve)/, 'OpenTofu change without a reviewed plan'],
  [/\bgcloud\b.*\s(delete|remove-iam-policy-binding)\b/, 'gcloud delete'],
  [/\bgcloud\b.*add-iam-policy-binding\b.*roles\/(owner|editor)\b/, 'gcloud grants owner/editor'],
  [/\b(gsutil\s+(-m\s+)?rm\s+.*-r|gcloud\s+storage\s+rm\s+.*(-r|--recursive))/, 'recursive bucket delete'],
  [/\baws\b.*\s(delete-[\w-]+|terminate-instances|rb|deregister-[\w-]+)\b/, 'aws delete'],
  [/\baws\s+s3\s+rm\b.*--recursive/, 'recursive S3 delete'],
  [/\baws\s+iam\s+attach-\w+-policy\b.*AdministratorAccess/, 'aws grants AdministratorAccess'],
  [/\baz\b.*\s(delete|purge)\b/, 'az delete'],
  [/\bkubectl\b.*\sdelete\s+(ns|namespace|namespaces|pv|pvc|crd|node|nodes|all)\b|\bkubectl\b.*\sdelete\b.*--all\b/, 'kubectl bulk delete'],
  [/\bhelm\s+(uninstall|delete)\b/, 'helm uninstall'],
  [/\bdocker\s+(system|volume)\s+prune\b.*(-a|--all|--volumes|-f)/, 'docker prune of volumes/images'],
]

export const destructive = (command: string): { reason: string; isProd: boolean } | undefined => {
  const hit = DESTRUCTIVE.find(([re]) => re.test(command))
  if (hit === undefined) return undefined
  return { reason: hit[1], isProd: /\bprod(uction)?\b|-prd\b|_prod\b/i.test(command) }
}
