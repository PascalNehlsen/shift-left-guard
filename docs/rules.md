# Rules

[← README](../README.md) · [Configuration](configuration.md) · [CI](ci.md)

## What is checked when

| Who writes | How | Checked |
|---|---|---|
| Claude | `Write` / `Edit` tool | ✅ before the write, can block |
| Claude | Bash (`sed -i`, `cat >`, scripts …) | ✅ right after the command, Claude must fix |
| You | your editor | ✅ at `git commit`, with `/guard install-hook` |
| Anyone | CI | ✅ with `guard-scan.mjs --all` ([CI](ci.md)) |

Only the changed file is scanned, and only what the change introduces is reported. A file such as `abc.yml` gets the full rule set when it is a workflow (`.github/workflows/`) or a Kubernetes manifest (`apiVersion:` + `kind:`). Any other file is checked for secrets and hidden Unicode only.

| File | Rule set |
|---|---|
| `.github/workflows/*.yml`, `action.yml`, and any YAML with `on:` + `jobs:` + `runs-on:` (workflow templates) | GHA |
| `Dockerfile*`, `*.dockerfile`, `Containerfile` | DKR |
| `*.tf` | TF |
| Kubernetes manifests, Helm `charts/**/values*.yaml` | K8S |
| `compose.yml`, `docker-compose*.yml` | CMP |
| `package.json` | NPM |
| `.claude/settings*.json`, `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `hooks/hooks.json` | AGT001–004, AGT007 |
| `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `SKILL.md`, `.claude/commands/*.md`, `.claude/agents/*.md`, `.cursorrules`, `copilot-instructions.md` | AGT005–006 |
| every file | SEC |

> [!IMPORTANT]
> **Write/Edit are checked before the file is written. Shell commands can only be checked after.** A shell command's output is not known until it has run, so the shell guard cannot refuse the write. It flags it immediately and makes Claude fix it in the same step. The pre-commit hook is the backstop for anything that still slips through.

## All rules

| ID | Sev. | What |
|---|---|---|
| GHA001 | medium | Third-party action not pinned to a commit SHA |
| GHA002 | critical | `pull_request_target` checking out untrusted PR code |
| GHA003 | high | Script injection: `${{ github.event.*.title/body/… }}` inside `run:` or `script:` (actions/github-script) |
| GHA004 | high | `permissions: write-all` |
| GHA005 | low | No top-level `permissions:` block |
| GHA006 | medium | `${{ secrets.X }}` interpolated directly into `run:` / `script:` |
| DKR001 | medium | Base image `:latest` or untagged |
| DKR002 | medium | Final stage runs as root (follows `FROM <stage>`, accepts `:nonroot` images) |
| DKR003 | high | Secret baked in via `ENV`/`ARG` (skips `*_FILE`, URLs, paths, `$VARS`) |
| DKR004 | low | `ADD` instead of `COPY` |
| DKR005 | medium | `curl … \| sh` |
| TF001 | high · medium | `0.0.0.0/0` ingress (GCP firewall, AWS SG, Azure NSG); medium when only ports 80/443 are open, egress and routes are ignored |
| TF002 | high | Public buckets/resources: `allUsers`, `public-read`, S3 public access block off, Azure public network access |
| TF003 | high | `roles/owner`/`roles/editor`, `AdministratorAccess`, `"Action": "*"`, Azure `Owner`/`Contributor` |
| TF004 | medium | Database on a public IP (Cloud SQL `ipv4_enabled`, RDS `publicly_accessible`) |
| TF005 | critical | Hard-coded password/secret/token (skips URLs, numbers, `*_url`, `*_length`, …) |
| TF006 | medium | Encryption at rest / HTTPS-only disabled |
| TF007 | low | `deletion_protection = false` |
| K8S001 | high | `privileged: true` |
| K8S002 | medium | `hostNetwork`/`hostPID`/`hostIPC`/`hostPath` |
| K8S003 | medium | `allowPrivilegeEscalation: true`, `runAsUser: 0` |
| K8S004 | low | Image `:latest` or untagged (also in Helm `charts/**/values*.yaml`) |
| CMP001 | high | Compose: `privileged: true` |
| CMP002 | critical | Compose: Docker socket mounted into a container |
| CMP003 | medium | Compose: `network_mode`/`pid`/`ipc: host` |
| CMP004 | medium | Compose: literal secret in `environment:` (skips `${VAR}`, `*_FILE`, placeholders like `changeme`/`postgres`, and `e2e/`, `examples/`, `.devcontainer/` files) |
| CMP005 | low | Compose: image `:latest` or untagged |
| NPM001 | high | `package.json` install script fetches or evals code (`curl`, `\| sh`, `node -e`, `base64 -d`) |
| NPM002 | medium | Dependency from a git/HTTP URL not pinned to a commit SHA (dependency blocks only) |
| NPM003 | low | Dependency on `*` or `latest` (skips workspaces, same-scope siblings, peer/optional ranges) |
| AGT001 | high | Agent may run any shell command: `Bash`, `Bash(*)`, `*` in `allow`, or `defaultMode: bypassPermissions` |
| AGT002 | medium | `disableAllHooks` or `enableAllProjectMcpServers` switched on |
| AGT003 | medium | MCP server started with an unpinned `npx`/`bunx`/`pnpm dlx`/`uvx`/`pipx run` package |
| AGT004 | high | Credential literal in agent config (`env`, `headers`) instead of `${VAR}` |
| AGT005 | high | Invisible zero-width characters in `CLAUDE.md`, `AGENTS.md`, skills, commands, rules |
| AGT006 | high | Instruction file overrides earlier instructions, hides actions from the user, switches off safeguards or pipes downloads into a shell |
| AGT007 | high | Hook command pipes a download into a shell |
| AGT008 | high | `.guard.json` switches built-in rules off |
| SEC001 | critical | Private keys with key material (any file; a bare header in docs is ignored) |
| SEC002 | critical | AWS, GCP API, GitHub, GitLab, Slack, Stripe, Anthropic, OpenAI keys (any file) |
| SEC003 | high | Hidden bidi overrides/isolates or Unicode tag characters, "Trojan Source" (any file; translation files and flag emoji are fine) |
| SEC004 | high | New `.env` file that git does not ignore (templates like `.env.example` are fine) |

`allUsers` on `roles/run.invoker` / `roles/cloudfunctions.invoker` is allowed, because that is how a public Cloud Run service is exposed.

Every rule has a "why" with its CWE, shown in [learning mode](configuration.md#settings).

## Silencing a finding

Add `# guard:ignore` (all rules) or `# guard:ignore GHA001` (one rule) on the line or the line above.

> [!WARNING]
> Claude is told to add `guard:ignore` only with your agreement. Review these comments in PRs like any other security exception.

In Markdown use an HTML comment: `<!-- guard:ignore AGT006 -->`.
