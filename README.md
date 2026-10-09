# 🛡 Shift-Left Guard

<p align="center">
  <a href="https://github.com/PascalNehlsen/shift-left-guard/actions/workflows/ci.yml"><img src="https://github.com/PascalNehlsen/shift-left-guard/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/PascalNehlsen/shift-left-guard/actions/workflows/zizmor.yml"><img src="https://github.com/PascalNehlsen/shift-left-guard/actions/workflows/zizmor.yml/badge.svg" alt="zizmor"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://github.com/PascalNehlsen/shift-left-guard"><img src="https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2FPascalNehlsen%2Fshift-left-guard%2Fmain%2F.github%2Fshift-left-guard.json" alt="shift-left-guard score"></a>
</p>

**DevSecOps guardrails for Claude Code.** Every GitHub Actions workflow, Dockerfile, Terraform file, Kubernetes manifest, Compose file, `package.json`, agent config (`.claude/settings.json`, `.mcp.json`, `CLAUDE.md`) and secret that Claude writes is checked *before* it hits your disk. When something is wrong, Claude gets the findings and fixes them itself. Destructive cloud commands come to you before they run.

![Shift-Left Guard catching a script injection Claude copied from a template, Claude fixing it, a /guard audit, and the blast-radius dialog stopping a production delete](docs/demo.gif)

CI scanners find these problems after the push. Shift-Left Guard stops them while the code is still being written.

> [!TIP]
> No binaries, no API keys, no network. All rules run inside the mod, so it works the moment it is installed.

## Table of Contents

- [Why, if Claude already writes secure code?](#why-if-claude-already-writes-secure-code)
- [Install](#install)
  - [After installing](#after-installing)
- [What it does](#what-it-does)
  - [Commands](#commands)
- [Privacy: does Claude read my secrets?](#privacy-does-claude-read-my-secrets)
- [Scope: what is checked when?](#scope-what-is-checked-when)
- [Rules](#rules)
  - [Silencing a finding](#silencing-a-finding)
- [Settings](#settings)
- [CI](#ci)
- [What it is not](#what-it-is-not)
- [Develop](#develop)
- [License](#license)

## Why, if Claude already writes secure code?

Asked to *write* a workflow, Claude usually gets it right on its own. Risky code mostly comes **from outside**: templates, copy-paste, `cp`, generators, scaffolding. We ran the demo task ("copy the platform team's template") three times with Opus **without** the guard. Every run spotted the injection and suggested the fix, and every run **left the vulnerable file on disk** while it asked whether to apply the fix. One "commit this" later, it ships.

The guard turns "Claude noticed" into "the file is fixed":

- **Deterministic:** a rule fires every time, in every session, for every model and teammate. It does not depend on what the model paid attention to.
- **Covers what models skim:** copied files, shell writes, and long sessions where security is not the focus.
- **Covers humans too:** with the pre-commit hook, your own edits are checked the same way.

## Install

In a Claude Code terminal session:

```
/plugin install shift-left-guard --marketplace PascalNehlsen/shift-left-guard
```

Answer `y` to add the marketplace, then pick a scope (user scope = every project).

### After installing

There is nothing to switch on. The guard runs in every new session, in every project with user scope or in the chosen project with project scope. It stays invisible until it finds something; then the band above the prompt and the `🛡` status line appear.

| To … | Do |
|---|---|
| pause it for this session | `/guard pause`, back on with `/guard resume` |
| make it stricter or looser | `/config` → Shift-Left Guard → `blockAt` / `cloudGuard` ([Settings](#settings)) |
| turn it off completely | `/plugin` → shift-left-guard → disable, or `claude plugin disable shift-left-guard` |
| check your own commits too | run `/guard install-hook` **once per repo** |

> [!NOTE]
> The pre-commit hook is not installed automatically. The mod only guards what Claude writes, until you run `/guard install-hook` in a repo.

### Updates

> [!IMPORTANT]
> Claude Code does **not** auto-update plugins from community marketplaces by default, so new rules and fixes will not reach you on their own.

**Turn on auto-update (recommended):** `/plugin` → **Marketplaces** → shift-left-guard → **Enable auto-update**. Claude Code then checks in the background during a session, within about ten minutes of your first message. A new version is downloaded but takes effect only after `/reload-plugins` or in your next session.

**Or update by hand:**

```bash
claude plugin marketplace update shift-left-guard
claude plugin update shift-left-guard@shift-left-guard
```

Then run `/reload-plugins` in an open session, or start a new one. To stay on a fixed release, add the marketplace pinned to a tag instead: `PascalNehlsen/shift-left-guard#v0.3.0`.

## What it does

| | |
|---|---|
| **Write guard** | Hooks `Write` and `Edit`. It computes the file as it will look after the call, scans it, and keeps only the findings the change *introduces*, so legacy issues in old files never block you. |
| **Block → fix loop** | Findings at or above `blockAt` (default `high`) stop the write, and Claude gets each finding with a concrete fix. If the same findings come back after 2 retries, the write goes through with a loud warning, so the guard never deadlocks a session. |
| **Shell guard** | After every Bash command, files git sees as changed since the command started are scanned against `HEAD`. This catches `sed -i`, `cat > file`, heredocs and generators. Claude gets the findings in the same step and must fix them first. |
| **Warnings** | Lower-severity findings pass, and Claude gets them as a note after the write. |
| **Cloud guard** | Bash commands like `terraform destroy`, `apply -auto-approve`, `gcloud … delete`, `aws … delete-*`, `aws s3 rm --recursive`, `az … delete`, `kubectl delete ns`, `helm uninstall` and owner/admin IAM grants are put to you (`ask`) or refused (`deny`). With `ask` you get a **blast-radius dialog**: the command, the project, region, namespace or bucket it hits, whether it targets production, and what undoing it takes. |
| **Audit & score** | `/guard audit` scans the whole repository and gives it a **security score and grade (A–F)** with the top findings. `/guard fix` puts a fix request for all of them into your prompt (or press **Fix with Claude** in the pane); `/guard badge` writes `.github/shift-left-guard.json` and prints a **live** README badge that reads it, so each committed audit updates the badge. |
| **Weekly recap** | Once a week, at your first session, a toast says what the guard did last week: issues stopped, fixed by Claude, cloud commands checked. |
| **Pre-commit hook** | `/guard install-hook` installs a git hook with the same rules into the current repo. It covers your own edits too, with no Claude involved. |
| **Band, pane, status line** | A line above the prompt shows the last interception, with **[Report]** (opens the findings pane: every finding with its fix) and **[Hide]**. When Claude fixes a finding, the band shows the **before/after diff** of the lines it changed. The status line keeps a running score. |
| **🛡 on the transcript row** | Every `Write`/`Edit` Claude makes carries a mark on its row: `🛡 clean`, `🛡 blocked GHA003`, `🛡 fixed GHA003`. Shell commands that wrote an issue and cloud commands are marked too. |
| **Learning mode** | Turn on `explain` and every finding comes with *why* it is dangerous, its CWE and a real incident, in the pane and for Claude, who then explains it to you in its reply. Made for learners and teams new to DevSecOps. |

> [!IMPORTANT]
> **Write/Edit are checked before the file is written. Shell commands can only be checked after.** A shell command's output is not known until it has run, so the shell guard cannot refuse the write. It flags it immediately and makes Claude fix it in the same step. The pre-commit hook is the backstop for anything that still slips through.

### Commands

| Command | |
|---|---|
| `/guard` | Session + all-time report |
| `/guard audit` | Scan the whole repository: score, grade and top findings |
| `/guard fix` | Put a fix request for the audit's findings into your prompt; press Enter to send |
| `/guard badge` | Live README badge for the audit's grade (writes `.github/shift-left-guard.json`; commit it) |
| `/guard pane` | Open the findings pane (same as the **[Report]** button) |
| `/guard rules` | List all rules with severity |
| `/guard install-hook` | Install the pre-commit hook in the current repo |
| `/guard pause` · `/guard resume` | Switch the guard off/on for this session |

## Privacy: does Claude read my secrets?

No secret leaves your machine because of this mod.

- The mod runs **locally inside Claude Code**. It checks with regular expressions, makes no model calls, makes no network requests and stores no file contents. Only counters and rule IDs are kept (for `/guard`).
- To compare old and new, it reads the current version of the file Claude is changing. That version is **only scanned locally** and is not sent to Claude.
- When it reports a secret finding to Claude, the value is **masked** (`AKI****`), never echoed verbatim.

> [!NOTE]
> If Claude *writes* a secret, Claude already knows it, since Claude produced it. The guard keeps it off your disk and out of your repo; it cannot unsee it for the model. Keep real secrets in a secret manager and out of prompts.

## Scope: what is checked when?

| Who writes | How | Checked |
|---|---|---|
| Claude | `Write` / `Edit` tool | ✅ before the write, can block |
| Claude | Bash (`sed -i`, `cat >`, scripts …) | ✅ right after the command, Claude must fix |
| You | your editor | ✅ at `git commit`, with `/guard install-hook` |
| Anyone | CI | ✅ with `guard-scan.mjs --all` ([see below](#ci)) |

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

## Rules

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

### Silencing a finding

Add `# guard:ignore` (all rules) or `# guard:ignore GHA001` (one rule) on the line or the line above.

> [!WARNING]
> Claude is told to add `guard:ignore` only with your agreement. Review these comments in PRs like any other security exception.

In Markdown use an HTML comment: `<!-- guard:ignore AGT006 -->`.

### Team rules: `.guard.json`

Put a `.guard.json` in the repository root to add your own rules or switch built-in ones off. The mod, the pre-commit hook and CI all read it.

```json
{
  "rules": [
    {
      "id": "ACME001",
      "severity": "high",
      "title": "Base images must come from the internal registry",
      "fix": "Use FROM registry.acme.io/<image>:<tag>.",
      "pattern": "^FROM (?!registry\\.acme\\.io)",
      "files": "Dockerfile"
    }
  ],
  "disable": ["GHA005"]
}
```

- `pattern` is a JavaScript regular expression matched against each line; `files` (optional) is matched against the path.
- IDs are upper-case and must not reuse a built-in ID. A broken rule is skipped and reported, the rest keep working.
- `disable` is itself a finding (AGT008), so Claude cannot quietly switch a rule off: you see it and decide.

## Settings

`/config` → Shift-Left Guard, or `pluginConfigs` in `settings.json`:

| Option | Values | Default |
|---|---|---|
| `blockAt` | `critical` · `high` · `medium` · `low` · `never` | `high` |
| `cloudGuard` | `ask` · `deny` · `off` | `ask` |
| `explain` | `true` · `false` | `false` |

> [!CAUTION]
> `cloudGuard: ask` shows you the blast-radius dialog, in every permission mode, auto mode included. Where no one can answer it (`claude -p`, the SDK) or you dismiss it, the decision falls back to your permission mode, and **in auto mode the classifier decides, not you**. Use `deny` if a human must always run these commands; Claude then shows you the command to run with `! <command>`.

## CI

The pre-commit scanner is a self-contained Node script, [`bin/guard-scan.mjs`](bin/guard-scan.mjs), with no dependencies. Download it from a release tag and run it in any pipeline that has Node:

```yaml
- run: curl -fsSLO https://raw.githubusercontent.com/PascalNehlsen/shift-left-guard/v0.3.0/bin/guard-scan.mjs
- run: node guard-scan.mjs --all --block-at=high
```

Pin the tag (or a commit SHA) rather than `main`, so a new release never changes your pipeline unreviewed.

`--all` audits every tracked file and prints the security score; `--badge` prints a README badge, `--badge-file` writes `.github/shift-left-guard.json` for the live badge. Without `--all`, the script scans staged changes only (pre-commit mode).

The score is 100 minus 25 per critical, 10 per high, 3 per medium and 1 per low finding: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, else F.

**GitHub code scanning:** `--format=sarif` prints [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html), so findings show up in the Security tab and as PR annotations:

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@<sha> # v4
  - run: curl -fsSLO https://raw.githubusercontent.com/PascalNehlsen/shift-left-guard/<tag>/bin/guard-scan.mjs
  - run: node guard-scan.mjs --all --format=sarif > guard.sarif
    continue-on-error: true
  - uses: github/codeql-action/upload-sarif@<sha> # v3
    with:
      sarif_file: guard.sarif
```

## What it is not

> [!NOTE]
> **Not a sandbox.** A sandbox limits what Claude can *reach*. This guard limits what Claude *produces*. Use both.

- **Not a replacement for CI scanners.** Keep `zizmor`, `hadolint`, `checkov`, `gitleaks` in your pipeline. This guard is the fast, zero-config first line.
- The rules are line-based heuristics tuned for low noise, not full parsers.

## Develop

```bash
npm ci && npm test         # pinned Claude Code CLI + plugin tests
claude --plugin-dir .      # run a session with the local copy
```

> [!WARNING]
> If you also have the plugin installed, a `--plugin-dir` session runs **both** copies, so every finding is reported twice. Disable the installed one while developing: `claude plugin disable shift-left-guard`.

New rules, false-positive fixes and better fix texts are very welcome. [CONTRIBUTING.md](CONTRIBUTING.md) explains how to add a rule. Security issues in the guard itself go through [SECURITY.md](SECURITY.md), not public issues.

## License

MIT, built by [Pascal Nehlsen](https://github.com/PascalNehlsen).
