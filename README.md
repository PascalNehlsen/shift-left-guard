# 🛡 Shift-Left Guard

<p align="center">
  <a href="https://github.com/PascalNehlsen/shift-left-guard/actions/workflows/ci.yml"><img src="https://github.com/PascalNehlsen/shift-left-guard/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/PascalNehlsen/shift-left-guard/actions/workflows/zizmor.yml"><img src="https://github.com/PascalNehlsen/shift-left-guard/actions/workflows/zizmor.yml/badge.svg" alt="zizmor"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
</p>

**DevSecOps guardrails for Claude Code.** Every GitHub Actions workflow, Dockerfile, Terraform file, Kubernetes manifest and secret that Claude writes is checked *before* it hits your disk. When something is wrong, Claude gets the findings and fixes them itself. Destructive cloud commands come to you before they run.

![Shift-Left Guard blocking a script injection and Claude fixing it](docs/demo.gif)

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

Then run `/reload-plugins` in an open session, or start a new one. To stay on a fixed release, add the marketplace pinned to a tag instead: `PascalNehlsen/shift-left-guard#v0.2.0`.

## What it does

| | |
|---|---|
| **Write guard** | Hooks `Write` and `Edit`. It computes the file as it will look after the call, scans it, and keeps only the findings the change *introduces*, so legacy issues in old files never block you. |
| **Block → fix loop** | Findings at or above `blockAt` (default `high`) stop the write, and Claude gets each finding with a concrete fix. If the same findings come back after 2 retries, the write goes through with a loud warning, so the guard never deadlocks a session. |
| **Shell guard** | After every Bash command, files git sees as changed since the command started are scanned against `HEAD`. This catches `sed -i`, `cat > file`, heredocs and generators. Claude gets the findings in the same step and must fix them first. |
| **Warnings** | Lower-severity findings pass, and Claude gets them as a note after the write. |
| **Cloud guard** | Bash commands like `terraform destroy`, `apply -auto-approve`, `gcloud … delete`, `aws … delete-*`, `aws s3 rm --recursive`, `az … delete`, `kubectl delete ns`, `helm uninstall` and owner/admin IAM grants are put to you (`ask`) or refused (`deny`). Production targets are flagged. |
| **Pre-commit hook** | `/guard install-hook` installs a git hook with the same rules into the current repo. It covers your own edits too, with no Claude involved. |
| **Band, pane, status line** | A line above the prompt shows the last interception, with **[Report]** (opens the findings pane: every finding with its fix) and **[Hide]**. The status line keeps a running score. |

> [!IMPORTANT]
> **Write/Edit are checked before the file is written. Shell commands can only be checked after.** A shell command's output is not known until it has run, so the shell guard cannot refuse the write. It flags it immediately and makes Claude fix it in the same step. The pre-commit hook is the backstop for anything that still slips through.

### Commands

| Command | |
|---|---|
| `/guard` | Session + all-time report |
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

Only the changed file is scanned, and only what the change introduces is reported. A file such as `abc.yml` gets the full rule set when it is a workflow (`.github/workflows/`) or a Kubernetes manifest (`apiVersion:` + `kind:`). Any other file is checked for secrets only.

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
| K8S004 | low | Image `:latest` or untagged |
| SEC001 | critical | Private keys with key material (any file; a bare header in docs is ignored) |
| SEC002 | critical | AWS, GCP API, GitHub, GitLab, Slack, Stripe, Anthropic, OpenAI keys (any file) |

`allUsers` on `roles/run.invoker` / `roles/cloudfunctions.invoker` is allowed, because that is how a public Cloud Run service is exposed.

### Silencing a finding

Add `# guard:ignore` (all rules) or `# guard:ignore GHA001` (one rule) on the line or the line above.

> [!WARNING]
> Claude is told to add `guard:ignore` only with your agreement. Review these comments in PRs like any other security exception.

## Settings

`/config` → Shift-Left Guard, or `pluginConfigs` in `settings.json`:

| Option | Values | Default |
|---|---|---|
| `blockAt` | `critical` · `high` · `medium` · `low` · `never` | `high` |
| `cloudGuard` | `ask` · `deny` · `off` | `ask` |

> [!CAUTION]
> `cloudGuard: ask` hands the decision to your permission mode. In **auto mode the classifier decides, not you**. Use `deny` if a human must always run these commands; Claude then shows you the command to run with `! <command>`.

## CI

The pre-commit scanner is a self-contained Node script, [`bin/guard-scan.mjs`](bin/guard-scan.mjs), with no dependencies. Download it from a release tag and run it in any pipeline that has Node:

```yaml
- run: curl -fsSLO https://raw.githubusercontent.com/PascalNehlsen/shift-left-guard/v0.1.0/bin/guard-scan.mjs
- run: node guard-scan.mjs --all --block-at=high
```

Pin the tag (or a commit SHA) rather than `main`, so a new release never changes your pipeline unreviewed.

`--all` audits every tracked file. Without it, the script scans staged changes only (pre-commit mode).

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
