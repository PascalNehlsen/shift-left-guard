# Security Policy

Shift-Left Guard is a security tool, so flaws in it matter twice. Thank you for reporting them responsibly.

## Reporting a vulnerability

> [!IMPORTANT]
> Please **do not open a public issue** for vulnerabilities. Use GitHub's private reporting instead:
> **[Report a vulnerability](https://github.com/PascalNehlsen/shift-left-guard/security/advisories/new)**

You can expect a first answer within 7 days. Once a fix is released, you will be credited in the advisory unless you prefer otherwise.

## What counts as a vulnerability here

| In scope (report privately) | Not a vulnerability (open a normal issue) |
|---|---|
| A secret reaches the model or a log unmasked through the guard's own output | A rule misses an insecure pattern (false negative) |
| A file or command bypasses a guard that should apply to it (e.g. a crafted path skips the Write guard) | A rule flags safe code (false positive) |
| The pre-commit hook or `/guard install-hook` can be abused to run unintended commands | Feature requests and new rules |
| The mod writes outside the repo / `.git` directory it was asked to touch | Problems in Claude Code itself (report those to Anthropic) |

## Supported versions

Only the latest release receives security fixes. Update with `/plugin` → shift-left-guard → update.
