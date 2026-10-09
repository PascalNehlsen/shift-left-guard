# Configuration

[← README](../README.md) · [Rules](rules.md) · [CI](ci.md)

## Day to day

| To … | Do |
|---|---|
| pause it for this session | `/guard pause`, back on with `/guard resume` |
| make it stricter or looser | `/config` → Shift-Left Guard → `blockAt` / `cloudGuard` ([Settings](#settings)) |
| turn it off completely | `/plugin` → shift-left-guard → disable, or `claude plugin disable shift-left-guard` |
| check your own commits too | run `/guard install-hook` **once per repo** |

> [!NOTE]
> The pre-commit hook is not installed automatically. The mod only guards what Claude writes, until you run `/guard install-hook` in a repo.

## Settings

`/config` → Shift-Left Guard, or `pluginConfigs` in `settings.json`:

| Option | Values | Default |
|---|---|---|
| `blockAt` | `critical` · `high` · `medium` · `low` · `never` | `high` |
| `cloudGuard` | `ask` · `deny` · `off` | `ask` |
| `explain` | `true` · `false` | `false` |

> [!CAUTION]
> `cloudGuard: ask` shows you the blast-radius dialog, in every permission mode, auto mode included. Where no one can answer it (`claude -p`, the SDK) or you dismiss it, the decision falls back to your permission mode, and **in auto mode the classifier decides, not you**. Use `deny` if a human must always run these commands; Claude then shows you the command to run with `! <command>`.

## Team rules: `.guard.json`

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

## Updates

> [!IMPORTANT]
> Claude Code does **not** auto-update plugins from community marketplaces by default, so new rules and fixes will not reach you on their own.

**Turn on auto-update (recommended):** `/plugin` → **Marketplaces** → shift-left-guard → **Enable auto-update**. Claude Code then checks in the background during a session, within about ten minutes of your first message. A new version is downloaded but takes effect only after `/reload-plugins` or in your next session.

**Or update by hand:**

```bash
claude plugin marketplace update shift-left-guard
claude plugin update shift-left-guard@shift-left-guard
```

Then run `/reload-plugins` in an open session, or start a new one. To stay on a fixed release, add the marketplace pinned to a tag instead: `PascalNehlsen/shift-left-guard#v0.3.2`.
