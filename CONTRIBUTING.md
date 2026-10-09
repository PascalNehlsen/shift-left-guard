# Contributing

Thanks for helping make Claude's output safer! New rules, fewer false positives and better fixes are the most valuable contributions.

## Setup

You need Node 24 and [Bun](https://bun.sh) 1.3.14 (the version CI uses, so the bundle stays byte-identical).

```bash
npm ci                     # installs the pinned Claude Code CLI used for validate/test
npm run validate           # manifest, marketplace and hooks module
npm test                   # plugin tests (no login or API key needed)
bun run build              # bundles cli/guard-scan.ts → bin/guard-scan.mjs
npm run self-scan          # this repo, checked with its own rules
```

Try your local copy in a real session with `claude --plugin-dir .`.

> [!WARNING]
> If you also have the plugin installed, disable it while developing (`claude plugin disable shift-left-guard`), or every finding is reported twice.

## Adding a rule

1. Add one object to `RULES` in [`hooks/rules.ts`](hooks/rules.ts): `id`, `kind`, `severity`, `title`, `fix`, and a `line` or `file` matcher.
   - **IDs** continue the prefix: `GHA`, `DKR`, `TF`, `K8S`, `SEC`.
   - **`fix`** is what Claude reads. Make it concrete enough to act on without a web search.
   - **Severity:** `high` and `critical` block the write by default, so reserve them for issues that are exploitable as written.
2. Add a test to [`tests/rules.test.ts`](tests/rules.test.ts) with at least **one positive and one negative example**. The negative example is the safe code that must *not* be flagged.
3. If the rule matches values that are secrets, add its ID to `SECRET_RULES` so findings are masked.
4. Run `bun run build` and commit `bin/guard-scan.mjs` together with your rule. CI fails if the bundle is out of date.
5. Add the rule to the table in the README.

> [!TIP]
> Before opening the PR, run your rule against a few real repos. A rule that is noisy on real code gets switched off by users, and then it protects nobody.

## Pull requests

- Work on a feature branch; `main` is protected and only takes PRs with green checks.
- Use [Conventional Commits](https://www.conventionalcommits.org) (`feat(rules): …`, `fix: …`, `docs: …`).
- Type-checking needs the Claude Code API types, which the engine writes to `.claude-plugin/types/` when it loads the plugin from a folder it watches (e.g. `claude --plugin-dir .` in an interactive session). Then run `npx -p typescript tsc -p .`.

## Releasing (maintainers)

1. Bump `version` in `.claude-plugin/plugin.json`.
2. Merge to `main`, then tag: `git tag v0.2.0 && git push origin v0.2.0`.
3. The release workflow runs CI, checks the tag matches `plugin.json`, and creates the GitHub release with generated notes.
