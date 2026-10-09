# CI, pre-commit and the score

[← README](../README.md) · [Rules](rules.md) · [Configuration](configuration.md)

## Pre-commit hook

`/guard install-hook` copies the scanner into `.git/` and wires it as a `pre-commit` hook, so your own edits are checked with the same rules, no Claude involved. It is installed per repository, never automatically. With husky or another `core.hooksPath`, it prints the one line to add instead.

## Pipeline

The pre-commit scanner is a self-contained Node script, [`bin/guard-scan.mjs`](../bin/guard-scan.mjs), with no dependencies. Download it from a release tag and run it in any pipeline that has Node:

```yaml
- run: curl -fsSLO https://raw.githubusercontent.com/PascalNehlsen/shift-left-guard/v0.3.1/bin/guard-scan.mjs
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

## Live badge

`/guard badge` (or `guard-scan --all --badge-file`) writes `.github/shift-left-guard.json` in [shields.io endpoint](https://shields.io/badges/endpoint-badge) format and prints a badge that reads it from your default branch. Commit the file; every `/guard audit` rewrites it, so the badge follows the repository's score. Without a GitHub remote you get a fixed badge for today's grade.
