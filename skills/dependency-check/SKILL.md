---
name: dependency-check
description: >-
  Audit project dependencies for known-vulnerable versions and risky pinning.
  Parses requirements.txt, package.json, pyproject.toml, go.mod,
  package-lock.json and poetry.lock, matches a bundled offline advisory
  DB, optionally queries OSV.dev live, and warns about unpinned versions. Use
  when the user asks to "check dependencies for vulnerabilities", "audit my
  requirements.txt / package.json", "scan for vulnerable packages", or "is my
  dependency tree secure".
license: MIT
---

# Dependency Check

Scans Python (`requirements.txt`, `pyproject.toml`, `poetry.lock`), npm
(`package.json`, `package-lock.json`) and Go (`go.mod`) dependencies for
known-vulnerable versions and supply-chain risks. **Offline by default** — it
ships a bundled advisory database so it runs in air-gapped CI — with an optional
live OSV.dev lookup. Pure standard library.

## When to use this skill

- "Are any of my dependencies vulnerable?"
- "Audit requirements.txt / package.json."
- "Check for vulnerable / outdated packages before release."

## What it reports

- **Known vulnerabilities** — version matches against the bundled advisory DB
  (or OSV.dev with `--online`), with CVE/ID, severity and summary.
- **Transitive dependencies from lockfiles**: `package-lock.json` and
  `poetry.lock` give exact installed versions. A transitive finding names the
  chain that pulled it in (`lodash 4.17.15 (via webpack > terser)`). A
  lockfile replaces its manifest in a directory scan.
- **Unpinned dependencies** — ranges (`^`, `~`, `>=`) or missing pins that make
  builds non-reproducible and widen supply-chain exposure.

## How to run it

```bash
# Offline scan (bundled advisory DB)
python skills/dependency-check/checker.py requirements.txt
python skills/dependency-check/checker.py package.json

# Lockfiles: exact installed versions, including transitive deps
python skills/dependency-check/checker.py package-lock.json
python skills/dependency-check/checker.py poetry.lock

# Scan a directory (auto-discovers manifests and lockfiles; a lockfile wins)
python skills/dependency-check/checker.py .

# Live advisory lookup via OSV.dev
python skills/dependency-check/checker.py requirements.txt --online

# JSON output
python skills/dependency-check/checker.py . --json

# Only report MEDIUM or higher findings (unpinned warnings are LOW)
python skills/dependency-check/checker.py . --min-severity medium
```

**Exit codes:** `0` clean · `1` findings reported · `2` no manifest / usage
error. Unpinned dependencies are reported, so they fail the build too; suppress
them with `--no-unpinned`, or raise `--min-severity` to filter advisory
findings out of both the report and the exit code.

## Recommended workflow for Claude

1. Run offline first for a fast baseline, then `--online` for full coverage if
   the user has network access.
2. For each vulnerable package, recommend the **minimum fixed version** and
   note breaking-change risk. For a transitive one (`via`), the fix is usually
   upgrading the top of the chain, or an npm `overrides` / Poetry constraint.
3. Encourage exact pins (`==` / lockfiles) for reproducible, auditable builds.

## Note

The bundled DB is intentionally small (well-known historical CVEs) so the tool
is self-contained and testable. For comprehensive coverage use `--online`
(OSV.dev) or integrate a dedicated scanner; treat the offline DB as a fast
first pass.
