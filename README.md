# Assay

**Unit tests for detection rules.** Point Assay at your Sigma rules and a library of attack telemetry. It tells you which MITRE ATT&CK techniques you actually catch, which you miss, and which benign activity trips your rules, then fails your CI build if that gets worse.

No AI. Every result traces to a rule, a selection and an event.

```bash
npm install
npm run assay -- run --rules examples/rules --scenarios scenarios
npm run assay -- run --rules examples/rules --scenarios scenarios \
  --json baseline.json            # save a baseline
npm run assay -- run --rules examples/rules --scenarios scenarios \
  --baseline baseline.json --min-coverage 80 --max-false-positives 1   # CI gate, exit 1 on failure
```

## Web app
```bash
npm run dev        # http://localhost:5310
npm run build:web  # static site in dist-web/, host anywhere
```
The web app runs the same engine in a Web Worker, entirely client-side. It has three tabs:
- **Coverage matrix:** an ATT&CK heatmap. Click any technique for the evidence: every scenario, every event, and which rule and selection fired.
- **Rules:** a live YAML editor. Coverage re-runs as you type. You can also load your own rule files or a whole folder, or drop them on the page. Files are read in the browser and never uploaded.
- **Findings:** gaps, false positives, partial evasions, tagged-but-silent rules, dead, unsupported and invalid rules.

There is also a level filter and JSON export. Fonts are bundled locally, so the page makes no third-party requests. Loading all 3,779 SigmaHQ rules takes about 5 seconds and keeps the page responsive.

## What it reports
- **Technique coverage**: a technique is covered if at least one of its malicious scenarios fires a rule. Each row shows `detected/total` scenarios, so a partly evaded technique (like the encoded-PowerShell `-e` variant) is visible.
- **Gaps**: techniques with telemetry that nothing detects, including rules that are tagged for a technique but stay silent on it.
- **False positives**: benign scenarios that fire a rule, with the selection that caused it.
- **Dead rules**: rules that never fire on anything.
- **Unsupported rules**: rules using features Assay cannot evaluate. They are listed, never silently counted as non-matching.

## Sigma support
Tested against the full public SigmaHQ rule set (3,779 rules): **every document loads**, 2 are reported unsupported (they use `expand`), and the whole set evaluates against the bundled scenarios in about 2.5 seconds.

Supported:
- Selections: maps, lists of maps, keyword lists, and keyword searches with modifiers (`'|all': [...]`).
- Conditions: `and` / `or` / `not`, parentheses, `1 of` / `all of` with `them` and `*` patterns, and lists of conditions.
- Modifiers: `contains startswith endswith all cased exists fieldref re` (with `i m s` and leading PCRE flags like `(?i)`), `cidr` (IPv4 and IPv6), `base64 base64offset` with `utf16le utf16be utf16 wide`, `windash` (mixed `-`, `/` and typographic dashes), and `lt lte gt gte`.
- Values: `*` and `?` wildcards with `\` escapes, case-insensitive by default, numbers and nulls, and dotted field paths.
- Collections: Sigma v1 `action: global | reset | repeat`.

Reported as unsupported, never silently skipped:
- Aggregations (`| count()`), `near`/temporal, correlation rules and meta filter rules.
- `expand`.
- PCRE-only regex syntax (`\A`, `\Z`, atomic groups, possessive quantifiers, mid-pattern flags), which JavaScript would otherwise misread.

Matching notes:
- Base64-encoded forms always match case-sensitively, because base64 text is case-significant.
- `fieldref` compares values literally and case-insensitively unless `cased` is set.

## Robustness
- One bad rule never breaks a run. Each YAML document is isolated, and invalid ones are listed with file and document number. Use `--strict` to fail CI on them, or `assay validate` to lint a rule pack.
- Duplicate rule ids are reported. YAML alias bombs are rejected. Symlink loops are skipped.
- `--min-level medium` drops broad informational and low hunting rules. With it, SigmaHQ's own rules score 17/18 techniques and 0 false positives on the bundled scenarios.

## Scenarios
A scenario is a YAML document with `id`, `name`, `technique` (or `malicious: false` for benign activity), a `logsource`, and a list of `events`. An event can override the logsource with a reserved `_logsource` key, so one scenario can chain process, network and registry telemetry.

## Important
Scenario telemetry is **synthetic reference telemetry** written for this repo. Passing means "these rules catch these examples", not "you are protected". Treat gaps as certain and coverage as evidence.

## Layout
`src/sigma/` engine · `src/coverage.ts` runner and CI gate · `src/cli.ts` · `scenarios/` telemetry · `examples/rules/` sample rules · `test/` Vitest. Roadmap in `plan.md`.

License: Apache-2.0.
