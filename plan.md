# Assay: plan

**One line:** unit tests for detection rules. Feed in Sigma rules, replay attack telemetry, and get a provable ATT&CK coverage report, with a CI gate that fails when coverage regresses.

**Chosen:** 2026-11-17. Target: mid-size security teams (detection engineers). No AI anywhere. Deterministic, explainable, open-source core.

## Why this
- Teams write detection rules but cannot prove what they catch. Breach-and-attack tools are enterprise-priced; Atomic Red Team needs live endpoints.
- Sigma is an open, vendor-neutral format, so an offline evaluator is credible and testable.
- CI gate ("coverage must not drop below X, no new false positives") is the thing teams will pay to host.

## Business shape
- Open-source (Apache-2.0): engine, CLI, GitHub Action, scenario library.
- Paid hosted: history and trends, team dashboards, PR comments, policy gates, private scenario packs, audit export. Target $200-1,200 / month / team.
- Distribution: GitHub Action, Hacker News, detection-engineering communities. (User's job, not the agent's.)

## Architecture
```
src/sigma/    types, YAML -> Rule parser, condition parser, matchers, evaluator
src/scenarios/ scenario loader (YAML), schema validation
src/coverage/ runner: rules x scenarios -> per-technique results, false positives, dead rules
src/report/   JSON, terminal table, later HTML
src/cli.ts    `assay run|validate|explain`
scenarios/    built-in telemetry library (malicious + benign), each tagged with ATT&CK technique
examples/rules/ sample Sigma rules (original, written for this repo)
web/          (phase 3) Vite + React coverage matrix, runs the engine fully client-side
```

## Decisions
- Case-insensitive matching by default, per Sigma spec. Wildcards `*` `?`, escape with `\`.
- A rule only applies to an event if every logsource key the rule specifies equals the event's.
- A scenario is **detected** if any event in it fires any applicable rule. A **false positive** is any rule firing on a benign scenario.
- Unsupported Sigma features (aggregations like `| count()`, correlation rules) are reported as `unsupported`, never silently treated as non-matching.
- Technique ids normalised to `T1059.001` form.

## Phases
1. **Engine + CLI + tests** (this phase): parser, conditions, all common modifiers, coverage runner, ~25 scenarios, 12 sample rules.
2. **Quality**: Sigma field-modifier edge cases, correlation basics, scenario linting, JUnit/SARIF output, GitHub Action, coverage-regression gate against a baseline file.
3. **Web** (done 2026-11-17): ATT&CK matrix heatmap, evidence drawer, live rule editor, local rule-pack loading, findings, JSON export, light/dark. Client-side, so it doubles as the public demo and landing page. Not yet: authoring custom scenarios in the UI, shareable report links, scenario coverage for more techniques.
4. **Revenue**: hosted service (auth, history, Stripe test mode, PR bot). Account creation, domain and live Stripe are the user's.

## Risks
- Scenario realism: telemetry is hand-written, so labelled as "synthetic reference telemetry". Never claim it equals real-world detection.
- Sigma has long-tail features; keep the support matrix honest in README.
- Crowded adjacent space (Atomic Red Team, Sigma tooling like sigma-cli). Differentiator is the coverage proof and CI gate, not rule conversion.
