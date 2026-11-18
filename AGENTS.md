# AGENTS.md: Assay

Read `plan.md` first. Assay evaluates Sigma detection rules against synthetic attack telemetry and reports ATT&CK coverage.

## Rules
- **No AI features.** Everything is deterministic and explainable. Every result must be traceable to a rule, selection and event.
- Never silently drop unsupported Sigma features. Surface them as `unsupported`.
- Scenario telemetry is synthetic. Keep that wording in anything user-facing.
- Original rules and scenarios only. Do not copy SigmaHQ rule text or Atomic Red Team files.

## Gate (run before saying a task is done)
```
npm run typecheck
npm test
npm run assay -- run --rules examples/rules --scenarios scenarios
npm run build:web
```
`npm run typecheck` checks both the engine and `web/` (separate tsconfig). Tests use `vitest.config.ts`, because `vite.config.ts` roots Vite at `web/`.

Web UI: dev server is `assay-web` in `~/AG/.claude/launch.json` (port 5310). The engine runs in `web/worker.ts`; `src/sigma/` must stay free of Node APIs so it works there. The in-app browser pane is often hidden, which stops smooth scrolling and IntersectionObserver, so verify with headless puppeteer (installed at `~/AG/touchbeat/tools/node/node_modules/puppeteer`) and batch screenshots into one contact sheet.

Optional corpus check (needs a local SigmaHQ checkout, never committed to this repo because of its Detection Rule License):
```
ASSAY_CORPUS=/path/to/sigma npm test
```
Expect 0 invalid documents. A new invalid document means an engine regression or a new Sigma feature.

## Layout
See `plan.md`. TypeScript, ESM, NodeNext (imports end in `.js`). Tests in `test/` with Vitest.

## Notes
- Node 26 on this machine. No pnpm; use npm.
- The user handles anything outward-facing: domain, live Stripe, publishing to GitHub/HN.
