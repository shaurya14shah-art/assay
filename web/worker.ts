// Runs the Assay engine off the main thread so large rule packs never freeze the UI.
import { filterByLevel, runCoverage } from "../src/coverage.js";
import { parseScenarios, type Scenario } from "../src/scenarios.js";
import { parseRuleFile } from "../src/sigma/parse.js";
import type { Rule, RuleIssue } from "../src/sigma/types.js";
import type { RuleMeta, RunRequest, RunResponse } from "./protocol.js";

const ctx = self as unknown as {
  postMessage(message: RunResponse): void;
  onmessage: ((e: MessageEvent<RunRequest>) => void) | null;
};

ctx.onmessage = (e) => {
  const { id, rules: ruleFiles, scenarios: scenarioFiles, minLevel } = e.data;
  const started = performance.now();
  try {
    const rules: Rule[] = [];
    const issues: RuleIssue[] = [];
    for (const f of ruleFiles) {
      const r = parseRuleFile(f.text, f.name);
      rules.push(...r.rules);
      issues.push(...r.issues);
    }

    const scenarios: Scenario[] = [];
    const seen = new Set<string>();
    for (const f of scenarioFiles) {
      for (const s of parseScenarios(f.text, f.name)) {
        if (seen.has(s.id)) throw new Error(`Duplicate scenario id "${s.id}" in ${f.name}`);
        seen.add(s.id);
        scenarios.push(s);
      }
    }

    const evaluated = filterByLevel(rules, minLevel);
    const included = new Set(evaluated);
    const report = runCoverage(evaluated, scenarios, issues);
    const meta: RuleMeta[] = rules.map((r) => ({
      id: r.id,
      title: r.title,
      level: r.level,
      status: r.status,
      description: r.description,
      techniques: r.techniques,
      source: r.source ?? "",
      unsupported: r.unsupported,
      evaluated: included.has(r),
    }));
    const events = scenarios.reduce((n, s) => n + s.events.length, 0);
    ctx.postMessage({ id, ok: true, report, rules: meta, scenarios, ms: performance.now() - started, events });
  } catch (err) {
    ctx.postMessage({ id, ok: false, error: (err as Error).message });
  }
};
