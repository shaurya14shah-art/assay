import { readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { extname, join } from "node:path";
import { parseRuleFile } from "./sigma/parse.js";
import { parseScenarios, type Scenario } from "./scenarios.js";
import type { Rule, RuleIssue } from "./sigma/types.js";

/** Recursive file list. Follows symlinks but never visits the same directory twice. */
function walk(path: string, seen = new Set<string>()): string[] {
  const st = statSync(path);
  if (st.isFile()) return [path];
  if (!st.isDirectory()) return [];
  const real = realpathSync(path);
  if (seen.has(real)) return [];
  seen.add(real);
  const out: string[] = [];
  for (const name of readdirSync(path).sort()) {
    if (name.startsWith(".")) continue;
    out.push(...walk(join(path, name), seen));
  }
  return out;
}

const isYaml = (f: string) => [".yml", ".yaml"].includes(extname(f).toLowerCase());

export interface RuleSet {
  rules: Rule[];
  issues: RuleIssue[];
}

/** Load every rule under a path. Bad documents become issues; they never abort the load. */
export function loadRuleSet(path: string): RuleSet {
  const rules: Rule[] = [];
  const issues: RuleIssue[] = [];
  for (const f of walk(path).filter(isYaml)) {
    let text: string;
    try {
      text = readFileSync(f, "utf8");
    } catch (e) {
      issues.push({ source: f, message: `cannot read file: ${(e as Error).message}` });
      continue;
    }
    const r = parseRuleFile(text, f);
    rules.push(...r.rules);
    issues.push(...r.issues);
  }
  return { rules, issues };
}

/** Scenarios are test fixtures, so loading is strict: any error aborts with the file name. */
export function loadScenarios(path: string): Scenario[] {
  const all = walk(path)
    .filter(isYaml)
    .flatMap((f) => parseScenarios(readFileSync(f, "utf8"), f));
  const seen = new Set<string>();
  for (const s of all) {
    if (seen.has(s.id)) throw new Error(`Duplicate scenario id "${s.id}" (${s.source})`);
    seen.add(s.id);
  }
  return all;
}
