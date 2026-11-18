import { evaluateRule, logsourceApplies } from "./sigma/evaluate.js";
import type { LogSource, Rule, RuleIssue } from "./sigma/types.js";
import type { Scenario } from "./scenarios.js";

export interface Firing {
  ruleId: string;
  ruleTitle: string;
  selections: string[];
  eventIndex: number;
}

export interface ScenarioResult {
  scenarioId: string;
  name: string;
  technique?: string;
  malicious: boolean;
  detected: boolean;
  firings: Firing[];
}

export type TechniqueStatus = "covered" | "gap";

export interface TechniqueResult {
  technique: string;
  tactic?: string;
  scenarios: number;
  detected: number;
  status: TechniqueStatus;
  /** Rules that fired on at least one of this technique's scenarios. */
  rules: string[];
  /** Rules that claim this technique via tags but never fired on its scenarios. */
  claimedButSilent: string[];
}

export interface CoverageReport {
  summary: {
    rules: number;
    unsupportedRules: number;
    invalidRules: number;
    maliciousScenarios: number;
    detectedScenarios: number;
    detectionRate: number;
    techniques: number;
    coveredTechniques: number;
    techniqueCoverage: number;
    benignScenarios: number;
    falsePositives: number;
  };
  techniques: TechniqueResult[];
  scenarios: ScenarioResult[];
  falsePositives: ScenarioResult[];
  unsupported: Array<{ ruleId: string; title: string; reason: string }>;
  /** Rule documents that failed to load. They are excluded from every other number. */
  invalid: RuleIssue[];
  /** Rule ids used by more than one rule; results for these ids are ambiguous. */
  duplicateRuleIds: string[];
  /** Rules that never fired on any scenario (malicious or benign). */
  deadRules: Array<{ ruleId: string; title: string }>;
}

const round = (n: number) => Math.round(n * 10000) / 10000;

export const LEVELS = ["informational", "low", "medium", "high", "critical"] as const;
export type Level = (typeof LEVELS)[number];

/** Keep rules at or above a Sigma level. Rules with an unknown level are treated as medium. */
export function filterByLevel(rules: Rule[], min: Level): Rule[] {
  const rank = (l: string) => {
    const i = LEVELS.indexOf(l.toLowerCase() as Level);
    return i < 0 ? LEVELS.indexOf("medium") : i;
  };
  return rules.filter((r) => rank(r.level) >= LEVELS.indexOf(min));
}

export function runCoverage(rules: Rule[], scenarios: Scenario[], issues: RuleIssue[] = []): CoverageReport {
  // Rules are filtered by logsource once per distinct logsource, not once per event.
  const live = rules.filter((r) => !r.unsupported);
  const byLogsource = new Map<string, Rule[]>();
  const rulesFor = (ls: LogSource): Rule[] => {
    const key = `${ls.category ?? ""}|${ls.product ?? ""}|${ls.service ?? ""}`;
    let hit = byLogsource.get(key);
    if (!hit) {
      hit = live.filter((r) => logsourceApplies(r.logsource, ls));
      byLogsource.set(key, hit);
    }
    return hit;
  };

  const results: ScenarioResult[] = scenarios.map((sc) => {
    const firings: Firing[] = [];
    sc.events.forEach(({ fields, logsource }, eventIndex) => {
      for (const rule of rulesFor(logsource)) {
        const m = evaluateRule(rule, fields, logsource);
        if (m) firings.push({ ruleId: rule.id, ruleTitle: rule.title, selections: m.selections, eventIndex });
      }
    });
    return {
      scenarioId: sc.id,
      name: sc.name,
      technique: sc.technique,
      malicious: sc.malicious,
      detected: firings.length > 0,
      firings,
    };
  });

  const malicious = results.filter((r) => r.malicious);
  const benign = results.filter((r) => !r.malicious);
  const falsePositives = benign.filter((r) => r.detected);

  const byTech = new Map<string, ScenarioResult[]>();
  for (const r of malicious) {
    const t = r.technique as string;
    byTech.set(t, [...(byTech.get(t) ?? []), r]);
  }
  const tacticOf = new Map<string, string | undefined>();
  for (const sc of scenarios) if (sc.technique && !tacticOf.has(sc.technique)) tacticOf.set(sc.technique, sc.tactic);

  const techniques: TechniqueResult[] = [...byTech.entries()]
    .map(([technique, rs]) => {
      const firedRules = new Set(rs.flatMap((r) => r.firings.map((f) => f.ruleId)));
      const claimed = rules.filter((r) => r.techniques.includes(technique)).map((r) => r.id);
      const detected = rs.filter((r) => r.detected).length;
      return {
        technique,
        tactic: tacticOf.get(technique),
        scenarios: rs.length,
        detected,
        status: (detected > 0 ? "covered" : "gap") as TechniqueStatus,
        rules: [...firedRules].sort(),
        claimedButSilent: claimed.filter((id) => !firedRules.has(id)).sort(),
      };
    })
    .sort((a, b) => a.technique.localeCompare(b.technique));

  const everFired = new Set(results.flatMap((r) => r.firings.map((f) => f.ruleId)));
  const unsupported = rules
    .filter((r) => r.unsupported)
    .map((r) => ({ ruleId: r.id, title: r.title, reason: r.unsupported as string }));
  const deadRules = rules
    .filter((r) => !r.unsupported && !everFired.has(r.id))
    .map((r) => ({ ruleId: r.id, title: r.title }));

  const detectedScenarios = malicious.filter((r) => r.detected).length;
  const coveredTechniques = techniques.filter((t) => t.status === "covered").length;
  const idCounts = new Map<string, number>();
  for (const r of rules) idCounts.set(r.id, (idCounts.get(r.id) ?? 0) + 1);
  const duplicateRuleIds = [...idCounts].filter(([, n]) => n > 1).map(([id]) => id).sort();

  return {
    summary: {
      rules: rules.length,
      unsupportedRules: unsupported.length,
      invalidRules: issues.length,
      maliciousScenarios: malicious.length,
      detectedScenarios,
      detectionRate: malicious.length ? round(detectedScenarios / malicious.length) : 0,
      techniques: techniques.length,
      coveredTechniques,
      techniqueCoverage: techniques.length ? round(coveredTechniques / techniques.length) : 0,
      benignScenarios: benign.length,
      falsePositives: falsePositives.length,
    },
    techniques,
    scenarios: results,
    falsePositives,
    unsupported,
    invalid: issues,
    duplicateRuleIds,
    deadRules,
  };
}

export interface GateOptions {
  minTechniqueCoverage?: number;
  maxFalsePositives?: number;
  /** A previous report's JSON; coverage may not regress below it. */
  baseline?: CoverageReport;
  /** Fail when any rule document is invalid. */
  strict?: boolean;
}

export interface GateResult {
  passed: boolean;
  failures: string[];
}

export function checkGate(report: CoverageReport, opts: GateOptions): GateResult {
  const failures: string[] = [];
  const s = report.summary;
  if (opts.strict && s.invalidRules > 0) failures.push(`${s.invalidRules} invalid rule document(s)`);
  if (opts.minTechniqueCoverage !== undefined && s.techniqueCoverage < opts.minTechniqueCoverage) {
    failures.push(
      `technique coverage ${(s.techniqueCoverage * 100).toFixed(1)}% is below the required ${(opts.minTechniqueCoverage * 100).toFixed(1)}%`,
    );
  }
  if (opts.maxFalsePositives !== undefined && s.falsePositives > opts.maxFalsePositives) {
    failures.push(`${s.falsePositives} false positive scenario(s); allowed ${opts.maxFalsePositives}`);
  }
  if (opts.baseline) {
    const was = new Map(opts.baseline.techniques.map((t) => [t.technique, t.status]));
    for (const t of report.techniques) {
      if (was.get(t.technique) === "covered" && t.status === "gap") failures.push(`regression: ${t.technique} was covered, now a gap`);
    }
    if (s.falsePositives > opts.baseline.summary.falsePositives) {
      failures.push(`regression: false positives rose from ${opts.baseline.summary.falsePositives} to ${s.falsePositives}`);
    }
  }
  return { passed: failures.length === 0, failures };
}
