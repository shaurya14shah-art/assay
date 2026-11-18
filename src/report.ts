import type { CoverageReport } from "./coverage.js";

const pct = (n: number) => `${(n * 100).toFixed(1)}%`;

/** Plain-text report for terminals and CI logs. No colour so it stays readable in logs. */
export function formatText(report: CoverageReport): string {
  const s = report.summary;
  const lines: string[] = [];
  lines.push("ASSAY: detection coverage report (synthetic reference telemetry)");
  lines.push("");
  const extras = [
    s.unsupportedRules ? `${s.unsupportedRules} unsupported` : "",
    s.invalidRules ? `${s.invalidRules} invalid, not loaded` : "",
  ].filter(Boolean);
  lines.push(`Rules              ${s.rules}${extras.length ? `  (${extras.join(", ")})` : ""}`);
  lines.push(`Technique coverage ${s.coveredTechniques}/${s.techniques}  ${pct(s.techniqueCoverage)}`);
  lines.push(`Scenario detection ${s.detectedScenarios}/${s.maliciousScenarios}  ${pct(s.detectionRate)}`);
  lines.push(`False positives    ${s.falsePositives}/${s.benignScenarios} benign scenarios`);
  lines.push("");

  const w = Math.max(...report.techniques.map((t) => t.technique.length), 9);
  lines.push(`${"TECHNIQUE".padEnd(w)}  STATUS   HIT   CAUGHT BY`);
  for (const t of report.techniques) {
    const mark = t.status === "covered" ? "covered" : "GAP    ";
    const by = t.rules.length ? t.rules.join(", ") : "-";
    lines.push(`${t.technique.padEnd(w)}  ${mark}  ${`${t.detected}/${t.scenarios}`.padEnd(5)} ${by}`);
    if (t.claimedButSilent.length) lines.push(`${" ".repeat(w)}  note: tagged but silent -> ${t.claimedButSilent.join(", ")}`);
  }

  if (report.falsePositives.length) {
    lines.push("", "FALSE POSITIVES");
    for (const fp of report.falsePositives) {
      lines.push(`  ${fp.scenarioId}  ${fp.name}`);
      for (const f of fp.firings) lines.push(`    fired: ${f.ruleTitle} (${f.selections.join(", ")}) on event #${f.eventIndex}`);
    }
  }
  if (report.deadRules.length) {
    lines.push("", "RULES THAT NEVER FIRED");
    for (const r of report.deadRules) lines.push(`  ${r.ruleId}  ${r.title}`);
  }
  const LIMIT = 25;
  if (report.unsupported.length) {
    lines.push("", "UNSUPPORTED RULES (not evaluated)");
    for (const r of report.unsupported.slice(0, LIMIT)) lines.push(`  ${r.ruleId}  ${r.title}: ${r.reason}`);
    if (report.unsupported.length > LIMIT) lines.push(`  ... and ${report.unsupported.length - LIMIT} more (see --json)`);
  }
  if (report.invalid.length) {
    lines.push("", "INVALID RULES (not loaded)");
    for (const r of report.invalid.slice(0, LIMIT)) lines.push(`  ${r.source ?? "?"}: ${r.message}`);
    if (report.invalid.length > LIMIT) lines.push(`  ... and ${report.invalid.length - LIMIT} more (see --json)`);
  }
  if (report.duplicateRuleIds.length) {
    lines.push("", `DUPLICATE RULE IDS: ${report.duplicateRuleIds.join(", ")}`);
  }
  return lines.join("\n");
}
