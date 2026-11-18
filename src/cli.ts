#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { LEVELS, checkGate, filterByLevel, runCoverage, type CoverageReport, type Level } from "./coverage.js";
import { loadRuleSet, loadScenarios } from "./io.js";
import { formatText } from "./report.js";
import { SigmaError } from "./sigma/types.js";

const HELP = `assay: unit tests for detection rules

Usage:
  assay run --rules <path> --scenarios <path> [options]
  assay validate --rules <path>

Options for run:
  --json <file>                 write the full report as JSON
  --baseline <file>             fail if coverage regresses against a previous --json report
  --min-coverage <0-100>        fail if technique coverage is below this percentage
  --max-false-positives <n>     fail if more than n benign scenarios trigger a rule
  --strict                      fail if any rule document is invalid
  --min-level <level>           only evaluate rules at or above this level
                                (informational, low, medium, high, critical)
  --quiet                       print only the summary line

validate exits 1 when any rule document is invalid.
`;

function fail(msg: string, code = 2): never {
  process.stderr.write(`assay: ${msg}\n`);
  process.exit(code);
}

function main(): void {
  const [cmd, ...rest] = process.argv.slice(2);
  if (!cmd || cmd === "--help" || cmd === "-h") {
    process.stdout.write(HELP);
    return;
  }

  const { values } = parseArgs({
    args: rest,
    options: {
      rules: { type: "string" },
      scenarios: { type: "string" },
      json: { type: "string" },
      baseline: { type: "string" },
      "min-coverage": { type: "string" },
      "max-false-positives": { type: "string" },
      quiet: { type: "boolean" },
      strict: { type: "boolean" },
      "min-level": { type: "string" },
    },
  });
  const minLevel = values["min-level"]?.toLowerCase();
  if (minLevel !== undefined && !(LEVELS as readonly string[]).includes(minLevel)) {
    fail(`--min-level must be one of ${LEVELS.join(", ")}`);
  }

  try {
    if (cmd === "validate") {
      if (!values.rules) fail("validate needs --rules <path>");
      const { rules, issues } = loadRuleSet(values.rules);
      const bad = rules.filter((r) => r.unsupported);
      process.stdout.write(`${rules.length} rule(s) loaded, ${bad.length} unsupported, ${issues.length} invalid\n`);
      if (!values.quiet) {
        for (const r of bad) process.stdout.write(`  unsupported: ${r.title}: ${r.unsupported}\n`);
        for (const i of issues) process.stdout.write(`  invalid: ${i.source ?? "?"}: ${i.message}\n`);
      }
      if (issues.length) process.exit(1);
      return;
    }

    if (cmd !== "run") fail(`unknown command "${cmd}"\n\n${HELP}`);
    if (!values.rules || !values.scenarios) fail("run needs --rules <path> and --scenarios <path>");

    const loaded = loadRuleSet(values.rules);
    const rules = minLevel ? filterByLevel(loaded.rules, minLevel as Level) : loaded.rules;
    const scenarios = loadScenarios(values.scenarios);
    const report = runCoverage(rules, scenarios, loaded.issues);

    if (values.json) writeFileSync(values.json, JSON.stringify(report, null, 2) + "\n");

    const s = report.summary;
    if (values.quiet) {
      process.stdout.write(
        `techniques ${s.coveredTechniques}/${s.techniques} (${(s.techniqueCoverage * 100).toFixed(1)}%), false positives ${s.falsePositives}\n`,
      );
    } else process.stdout.write(formatText(report) + "\n");

    const num = (v: string | undefined, name: string): number | undefined => {
      if (v === undefined) return undefined;
      const n = Number(v);
      if (!Number.isFinite(n) || n < 0) fail(`${name} must be a non-negative number`);
      return n;
    };
    const minCov = num(values["min-coverage"], "--min-coverage");
    const baseline = values.baseline ? (JSON.parse(readFileSync(values.baseline, "utf8")) as CoverageReport) : undefined;
    const gate = checkGate(report, {
      minTechniqueCoverage: minCov === undefined ? undefined : minCov / 100,
      maxFalsePositives: num(values["max-false-positives"], "--max-false-positives"),
      baseline,
      strict: values.strict,
    });
    if (!gate.passed) {
      process.stdout.write("\nGATE FAILED\n" + gate.failures.map((f) => `  - ${f}`).join("\n") + "\n");
      process.exit(1);
    }
  } catch (e) {
    if (e instanceof SigmaError) fail(e.message);
    throw e;
  }
}

main();
