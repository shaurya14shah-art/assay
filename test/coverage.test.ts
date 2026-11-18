import { describe, expect, it } from "vitest";
import { checkGate, runCoverage } from "../src/coverage.js";
import { loadRuleSet, loadScenarios } from "../src/io.js";
import { parseScenarios } from "../src/scenarios.js";
import { parseRules } from "../src/sigma/parse.js";

const R = `title: Whoami
id: r1
tags: [attack.t1033]
logsource: { category: process_creation, product: windows }
detection:
  sel: { Image|endswith: '\\whoami.exe' }
  condition: sel
---
title: Never fires
id: r2
tags: [attack.t1033]
logsource: { category: process_creation, product: windows }
detection:
  sel: { Image|endswith: '\\nothing.exe' }
  condition: sel
`;
const S = `id: s1
name: whoami run
technique: T1033
logsource: { category: process_creation, product: windows }
events: [ { Image: 'C:\\Windows\\System32\\whoami.exe' } ]
---
id: s2
name: no rule for this
technique: T1082
logsource: { category: process_creation, product: windows }
events: [ { Image: 'C:\\Windows\\System32\\systeminfo.exe' } ]
---
id: b1
name: benign whoami by IT
malicious: false
logsource: { category: process_creation, product: windows }
events: [ { Image: 'C:\\Windows\\System32\\whoami.exe' } ]
`;

describe("coverage runner", () => {
  const report = runCoverage(parseRules(R), parseScenarios(S));
  it("computes technique coverage, gaps, false positives and dead rules", () => {
    expect(report.summary.techniques).toBe(2);
    expect(report.summary.coveredTechniques).toBe(1);
    expect(report.summary.techniqueCoverage).toBe(0.5);
    expect(report.summary.falsePositives).toBe(1);
    expect(report.deadRules.map((r) => r.ruleId)).toEqual(["r2"]);
    expect(report.techniques.find((t) => t.technique === "T1082")?.status).toBe("gap");
  });
  it("reports tagged-but-silent rules", () => {
    expect(report.techniques.find((t) => t.technique === "T1033")?.claimedButSilent).toEqual(["r2"]);
  });
  it("records which selection fired", () => {
    expect(report.scenarios.find((s) => s.scenarioId === "s1")?.firings[0]?.selections).toEqual(["sel"]);
  });
});

describe("gate", () => {
  const rules = parseRules(R);
  const scenarios = parseScenarios(S);
  const report = runCoverage(rules, scenarios);
  it("fails below minimum coverage and above allowed false positives", () => {
    const g = checkGate(report, { minTechniqueCoverage: 0.9, maxFalsePositives: 0 });
    expect(g.passed).toBe(false);
    expect(g.failures).toHaveLength(2);
    expect(checkGate(report, { minTechniqueCoverage: 0.5, maxFalsePositives: 1 }).passed).toBe(true);
  });
  it("detects regressions against a baseline", () => {
    const better = runCoverage(parseRules(R), parseScenarios(S));
    const worse = runCoverage(parseRules(R).slice(1), parseScenarios(S));
    const g = checkGate(worse, { baseline: better });
    expect(g.passed).toBe(false);
    expect(g.failures.join(" ")).toMatch(/T1033 was covered/);
  });
});

describe("scenario validation", () => {
  it("requires a technique on malicious scenarios and valid ids", () => {
    expect(() => parseScenarios(`id: x\nevents: [ {A: 1} ]\n`)).toThrow(/need a technique/);
    expect(() => parseScenarios(`id: x\ntechnique: banana\nevents: [ {A: 1} ]\n`)).toThrow(/invalid technique/);
    expect(() => parseScenarios(`id: x\ntechnique: T1\nevents: []\n`)).toThrow();
  });
});

describe("bundled example (pinned so regressions are visible)", () => {
  const set = loadRuleSet("examples/rules");
  const report = runCoverage(set.rules, loadScenarios("scenarios"), set.issues);
  it("has the expected shape", () => {
    expect(report.summary.rules).toBe(17);
    expect(report.summary.unsupportedRules).toBe(1);
    expect(report.summary.falsePositives).toBe(2);
  });
  it("catches the known gaps honestly", () => {
    const gaps = report.techniques.filter((t) => t.status === "gap").map((t) => t.technique);
    expect(gaps).toEqual(["T1053.003", "T1055", "T1110", "T1136.001"]);
    const lsass = report.techniques.find((t) => t.technique === "T1003.001")!;
    expect(`${lsass.detected}/${lsass.scenarios}`).toBe("2/3");
  });
  it("fires the writable-path schtasks rule on both the attack and the benign admin task", () => {
    expect(report.scenarios.find((s) => s.scenarioId === "SC-W-020")?.detected).toBe(true);
    expect(report.falsePositives.map((f) => f.scenarioId).sort()).toEqual(["SC-B-003", "SC-LB-001"]);
    expect(report.deadRules).toEqual([]);
  });
});
