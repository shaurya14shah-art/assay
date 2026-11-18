import { describe, expect, it } from "vitest";
import { conditionUnsupported, expandPattern, parseCondition } from "../src/sigma/condition.js";
import { parseRules } from "../src/sigma/parse.js";
import { evaluateRule } from "../src/sigma/evaluate.js";

const rule = (detection: string, extra = "") =>
  parseRules(`title: t\nlogsource: { category: process_creation, product: windows }\n${extra}detection:\n${detection}`)[0]!;

describe("condition parser", () => {
  it("honours precedence: not > and > or", () => {
    expect(parseCondition("a or b and not c")).toEqual({
      type: "or",
      left: { type: "ref", name: "a" },
      right: {
        type: "and",
        left: { type: "ref", name: "b" },
        right: { type: "not", operand: { type: "ref", name: "c" } },
      },
    });
  });
  it("parses quantifiers", () => {
    expect(parseCondition("1 of sel_*")).toEqual({ type: "quant", quantifier: "any", pattern: "sel_*" });
    expect(parseCondition("all of them")).toEqual({ type: "quant", quantifier: "all", pattern: "them" });
  });
  it("rejects malformed conditions", () => {
    expect(() => parseCondition("a and")).toThrow();
    expect(() => parseCondition("(a or b")).toThrow();
    expect(() => parseCondition("2 of them")).toThrow(/Unsupported quantifier/);
    expect(() => parseCondition("a b")).toThrow();
  });
  it("expands patterns", () => {
    expect(expandPattern("sel_*", ["sel_a", "sel_b", "filter"])).toEqual(["sel_a", "sel_b"]);
    expect(expandPattern("them", ["a", "b"])).toEqual(["a", "b"]);
  });
  it("flags aggregation as unsupported", () => {
    expect(conditionUnsupported("sel | count() > 3")).toBeTruthy();
    expect(conditionUnsupported("sel and not f")).toBeUndefined();
  });
});

describe("rule evaluation", () => {
  const ls = { category: "process_creation", product: "windows" };
  it("AND across fields, OR across list of maps", () => {
    const r = rule(`  sel:\n    - { Image|endswith: '\\a.exe', User: bob }\n    - { Image|endswith: '\\b.exe' }\n  condition: sel`);
    expect(evaluateRule(r, { Image: "C:\\x\\a.exe", User: "bob" }, ls)).not.toBeNull();
    expect(evaluateRule(r, { Image: "C:\\x\\a.exe", User: "eve" }, ls)).toBeNull();
    expect(evaluateRule(r, { Image: "C:\\x\\b.exe", User: "eve" }, ls)).not.toBeNull();
  });
  it("filter pattern: selection and not filter", () => {
    const r = rule(`  sel: { Image|endswith: '\\cmd.exe' }\n  filter: { ParentImage|endswith: '\\explorer.exe' }\n  condition: sel and not filter`);
    expect(evaluateRule(r, { Image: "\\cmd.exe", ParentImage: "\\word.exe" }, ls)).not.toBeNull();
    expect(evaluateRule(r, { Image: "\\cmd.exe", ParentImage: "\\explorer.exe" }, ls)).toBeNull();
  });
  it("1 of / all of with wildcards", () => {
    const r = rule(`  s_a: { A: 1 }\n  s_b: { B: 2 }\n  condition: all of s_*`);
    expect(evaluateRule(r, { A: 1, B: 2 }, ls)).not.toBeNull();
    expect(evaluateRule(r, { A: 1 }, ls)).toBeNull();
    const r2 = rule(`  s_a: { A: 1 }\n  s_b: { B: 2 }\n  condition: 1 of them`);
    expect(evaluateRule(r2, { B: 2 }, ls)?.selections).toEqual(["s_b"]);
  });
  it("keyword selections search every value", () => {
    const r = rule(`  kw:\n    - mimikatz\n    - 'sekurlsa::*'\n  condition: kw`);
    expect(evaluateRule(r, { Foo: { Bar: "ran MIMIKATZ.exe" } }, ls)).not.toBeNull();
    expect(evaluateRule(r, { Foo: "nothing" }, ls)).toBeNull();
  });
  it("list of conditions is an OR", () => {
    const r = rule(`  a: { A: 1 }\n  b: { B: 1 }\n  condition:\n    - a\n    - b`);
    expect(evaluateRule(r, { B: 1 }, ls)).not.toBeNull();
  });
  it("respects logsource", () => {
    const r = rule(`  a: { A: 1 }\n  condition: a`);
    expect(evaluateRule(r, { A: 1 }, { category: "process_creation", product: "linux" })).toBeNull();
    expect(evaluateRule(r, { A: 1 }, undefined)).toBeNull();
    expect(evaluateRule(r, { A: 1 }, { ...ls, service: "extra" })).not.toBeNull();
  });
  it("unsupported rules never match and are flagged", () => {
    const r = rule(`  a: { A: 1 }\n  condition: a | count() > 2`);
    expect(r.unsupported).toBeTruthy();
    expect(evaluateRule(r, { A: 1 }, ls)).toBeNull();
  });
  it("rejects dangling references and empty patterns", () => {
    expect(() => rule(`  a: { A: 1 }\n  condition: a and zzz`)).toThrow(/unknown selection/);
    expect(() => rule(`  a: { A: 1 }\n  condition: 1 of nope_*`)).toThrow(/matches no selections/);
  });
  it("extracts ATT&CK technique and tactic tags", () => {
    const r = rule(`  a: { A: 1 }\n  condition: a`, `tags: [attack.execution, attack.t1059.001, attack.g0016, attack.credential-access]\n`);
    expect(r.techniques).toEqual(["T1059.001"]);
    expect(r.tactics).toEqual(["execution", "credential_access"]);
  });
  it("marks correlation rules unsupported", () => {
    const [r] = parseRules(`title: c\ncorrelation:\n  type: event_count\n`);
    expect(r!.unsupported).toMatch(/correlation/);
  });
});
