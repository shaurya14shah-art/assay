import { describe, expect, it } from "vitest";
import { base64Variants, cidrContains, compileFieldMatcher, windashVariants, wildcardToRegex } from "../src/sigma/matchers.js";

const m = (key: string, raw: unknown, event: Record<string, unknown>) => compileFieldMatcher(key, raw).test(event);

describe("wildcards", () => {
  it("matches * and ? case-insensitively", () => {
    expect(wildcardToRegex("C:\\Win*\\cmd.exe").test("c:\\windows\\system32\\CMD.EXE")).toBe(true);
    expect(wildcardToRegex("C:\\Win*\\cmd.exe").test("c:\\windows\\system32\\powershell.exe")).toBe(false);
    expect(wildcardToRegex("*\\cmd.exe").test("C:\\Windows\\System32\\CMD.EXE")).toBe(true);
    expect(wildcardToRegex("ab?d").test("ABcD")).toBe(true);
    expect(wildcardToRegex("ab?d").test("abd")).toBe(false);
  });
  it("treats \\* as a literal star and other backslashes as literal", () => {
    expect(wildcardToRegex("a\\*b").test("a*b")).toBe(true);
    expect(wildcardToRegex("a\\*b").test("axb")).toBe(false);
    expect(wildcardToRegex("C:\\Temp\\x").test("C:\\Temp\\x")).toBe(true);
  });
  it("regression: a trailing backslash does not escape the contains wildcard", () => {
    expect(m("CommandLine|contains", "\\Users\\Public\\", { CommandLine: "run C:\\Users\\Public\\up.exe" })).toBe(true);
  });
});

describe("modifiers", () => {
  it("contains / startswith / endswith", () => {
    expect(m("A|contains", "mid", { A: "a mid b" })).toBe(true);
    expect(m("A|startswith", "a m", { A: "a mid b" })).toBe(true);
    expect(m("A|startswith", "mid", { A: "a mid b" })).toBe(false);
    expect(m("A|endswith", "d b", { A: "a mid b" })).toBe(true);
  });
  it("list values are OR; |all makes them AND", () => {
    expect(m("A|contains", ["x", "mid"], { A: "a mid b" })).toBe(true);
    expect(m("A|contains|all", ["x", "mid"], { A: "a mid b" })).toBe(false);
    expect(m("A|contains|all", ["a", "mid"], { A: "a mid b" })).toBe(true);
  });
  it("re is case-sensitive unless |i", () => {
    expect(m("A|re", "^Mid", { A: "mid" })).toBe(false);
    expect(m("A|re|i", "^Mid", { A: "mid" })).toBe(true);
  });
  it("cidr", () => {
    expect(cidrContains("10.0.0.0/8", "10.200.3.4")).toBe(true);
    expect(cidrContains("10.0.0.0/8", "11.0.0.1")).toBe(false);
    expect(cidrContains("192.168.1.0/24", "192.168.1.255")).toBe(true);
    expect(cidrContains("192.168.1.0/24", "not-an-ip")).toBe(false);
    expect(m("Ip|cidr", ["10.0.0.0/8", "172.16.0.0/12"], { Ip: "172.20.1.1" })).toBe(true);
  });
  it("numeric comparison", () => {
    expect(m("N|gt", 5, { N: 6 })).toBe(true);
    expect(m("N|gte", 5, { N: 5 })).toBe(true);
    expect(m("N|lt", 5, { N: "4" })).toBe(true);
    expect(m("N|lt", 5, { N: "abc" })).toBe(false);
  });
  it("exists", () => {
    expect(m("A|exists", true, { A: "x" })).toBe(true);
    expect(m("A|exists", true, {})).toBe(false);
    expect(m("A|exists", false, {})).toBe(true);
  });
  it("null matches missing or empty", () => {
    expect(m("A", null, {})).toBe(true);
    expect(m("A", null, { A: "" })).toBe(true);
    expect(m("A", null, { A: "x" })).toBe(false);
  });
  it("windash expands leading dashes", () => {
    expect(windashVariants("-enc")).toContain("/enc");
    expect(m("C|contains|windash", " -enc ", { C: "powershell /enc abc" })).toBe(true);
    expect(windashVariants("a-b")).toEqual(["a-b"]);
  });
  it("base64 and base64offset", () => {
    expect(base64Variants("hello", false)).toEqual([Buffer.from("hello").toString("base64")]);
    // A 1-byte prefix shifts the payload off the 3-byte base64 boundary, so only the offset form finds it.
    const shifted = Buffer.from("x whoami yy").toString("base64");
    expect(m("C|base64offset|contains", "whoami", { C: shifted })).toBe(true);
    expect(m("C|base64|contains", "whoami", { C: shifted })).toBe(false);
    // Aligned payload (3-byte prefix) is found by plain base64 as well.
    const aligned = Buffer.from("xx whoami yy").toString("base64");
    expect(m("C|base64|contains", "whoami", { C: aligned })).toBe(true);
  });
  it("rejects unknown modifiers and bad regexes", () => {
    expect(() => compileFieldMatcher("A|nonsense", "x")).toThrow(/Unknown modifier/);
    expect(() => compileFieldMatcher("A|re", "(")).toThrow(/invalid regex/);
  });
  it("field lookup is case-insensitive and supports dotted paths", () => {
    expect(m("commandline", "x", { CommandLine: "x" })).toBe(true);
    expect(m("process.name", "cmd.exe", { process: { name: "cmd.exe" } })).toBe(true);
  });
  it("array event values match if any element matches", () => {
    expect(m("Tags", "b", { Tags: ["a", "b"] })).toBe(true);
  });
  it("numbers compare as numbers and as strings", () => {
    expect(m("EventID", 4625, { EventID: 4625 })).toBe(true);
    expect(m("EventID", 4625, { EventID: "4625" })).toBe(true);
    expect(m("EventID", 4625, { EventID: 4624 })).toBe(false);
  });
});
