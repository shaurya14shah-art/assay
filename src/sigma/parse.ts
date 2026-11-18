import { parseAllDocuments } from "yaml";
import { conditionUnsupported, expandPattern, parseCondition } from "./condition.js";
import { compileFieldMatcher, wildcardToRegex } from "./matchers.js";
import {
  SigmaError,
  UnsupportedError,
  type ConditionNode,
  type KeywordMatcher,
  type LogSource,
  type MapMatcher,
  type Rule,
  type RuleIssue,
  type Scalar,
  type Selection,
} from "./types.js";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

/** `attack.t1059.001` -> `T1059.001`; tactics (`attack.execution`) returned separately. */
export function splitAttackTags(tags: unknown): { techniques: string[]; tactics: string[] } {
  const techniques = new Set<string>();
  const tactics = new Set<string>();
  if (!Array.isArray(tags)) return { techniques: [], tactics: [] };
  for (const tag of tags) {
    if (typeof tag !== "string") continue;
    const t = /^attack\.(t\d{4}(?:\.\d{3})?)$/i.exec(tag.trim());
    if (t) {
      techniques.add((t[1] as string).toUpperCase());
      continue;
    }
    const tac = /^attack\.([a-z][a-z_-]+)$/i.exec(tag.trim());
    // Group (g0001) and software (s0001) tags are not tactics.
    if (tac && !/^[gs]\d{4}$/i.test(tac[1] as string)) tactics.add((tac[1] as string).toLowerCase().replace(/-/g, "_"));
  }
  return { techniques: [...techniques], tactics: [...tactics] };
}

function compileSelection(name: string, raw: unknown): Selection {
  if (raw === null || raw === undefined) throw new SigmaError(`Selection "${name}" is empty`);
  const alternatives: Array<MapMatcher | KeywordMatcher> = [];
  const items: unknown[] = Array.isArray(raw) ? raw : [raw];
  if (items.length === 0) throw new SigmaError(`Selection "${name}" is empty`);

  const allScalar = items.every((i) => !isObj(i) && !Array.isArray(i));
  const allMaps = items.every(isObj);
  if (!allScalar && !allMaps) throw new SigmaError(`Selection "${name}" mixes maps, lists and plain values`);

  if (allScalar) {
    alternatives.push({
      kind: "keywords",
      patterns: (items as Scalar[]).map((v) => wildcardToRegex(String(v), { prefix: true, suffix: true })),
    });
  } else {
    for (const item of items as Obj[]) {
      const entries = Object.entries(item);
      if (entries.length === 0) throw new SigmaError(`Selection "${name}" contains an empty map`);
      alternatives.push({ kind: "map", fields: entries.map(([k, v]) => compileFieldMatcher(k, v)) });
    }
  }
  return { name, alternatives };
}

function walk(node: ConditionNode, visit: (n: ConditionNode) => void): void {
  visit(node);
  if (node.type === "and" || node.type === "or") {
    walk(node.left, visit);
    walk(node.right, visit);
  } else if (node.type === "not") walk(node.operand, visit);
}

function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function blankRule(doc: Obj, source?: string): Rule {
  const { techniques, tactics } = splitAttackTags(doc.tags);
  const ls = isObj(doc.logsource) ? doc.logsource : {};
  const logsource: LogSource = {};
  for (const k of ["category", "product", "service"] as const) {
    if (typeof ls[k] === "string") logsource[k] = (ls[k] as string).toLowerCase();
  }
  const title = str(doc.title) ?? "(untitled)";
  return {
    id: str(doc.id) ?? title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""),
    title,
    level: str(doc.level) ?? "medium",
    status: str(doc.status) ?? "experimental",
    description: (str(doc.description) ?? "").trim(),
    techniques,
    tactics,
    logsource,
    selections: new Map(),
    conditions: [],
    source,
  };
}

/** Parse one Sigma rule document that is already a JS object. Throws SigmaError if invalid. */
export function parseRuleObject(doc: Obj, source?: string): Rule {
  const rule = blankRule(doc, source);
  const fail = (msg: string): never => {
    throw new SigmaError(`Rule "${rule.title}": ${msg}`);
  };

  if ("correlation" in doc) {
    rule.unsupported = "correlation rules";
    return rule;
  }
  if ("filter" in doc && !("detection" in doc)) {
    rule.unsupported = "meta filter rules";
    return rule;
  }
  const detection = doc.detection;
  if (!isObj(detection)) fail("missing detection block");
  const { condition, timeframe: _timeframe, ...selectionDefs } = detection as Obj;
  if (condition === undefined || condition === null) fail("missing condition");

  const condList = Array.isArray(condition) ? condition : [condition];
  if (condList.length === 0) fail("empty condition list");
  const condStrings = condList.map((c) => (typeof c === "string" ? c : fail("condition must be a string")));

  const unsupported = condStrings.map(conditionUnsupported).find(Boolean);
  if (unsupported) {
    rule.unsupported = unsupported;
    return rule;
  }
  if (Object.keys(selectionDefs).length === 0) fail("detection has no selections");

  for (const [name, raw] of Object.entries(selectionDefs)) {
    try {
      rule.selections.set(name, compileSelection(name, raw));
    } catch (e) {
      if (e instanceof UnsupportedError) {
        rule.unsupported = e.message;
        rule.selections.clear();
        return rule;
      }
      if (e instanceof SigmaError) fail(e.message);
      throw e;
    }
  }

  const names = [...rule.selections.keys()];
  for (const c of condStrings) {
    let ast: ConditionNode;
    try {
      ast = parseCondition(c);
    } catch (e) {
      if (e instanceof SigmaError) fail(e.message);
      throw e;
    }
    walk(ast, (n) => {
      if (n.type === "ref" && !rule.selections.has(n.name)) fail(`condition references unknown selection "${n.name}"`);
      if (n.type === "quant") {
        n.names = expandPattern(n.pattern, names);
        if (n.names.length === 0) fail(`"${n.pattern}" in condition matches no selections`);
      }
    });
    rule.conditions.push(ast);
  }
  return rule;
}

function deepMerge(base: Obj, over: Obj): Obj {
  const out: Obj = { ...base };
  for (const [k, v] of Object.entries(over)) {
    const prev = out[k];
    out[k] = isObj(prev) && isObj(v) ? deepMerge(prev, v) : v;
  }
  return out;
}

export interface RuleFile {
  rules: Rule[];
  issues: RuleIssue[];
}

/**
 * Parse a YAML string with one or more Sigma rules. Each document is isolated: an invalid
 * document becomes a RuleIssue and the rest still load. Supports Sigma v1 rule collections
 * (`action: global | reset | repeat`).
 */
export function parseRuleFile(yamlText: string, source?: string): RuleFile {
  const rules: Rule[] = [];
  const issues: RuleIssue[] = [];
  const docs = [...parseAllDocuments(yamlText)];
  let global: Obj | undefined;
  let previous: Obj | undefined;

  docs.forEach((d, idx) => {
    const where = docs.length > 1 ? `${source ?? "<input>"} (document ${idx + 1})` : source;
    if (d.errors.length > 0) {
      issues.push({ source: where, message: `YAML error: ${d.errors[0]?.message.split("\n")[0]}` });
      return;
    }
    let js: unknown;
    try {
      js = d.toJS({ maxAliasCount: 50 });
    } catch (e) {
      issues.push({ source: where, message: `YAML error: ${(e as Error).message}` });
      return;
    }
    if (js === null || js === undefined) return;
    if (!isObj(js)) {
      issues.push({ source: where, message: "document is not a mapping" });
      return;
    }

    let doc: Obj = js;
    if (typeof doc.action === "string") {
      const { action, ...body } = doc;
      if (action === "global") {
        global = body;
        return;
      }
      if (action === "reset") {
        global = undefined;
        return;
      }
      if (action !== "repeat") {
        issues.push({ source: where, message: `unknown collection action "${String(action)}"` });
        return;
      }
      if (!previous) {
        issues.push({ source: where, message: 'action "repeat" with no previous rule' });
        return;
      }
      doc = deepMerge(previous, body);
    } else if (global) doc = deepMerge(global, doc);
    previous = doc;

    try {
      rules.push(parseRuleObject(doc, source));
    } catch (e) {
      if (!(e instanceof SigmaError)) throw e;
      issues.push({ source: where, title: str(doc.title), id: str(doc.id), message: e.message });
    }
  });
  return { rules, issues };
}

/** Strict variant: throws on the first invalid document. */
export function parseRules(yamlText: string, source?: string): Rule[] {
  const { rules, issues } = parseRuleFile(yamlText, source);
  const first = issues[0];
  if (first) throw new SigmaError(first.source ? `${first.source}: ${first.message}` : first.message);
  return rules;
}
