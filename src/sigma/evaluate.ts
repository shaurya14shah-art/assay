import { expandPattern } from "./condition.js";
import { collectStrings } from "./matchers.js";
import type { ConditionNode, Event, LogSource, Rule, Selection } from "./types.js";

export interface Match {
  rule: Rule;
  /** Names of selections that evaluated true: the explanation for why the rule fired. */
  selections: string[];
}

/** Per-event memo so keyword selections flatten the event at most once. */
interface Ctx {
  event: Event;
  strings?: string[];
  cache: Map<string, boolean>;
}

function selectionMatches(sel: Selection, ctx: Ctx): boolean {
  for (const alt of sel.alternatives) {
    if (alt.kind === "map") {
      if (alt.fields.every((f) => f.test(ctx.event))) return true;
    } else {
      const strings = (ctx.strings ??= collectStrings(ctx.event));
      if (alt.patterns.some((p) => strings.some((s) => p.test(s)))) return true;
    }
  }
  return false;
}

/** A rule applies to an event only if every logsource key the rule names equals the event's. */
export function logsourceApplies(rule: LogSource, event: LogSource | undefined): boolean {
  for (const k of ["category", "product", "service"] as const) {
    const want = rule[k];
    if (want === undefined) continue;
    if (event?.[k]?.toLowerCase() !== want) return false;
  }
  return true;
}

function resolve(name: string, rule: Rule, ctx: Ctx): boolean {
  const hit = ctx.cache.get(name);
  if (hit !== undefined) return hit;
  const sel = rule.selections.get(name);
  const result = sel ? selectionMatches(sel, ctx) : false;
  ctx.cache.set(name, result);
  return result;
}

function evalNode(node: ConditionNode, rule: Rule, ctx: Ctx): boolean {
  switch (node.type) {
    case "ref":
      return resolve(node.name, rule, ctx);
    case "and":
      return evalNode(node.left, rule, ctx) && evalNode(node.right, rule, ctx);
    case "or":
      return evalNode(node.left, rule, ctx) || evalNode(node.right, rule, ctx);
    case "not":
      return !evalNode(node.operand, rule, ctx);
    case "quant": {
      const names = node.names ?? expandPattern(node.pattern, [...rule.selections.keys()]);
      return node.quantifier === "all" ? names.every((n) => resolve(n, rule, ctx)) : names.some((n) => resolve(n, rule, ctx));
    }
  }
}

/**
 * Evaluate one rule against one event. Returns a Match (with the selections that fired)
 * or null. Unsupported rules never match; callers must report them separately.
 */
export function evaluateRule(rule: Rule, event: Event, logsource?: LogSource): Match | null {
  if (rule.unsupported) return null;
  if (!logsourceApplies(rule.logsource, logsource)) return null;
  const ctx: Ctx = { event, cache: new Map() };
  if (!rule.conditions.some((c) => evalNode(c, rule, ctx))) return null;
  const selections = [...rule.selections.keys()].filter((n) => resolve(n, rule, ctx));
  return { rule, selections };
}
