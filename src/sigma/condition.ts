import { SigmaError, type ConditionNode } from "./types.js";

type Token =
  | { t: "lparen" }
  | { t: "rparen" }
  | { t: "and" }
  | { t: "or" }
  | { t: "not" }
  | { t: "of"; quantifier: "any" | "all" }
  | { t: "ident"; value: string };

/** True when the condition string uses aggregation or other features we cannot evaluate. */
export function conditionUnsupported(cond: string): string | undefined {
  if (/\|/.test(cond)) return "aggregation / pipe conditions (e.g. `| count()`)";
  if (/\b(near|temporal)\b/i.test(cond)) return "temporal / near conditions";
  return undefined;
}

function tokenize(input: string): Token[] {
  const tokens: Token[] = [];
  const re = /\s*(\(|\)|[^\s()]+)/y;
  let m: RegExpExecArray | null;
  while (re.lastIndex < input.length && (m = re.exec(input)) !== null) {
    const raw = m[1] as string;
    const lower = raw.toLowerCase();
    if (raw === "(") tokens.push({ t: "lparen" });
    else if (raw === ")") tokens.push({ t: "rparen" });
    else if (lower === "and") tokens.push({ t: "and" });
    else if (lower === "or") tokens.push({ t: "or" });
    else if (lower === "not") tokens.push({ t: "not" });
    else if (lower === "of") {
      // quantifier handled below via the previous token
      tokens.push({ t: "of", quantifier: "any" });
    } else tokens.push({ t: "ident", value: raw });
  }
  // Fold `<n|all> of` into a single quantifier marker.
  const folded: Token[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i] as Token;
    const next = tokens[i + 1];
    if (tok.t === "ident" && next && next.t === "of") {
      const q = tok.value.toLowerCase();
      if (q === "all") folded.push({ t: "of", quantifier: "all" });
      else if (/^\d+$/.test(q) && Number(q) >= 1) {
        // Sigma only defines `1 of`; treat any positive count as "any" but reject others.
        if (q !== "1") throw new SigmaError(`Unsupported quantifier "${q} of"; only "1 of" and "all of" are defined`);
        folded.push({ t: "of", quantifier: "any" });
      } else throw new SigmaError(`Unknown quantifier "${tok.value} of"`);
      i++;
    } else if (tok.t === "of") {
      throw new SigmaError('"of" must follow "1" or "all"');
    } else folded.push(tok);
  }
  return folded;
}

/**
 * Parse a Sigma condition into an AST.
 * Precedence (high to low): not, and, or. Parentheses override.
 */
export function parseCondition(input: string): ConditionNode {
  const tokens = tokenize(input);
  let pos = 0;

  const peek = (): Token | undefined => tokens[pos];

  function parseOr(): ConditionNode {
    let left = parseAnd();
    while (peek()?.t === "or") {
      pos++;
      left = { type: "or", left, right: parseAnd() };
    }
    return left;
  }

  function parseAnd(): ConditionNode {
    let left = parseNot();
    while (peek()?.t === "and") {
      pos++;
      left = { type: "and", left, right: parseNot() };
    }
    return left;
  }

  function parseNot(): ConditionNode {
    if (peek()?.t === "not") {
      pos++;
      return { type: "not", operand: parseNot() };
    }
    return parseAtom();
  }

  function parseAtom(): ConditionNode {
    const tok = peek();
    if (!tok) throw new SigmaError(`Unexpected end of condition: "${input}"`);
    if (tok.t === "lparen") {
      pos++;
      const inner = parseOr();
      if (peek()?.t !== "rparen") throw new SigmaError(`Missing ")" in condition: "${input}"`);
      pos++;
      return inner;
    }
    if (tok.t === "of") {
      pos++;
      const target = peek();
      if (!target || target.t !== "ident") throw new SigmaError(`Expected selection name after quantifier in: "${input}"`);
      pos++;
      return { type: "quant", quantifier: tok.quantifier, pattern: target.value };
    }
    if (tok.t === "ident") {
      pos++;
      return { type: "ref", name: tok.value };
    }
    throw new SigmaError(`Unexpected token in condition: "${input}"`);
  }

  const ast = parseOr();
  if (pos !== tokens.length) throw new SigmaError(`Unexpected trailing tokens in condition: "${input}"`);
  return ast;
}

/** Selection names a quantifier pattern expands to (`them`, `sel_*`, or an exact name). */
export function expandPattern(pattern: string, names: string[]): string[] {
  if (pattern.toLowerCase() === "them") return names.filter((n) => !n.startsWith("_"));
  if (!pattern.includes("*")) return names.filter((n) => n === pattern);
  const re = new RegExp("^" + pattern.split("*").map(escapeRe).join(".*") + "$");
  return names.filter((n) => re.test(n));
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
