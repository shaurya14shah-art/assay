import { SigmaError, UnsupportedError, type Event, type FieldMatcher, type Scalar } from "./types.js";

// This module is runtime-neutral (no Node APIs) so the engine also runs in the browser.

const SHAPE_MODS = new Set(["contains", "startswith", "endswith"]);
const REGEX_FLAG_MODS = new Set(["i", "m", "s"]);
const NUMERIC_MODS = new Set(["lt", "lte", "gt", "gte"]);
const ENCODING_MODS = new Set(["utf16le", "utf16be", "utf16", "wide"]);
/** Valid Sigma modifiers we deliberately do not evaluate. */
const UNSUPPORTED_MODS = new Set(["expand"]);
const KNOWN_MODS = new Set([
  ...SHAPE_MODS,
  ...REGEX_FLAG_MODS,
  ...NUMERIC_MODS,
  ...ENCODING_MODS,
  "all",
  "re",
  "cidr",
  "base64",
  "base64offset",
  "windash",
  "exists",
  "cased",
  "fieldref",
]);

const ANY = "[\\s\\S]*";
const hasOwn = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);

function lookupKey(obj: Record<string, unknown>, key: string): { found: boolean; value?: unknown } {
  // Own properties only: a rule field named `constructor` must not resolve to Object.prototype.
  if (hasOwn(obj, key)) return { found: true, value: obj[key] };
  const lower = key.toLowerCase();
  for (const k of Object.keys(obj)) if (k.toLowerCase() === lower) return { found: true, value: obj[k] };
  return { found: false };
}

/** Look up a field by exact key, then case-insensitively, then as a dotted path. */
export function getField(event: Event, name: string): unknown {
  const direct = lookupKey(event, name);
  if (direct.found) return direct.value;
  if (!name.includes(".")) return undefined;
  let cur: unknown = event;
  for (const part of name.split(".")) {
    if (!cur || typeof cur !== "object" || Array.isArray(cur)) return undefined;
    const r = lookupKey(cur as Record<string, unknown>, part);
    if (!r.found) return undefined;
    cur = r.value;
  }
  return cur;
}

/** Every scalar value in an event, as strings (used for keyword search). */
export function collectStrings(value: unknown, out: string[] = [], depth = 0): string[] {
  if (depth > 8 || value === null || value === undefined) return out;
  if (typeof value === "string") out.push(value);
  else if (typeof value === "number" || typeof value === "boolean") out.push(String(value));
  else if (Array.isArray(value)) for (const v of value) collectStrings(v, out, depth + 1);
  else if (typeof value === "object") for (const v of Object.values(value as object)) collectStrings(v, out, depth + 1);
  return out;
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const isWord = (c: string | undefined) => c !== undefined && /[A-Za-z0-9_]/.test(c);
const WINDASH_CHARS = ["-", "/", "\u2013", "\u2014", "\u2015"];
const WINDASH_CLASS = "[-/\\u2013\\u2014\\u2015]";

/** A `-` or `/` that starts a word, the positions `windash` rewrites (pySigma uses `\B[-/]\b`). */
function isWindashAt(s: string, i: number): boolean {
  const ch = s[i];
  return (ch === "-" || ch === "/") && !isWord(s[i - 1]) && isWord(s[i + 1]);
}

export interface PatternOptions {
  /** Leading wildcard added by `contains` / `endswith`. */
  prefix?: boolean;
  /** Trailing wildcard added by `contains` / `startswith`. */
  suffix?: boolean;
  /** Word-initial `-` or `/` also matches the other dash forms. */
  windash?: boolean;
  /** Case-sensitive match (`cased` modifier). */
  cased?: boolean;
}

/**
 * Convert a Sigma value with `*` / `?` wildcards into an anchored regex.
 * `\*`, `\?` and `\\` are literals; a backslash before anything else is a literal backslash
 * (so Windows paths such as `C:\Windows\` work unescaped). Wildcards added by modifiers are
 * added structurally, so a value ending in a backslash cannot escape them.
 */
export function wildcardToRegex(pattern: string, opts: PatternOptions = {}): RegExp {
  let out = opts.prefix ? ANY : "";
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i] as string;
    if (ch === "\\") {
      const next = pattern[i + 1];
      if (next === "*" || next === "?" || next === "\\") {
        out += escapeRegex(next);
        i++;
      } else out += "\\\\";
    } else if (ch === "*") out += ANY;
    else if (ch === "?") out += "[\\s\\S]";
    else if (opts.windash && isWindashAt(pattern, i)) out += WINDASH_CLASS;
    else out += escapeRegex(ch);
  }
  if (opts.suffix) out += ANY;
  return new RegExp("^" + out + "$", opts.cased ? "" : "i");
}

/** Explicit windash expansion, only needed when the value is then base64-encoded. */
export function windashVariants(value: string, cap = 625): string[] {
  const positions: number[] = [];
  for (let i = 0; i < value.length; i++) if (isWindashAt(value, i)) positions.push(i);
  if (positions.length === 0) return [value];
  const total = WINDASH_CHARS.length ** positions.length;
  if (total > cap) throw new UnsupportedError(`windash before base64 on "${value}" expands to ${total} variants`);
  const out: string[] = [];
  for (let n = 0; n < total; n++) {
    const chars = value.split("");
    let k = n;
    for (const p of positions) {
      chars[p] = WINDASH_CHARS[k % WINDASH_CHARS.length] as string;
      k = Math.floor(k / WINDASH_CHARS.length);
    }
    out.push(chars.join(""));
  }
  return out;
}

function utf16(s: string, littleEndian: boolean, bom: boolean): Uint8Array {
  const out = new Uint8Array((s.length + (bom ? 1 : 0)) * 2);
  let o = 0;
  if (bom) {
    out[o++] = 0xff;
    out[o++] = 0xfe;
  }
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (littleEndian) {
      out[o++] = c & 0xff;
      out[o++] = c >> 8;
    } else {
      out[o++] = c >> 8;
      out[o++] = c & 0xff;
    }
  }
  return out;
}

export function encodeText(s: string, encoding?: string): Uint8Array {
  if (encoding === "utf16le" || encoding === "wide") return utf16(s, true, false);
  if (encoding === "utf16be") return utf16(s, false, false);
  if (encoding === "utf16") return utf16(s, true, true);
  return new TextEncoder().encode(s);
}

export function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** Plain base64, or the three shifted forms used by `base64offset` (same slicing as pySigma). */
export function base64Variants(input: string | Uint8Array, offsets: boolean): string[] {
  const buf = typeof input === "string" ? new TextEncoder().encode(input) : input;
  if (!offsets) return [bytesToBase64(buf)];
  const starts = [0, 2, 3];
  const ends = [0, -3, -2];
  const out: string[] = [];
  for (let i = 0; i < 3; i++) {
    const padded = new Uint8Array(buf.length + i);
    padded.set(buf, i);
    const enc = bytesToBase64(padded);
    const end = ends[(buf.length + i) % 3] as number;
    out.push(end === 0 ? enc.slice(starts[i]) : enc.slice(starts[i], end));
  }
  return out;
}

function parseIPv4(ip: string): bigint | undefined {
  const parts = ip.trim().split(".");
  if (parts.length !== 4) return undefined;
  let n = 0n;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return undefined;
    const v = Number(p);
    if (v > 255) return undefined;
    n = n * 256n + BigInt(v);
  }
  return n;
}

function parseIPv6(ip: string): bigint | undefined {
  let s = ip.trim().toLowerCase();
  const zone = s.indexOf("%");
  if (zone >= 0) s = s.slice(0, zone);
  if (!s.includes(":")) return undefined;
  const lastColon = s.lastIndexOf(":");
  const tail = s.slice(lastColon + 1);
  if (tail.includes(".")) {
    const v4 = parseIPv4(tail);
    if (v4 === undefined) return undefined;
    s = s.slice(0, lastColon + 1) + ((v4 >> 16n) & 0xffffn).toString(16) + ":" + (v4 & 0xffffn).toString(16);
  }
  const halves = s.split("::");
  if (halves.length > 2) return undefined;
  const head = halves[0] ? halves[0].split(":") : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  let groups: string[];
  if (halves.length === 2) {
    const missing = 8 - head.length - rest.length;
    if (missing < 1) return undefined;
    groups = [...head, ...Array<string>(missing).fill("0"), ...rest];
  } else groups = head;
  if (groups.length !== 8) return undefined;
  let n = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return undefined;
    n = (n << 16n) | BigInt(parseInt(g, 16));
  }
  return n;
}

interface Cidr {
  v6: boolean;
  base: bigint;
  shift: bigint;
}

function parseCidr(cidr: string): Cidr | undefined {
  const slash = cidr.indexOf("/");
  const baseStr = slash < 0 ? cidr : cidr.slice(0, slash);
  const v6 = baseStr.includes(":");
  const width = v6 ? 128 : 32;
  const bits = slash < 0 ? width : Number(cidr.slice(slash + 1));
  if (!Number.isInteger(bits) || bits < 0 || bits > width) return undefined;
  const base = v6 ? parseIPv6(baseStr) : parseIPv4(baseStr);
  if (base === undefined) return undefined;
  const shift = BigInt(width - bits);
  return { v6, base: base >> shift, shift };
}

function inCidr(c: Cidr, ip: string): boolean {
  const t = c.v6 ? parseIPv6(ip) : parseIPv4(ip);
  return t !== undefined && t >> c.shift === c.base;
}

export function cidrContains(cidr: string, ip: string): boolean {
  const c = parseCidr(cidr);
  return c !== undefined && inCidr(c, ip);
}

const eventValues = (raw: unknown): unknown[] => (Array.isArray(raw) ? raw : [raw]);

function asString(v: unknown): string {
  if (typeof v === "string") return v;
  if (typeof v === "boolean") return v ? "true" : "false";
  return String(v);
}

type ValueTest = (eventValue: unknown, event: Event) => boolean;

/** PCRE escapes that JavaScript would silently read as plain letters, changing the meaning. */
const PCRE_ONLY_ESCAPES = new Set(["A", "Z", "z", "G", "K", "Q", "E", "R", "h", "H", "X"]);

/**
 * Sigma regexes are PCRE-flavoured. Translate a leading inline flag group such as `(?i)` or
 * `(?is)` into JS flags, and refuse syntax JS would compile with a different meaning.
 */
export function translatePcre(pattern: string, field: string): { source: string; flags: string[] } {
  let source = pattern;
  const flags: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = /^\(\?([a-zA-Z]+)\)/.exec(source)) !== null) {
    for (const f of m[1] as string) {
      if (f === "i" || f === "m" || f === "s") flags.push(f);
      else throw new UnsupportedError(`regex inline flag "(?${f})" on field "${field}"`);
    }
    source = source.slice(m[0].length);
  }
  for (let i = 0; i < source.length; i++) {
    if (source[i] !== "\\") continue;
    const next = source[i + 1];
    if (next !== undefined && PCRE_ONLY_ESCAPES.has(next)) {
      throw new UnsupportedError(`PCRE-only regex escape "\\${next}" on field "${field}"`);
    }
    i++;
  }
  // Check structure on a copy with escapes and character classes blanked out.
  const bare = source.replace(/\\./g, "_").replace(/\[(?:\\.|[^\]\\])*\]/g, "_");
  if (/\(\?[a-zA-Z]+\)/.test(bare) || /\(\?[a-zA-Z]*-[a-zA-Z]+[:)]/.test(bare)) {
    throw new UnsupportedError(`mid-pattern regex inline flags on field "${field}"`);
  }
  if (/\(\?>|[*+?}]\+/.test(bare)) throw new UnsupportedError(`atomic group or possessive quantifier on field "${field}"`);
  return { source, flags };
}

function checkCombination(mods: string[], field: string): void {
  const bad = (why: string): never => {
    throw new SigmaError(`Field "${field}": ${why} (${mods.join("|")})`);
  };
  const has = (m: string) => mods.includes(m);
  const shapes = mods.filter((m) => SHAPE_MODS.has(m));
  const numeric = mods.filter((m) => NUMERIC_MODS.has(m));
  const encodings = mods.filter((m) => ENCODING_MODS.has(m));
  const b64 = has("base64") || has("base64offset");
  const kinds = [has("re"), has("cidr"), numeric.length > 0, has("fieldref"), has("exists")].filter(Boolean).length;

  if (shapes.length > 1) bad("only one of contains/startswith/endswith is allowed");
  if (numeric.length > 1) bad("only one numeric comparison is allowed");
  if (encodings.length > 1) bad("only one text encoding is allowed");
  if (has("base64") && has("base64offset")) bad("base64 and base64offset are exclusive");
  if (kinds > 1) bad("re, cidr, numeric, fieldref and exists cannot be combined");
  if ((has("re") || has("cidr") || numeric.length || has("exists")) && (shapes.length || b64 || encodings.length || has("windash"))) {
    bad("string modifiers cannot be combined with re, cidr, numeric or exists");
  }
  if (has("fieldref") && (b64 || encodings.length || has("windash"))) bad("fieldref cannot be combined with encodings");
  if (encodings.length && !b64) bad(`${encodings[0]} must be used together with base64 or base64offset`);
  for (const f of mods.filter((m) => REGEX_FLAG_MODS.has(m))) {
    if (!has("re")) bad(`regex flag "${f}" requires the re modifier`);
  }
}

/** Build the test for one rule value under a given modifier chain. */
function compileValue(value: Scalar, mods: string[], field: string): ValueTest {
  const has = (m: string) => mods.includes(m);
  const cased = has("cased");
  const shape = mods.find((m) => SHAPE_MODS.has(m));
  const prefix = shape === "contains" || shape === "endswith";
  const suffix = shape === "contains" || shape === "startswith";
  const numeric = mods.find((m) => NUMERIC_MODS.has(m));

  if (has("re")) {
    if (typeof value !== "string") throw new SigmaError(`Field "${field}": re modifier needs a string value`);
    const { source, flags: inline } = translatePcre(value, field);
    const flags = [...new Set([...mods.filter((m) => REGEX_FLAG_MODS.has(m)), ...inline])].join("");
    let rx: RegExp;
    try {
      rx = new RegExp(source, flags);
    } catch (e) {
      throw new SigmaError(`Field "${field}": invalid regex "${value}": ${(e as Error).message}`);
    }
    return (ev) => ev !== undefined && ev !== null && rx.test(asString(ev));
  }

  if (has("cidr")) {
    const c = typeof value === "string" ? parseCidr(value) : undefined;
    if (!c) throw new SigmaError(`Field "${field}": invalid CIDR "${String(value)}"`);
    return (ev) => ev !== undefined && ev !== null && inCidr(c, asString(ev));
  }

  if (numeric) {
    const limit = Number(value);
    if (value === null || value === "" || Number.isNaN(limit)) throw new SigmaError(`Field "${field}": ${numeric} needs a numeric value`);
    return (ev) => {
      if (ev === undefined || ev === null || ev === "") return false;
      const n = Number(ev);
      if (Number.isNaN(n)) return false;
      if (numeric === "lt") return n < limit;
      if (numeric === "lte") return n <= limit;
      if (numeric === "gt") return n > limit;
      return n >= limit;
    };
  }

  if (has("fieldref")) {
    if (typeof value !== "string" || !value) throw new SigmaError(`Field "${field}": fieldref needs a field name`);
    const flags = cased ? "" : "i";
    return (ev, event) => {
      if (ev === undefined || ev === null) return false;
      const target = asString(ev);
      return eventValues(getField(event, value)).some((o) => {
        if (o === undefined || o === null) return false;
        const rx = new RegExp("^" + (prefix ? ANY : "") + escapeRegex(asString(o)) + (suffix ? ANY : "") + "$", flags);
        return rx.test(target);
      });
    };
  }

  if (value === null) return (ev) => ev === undefined || ev === null || ev === "";

  const encoding = mods.find((m) => ENCODING_MODS.has(m));
  const b64 = has("base64offset") ? "offset" : has("base64") ? "plain" : undefined;
  let regexes: RegExp[];
  if (b64) {
    let plain = [asString(value)];
    if (has("windash")) plain = plain.flatMap((p) => windashVariants(p));
    // Base64 text is case-significant, so encoded forms always match case-sensitively.
    regexes = plain
      .flatMap((p) => base64Variants(encodeText(p, encoding), b64 === "offset"))
      .map((enc) => new RegExp("^" + (prefix ? ANY : "") + escapeRegex(enc) + (suffix ? ANY : "") + "$"));
  } else {
    regexes = [wildcardToRegex(asString(value), { prefix, suffix, windash: has("windash"), cased })];
  }

  const isNumberRule = typeof value === "number" && !shape && !b64;
  return (ev) => {
    if (ev === undefined || ev === null) return false;
    if (isNumberRule && typeof ev === "number") return ev === value;
    const s = asString(ev);
    return regexes.some((r) => r.test(s));
  };
}

/**
 * Compile `Field|mod|mod: value(s)` into a FieldMatcher.
 * A key with an empty field name (`'|all': [...]`) is a keyword search with modifiers.
 */
export function compileFieldMatcher(key: string, raw: unknown): FieldMatcher {
  const [field, ...mods] = key.split("|") as [string, ...string[]];
  for (const m of mods) {
    if (UNSUPPORTED_MODS.has(m)) throw new UnsupportedError(`modifier "${m}"`);
    if (!KNOWN_MODS.has(m)) throw new SigmaError(`Unknown modifier "${m}" on field "${field || key}"`);
  }
  const keywordSearch = field === "";
  if (keywordSearch && mods.length === 0) throw new SigmaError(`Empty field name in "${key}"`);
  checkCombination(mods, field || "<keywords>");
  const describe = `${key}: ${JSON.stringify(raw)}`;

  if (mods.includes("exists")) {
    if (keywordSearch) throw new SigmaError("exists needs a field name");
    if (typeof raw !== "boolean") throw new SigmaError(`Field "${field}": exists needs true or false`);
    return {
      field,
      describe,
      test: (event) => {
        const v = getField(event, field);
        const present = v !== undefined && v !== null;
        return raw ? present : !present;
      },
    };
  }

  const values: Scalar[] = Array.isArray(raw) ? (raw as Scalar[]) : [raw as Scalar];
  if (values.length === 0) throw new SigmaError(`Field "${field}" has an empty value list`);
  for (const v of values) {
    if (v !== null && typeof v === "object") throw new SigmaError(`Field "${field}": nested lists or maps are not valid values`);
  }

  // Keyword search defaults to substring semantics, like plain keyword lists.
  const effectiveMods = keywordSearch && !mods.some((m) => SHAPE_MODS.has(m) || m === "re") ? [...mods, "contains"] : mods;
  const requireAll = mods.includes("all");
  const tests = values.map((v) => compileValue(v, effectiveMods, field || "<keywords>"));

  if (keywordSearch) {
    return {
      field: "",
      describe,
      test: (event) => {
        const strings = collectStrings(event);
        const hit = (t: ValueTest) => strings.some((s) => t(s, event));
        return requireAll ? tests.every(hit) : tests.some(hit);
      },
    };
  }

  return {
    field,
    describe,
    test: (event) => {
      const evs = eventValues(getField(event, field));
      const hit = (t: ValueTest) => evs.some((ev) => t(ev, event));
      return requireAll ? tests.every(hit) : tests.some(hit);
    },
  };
}
