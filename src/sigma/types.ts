export type Scalar = string | number | boolean | null;
export type Event = Record<string, unknown>;

export interface LogSource {
  category?: string;
  product?: string;
  service?: string;
}

/** A single field test, e.g. `CommandLine|contains|all: [a, b]`. */
export interface FieldMatcher {
  field: string;
  /** Returns true when the event satisfies this matcher. */
  test: (event: Event) => boolean;
  /** Human-readable form, used in explanations. */
  describe: string;
}

/** One map in a selection: all field matchers must hold (AND). */
export interface MapMatcher {
  kind: "map";
  fields: FieldMatcher[];
}

/** Keyword search over every string value in the event. */
export interface KeywordMatcher {
  kind: "keywords";
  patterns: RegExp[];
}

/** A selection is an OR of alternatives (maps or keyword lists). */
export interface Selection {
  name: string;
  alternatives: Array<MapMatcher | KeywordMatcher>;
}

export type ConditionNode =
  | { type: "ref"; name: string }
  | { type: "and"; left: ConditionNode; right: ConditionNode }
  | { type: "or"; left: ConditionNode; right: ConditionNode }
  | { type: "not"; operand: ConditionNode }
  /** `names` is resolved once at parse time so evaluation never re-expands patterns. */
  | { type: "quant"; quantifier: "any" | "all"; pattern: string; names?: string[] };

export interface Rule {
  id: string;
  title: string;
  level: string;
  status: string;
  description: string;
  /** Normalised ATT&CK technique ids from `attack.tNNNN(.NNN)` tags, e.g. `T1059.001`. */
  techniques: string[];
  /** Tactic names from `attack.<tactic>` tags, e.g. `execution`. */
  tactics: string[];
  logsource: LogSource;
  selections: Map<string, Selection>;
  conditions: ConditionNode[];
  /** Set when the rule uses a valid Sigma feature Assay cannot evaluate. */
  unsupported?: string;
  /** File the rule was loaded from, when known. */
  source?: string;
}

/** A rule document that could not be loaded. Reported, never fatal to the run. */
export interface RuleIssue {
  source?: string;
  title?: string;
  id?: string;
  message: string;
}

/** The rule is invalid Sigma. */
export class SigmaError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SigmaError";
  }
}

/** The rule is valid Sigma but uses a feature Assay does not evaluate. */
export class UnsupportedError extends SigmaError {
  constructor(message: string) {
    super(message);
    this.name = "UnsupportedError";
  }
}
