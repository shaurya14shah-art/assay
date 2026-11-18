import type { CoverageReport, Level } from "../src/coverage.js";
import type { Scenario } from "../src/scenarios.js";

export interface SourceFile {
  name: string;
  text: string;
}

export interface RunRequest {
  id: number;
  rules: SourceFile[];
  scenarios: SourceFile[];
  minLevel: Level;
}

/** Serializable view of a parsed rule (the engine's Rule holds RegExps and closures). */
export interface RuleMeta {
  id: string;
  title: string;
  level: string;
  status: string;
  description: string;
  techniques: string[];
  source: string;
  unsupported?: string;
  /** False when the level filter excluded it from this run. */
  evaluated: boolean;
}

export type RunResponse =
  | { id: number; ok: true; report: CoverageReport; rules: RuleMeta[]; scenarios: Scenario[]; ms: number; events: number }
  | { id: number; ok: false; error: string };
