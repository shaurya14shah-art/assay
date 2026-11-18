import { parseAllDocuments } from "yaml";
import { SigmaError, type Event, type LogSource } from "./sigma/types.js";

export interface ScenarioEvent {
  fields: Event;
  logsource: LogSource;
}

export interface Scenario {
  id: string;
  name: string;
  /** ATT&CK technique this telemetry represents, e.g. `T1059.001`. Benign scenarios may omit it. */
  technique?: string;
  tactic?: string;
  /** false = benign activity that must NOT trigger any rule (false-positive check). */
  malicious: boolean;
  /** Each event carries its own logsource, so one scenario can span several log types. */
  events: ScenarioEvent[];
  note?: string;
  source?: string;
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

/** Reserved event key that overrides the scenario logsource for that one event. */
export const EVENT_LOGSOURCE_KEY = "_logsource";

function readLogsource(raw: unknown, where: string): LogSource {
  if (raw === undefined) return {};
  if (!isObj(raw)) throw new SigmaError(`${where}: logsource must be a mapping`);
  const out: LogSource = {};
  for (const k of ["category", "product", "service"] as const) {
    const v = raw[k];
    if (v === undefined) continue;
    if (typeof v !== "string") throw new SigmaError(`${where}: logsource.${k} must be a string`);
    out[k] = v.toLowerCase();
  }
  return out;
}

export function parseScenarios(yamlText: string, source?: string): Scenario[] {
  const out: Scenario[] = [];
  const at = source ?? "scenario";
  for (const d of parseAllDocuments(yamlText)) {
    if (d.errors.length > 0) throw new SigmaError(`${at}: YAML error: ${d.errors[0]?.message.split("\n")[0]}`);
    const js = d.toJS({ maxAliasCount: 50 }) as unknown;
    if (js === null || js === undefined) continue;
    if (!isObj(js)) throw new SigmaError(`${at}: document is not a mapping`);

    const id = typeof js.id === "string" && js.id.trim() ? js.id.trim() : undefined;
    if (!id) throw new SigmaError(`${at}: scenario is missing an id`);
    const where = `${at}: scenario ${id}`;
    const name = typeof js.name === "string" ? js.name : id;
    if (js.malicious !== undefined && typeof js.malicious !== "boolean") throw new SigmaError(`${where}: malicious must be true or false`);
    const malicious = js.malicious !== false;

    let technique: string | undefined;
    if (js.technique !== undefined) {
      if (!/^t\d{4}(?:\.\d{3})?$/i.test(String(js.technique))) throw new SigmaError(`${where}: invalid technique "${String(js.technique)}"`);
      technique = String(js.technique).toUpperCase();
    }
    if (malicious && !technique) throw new SigmaError(`${where}: malicious scenarios need a technique`);

    if (!Array.isArray(js.events) || js.events.length === 0 || !js.events.every(isObj)) {
      throw new SigmaError(`${where}: events must be a non-empty list of objects`);
    }
    const base = readLogsource(js.logsource, where);
    const events: ScenarioEvent[] = (js.events as Obj[]).map((e, i) => {
      const { [EVENT_LOGSOURCE_KEY]: override, ...fields } = e;
      if (Object.keys(fields).length === 0) throw new SigmaError(`${where}: event #${i} has no fields`);
      return { fields, logsource: { ...base, ...readLogsource(override, `${where} event #${i}`) } };
    });

    out.push({
      id,
      name,
      technique,
      tactic: typeof js.tactic === "string" ? js.tactic.toLowerCase().replace(/-/g, "_") : undefined,
      malicious,
      events,
      note: typeof js.note === "string" ? js.note.trim() : undefined,
      source,
    });
  }
  return out;
}
