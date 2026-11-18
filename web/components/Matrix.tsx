import type { ScenarioResult, TechniqueResult } from "../../src/coverage.js";
import { TACTICS, techniqueName } from "../attack.js";

export type CellStatus = "full" | "partial" | "gap";

export function cellStatus(t: TechniqueResult): CellStatus {
  if (t.detected === 0) return "gap";
  return t.detected === t.scenarios ? "full" : "partial";
}

export const STATUS_LABEL: Record<CellStatus, string> = {
  full: "Fully detected",
  partial: "Partly evaded",
  gap: "Not detected",
};

interface Props {
  techniques: TechniqueResult[];
  scenarios: ScenarioResult[];
  onSelect: (technique: string) => void;
  showEmpty: boolean;
}

export function Matrix({ techniques, scenarios, onSelect, showEmpty }: Props) {
  const byTactic = new Map<string, TechniqueResult[]>();
  for (const t of techniques) {
    const key = TACTICS.some((x) => x.id === t.tactic) ? (t.tactic as string) : "unmapped";
    byTactic.set(key, [...(byTactic.get(key) ?? []), t]);
  }
  const columns = [...TACTICS, ...(byTactic.has("unmapped") ? [{ id: "unmapped", label: "Unmapped" }] : [])].filter(
    (c) => showEmpty || byTactic.has(c.id),
  );

  return (
    <div className="Matrix" role="region" aria-label="ATT&CK coverage matrix" tabIndex={0}>
      <div className="Matrix-grid" style={{ gridTemplateColumns: `repeat(${columns.length}, minmax(11.5rem, 1fr))` }}>
        {columns.map((col) => {
          const items = byTactic.get(col.id) ?? [];
          const covered = items.filter((t) => t.detected > 0).length;
          return (
            <section key={col.id} className={`Matrix-col${items.length ? "" : " is-empty"}`} aria-label={col.label}>
              <header className="Matrix-head">
                <span className="Matrix-tactic">{col.label}</span>
                <span className="Matrix-count">{items.length ? `${covered}/${items.length}` : "—"}</span>
              </header>
              {items.length === 0 && <p className="Matrix-none">No scenarios yet</p>}
              {items.map((t) => {
                const st = cellStatus(t);
                const runs = scenarios.filter((s) => s.malicious && s.technique === t.technique);
                return (
                  <button
                    key={t.technique}
                    className={`Cell is-${st}`}
                    onClick={() => onSelect(t.technique)}
                    aria-label={`${t.technique} ${techniqueName(t.technique)}: ${STATUS_LABEL[st]}, ${t.detected} of ${t.scenarios} scenarios detected`}
                  >
                    <span className="Cell-id">{t.technique}</span>
                    <span className="Cell-name">{techniqueName(t.technique) || "Technique"}</span>
                    <span className="Cell-foot">
                      <span className="Cell-dots" aria-hidden="true">
                        {runs.map((r) => (
                          <i key={r.scenarioId} className={r.detected ? "on" : ""} />
                        ))}
                      </span>
                      <span className="Cell-ratio">
                        {t.detected}/{t.scenarios}
                      </span>
                    </span>
                    {t.claimedButSilent.length > 0 && (
                      <span className="Cell-flag" title="A rule is tagged for this technique but never fired on it">
                        silent rule
                      </span>
                    )}
                  </button>
                );
              })}
            </section>
          );
        })}
      </div>
    </div>
  );
}
