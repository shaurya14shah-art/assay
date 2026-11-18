import type { ScenarioResult, TechniqueResult } from "../../src/coverage.js";
import type { Scenario, ScenarioEvent } from "../../src/scenarios.js";
import { attackUrl, tacticLabel, techniqueName } from "../attack.js";
import type { RuleMeta } from "../protocol.js";
import { cellStatus, STATUS_LABEL } from "./Matrix.js";

interface Props {
  technique: TechniqueResult;
  results: ScenarioResult[];
  scenarios: Scenario[];
  rules: RuleMeta[];
  onOpenRule: (source: string) => void;
}

function LogsourceChip({ ls }: { ls: ScenarioEvent["logsource"] }) {
  const parts = [ls.product, ls.category, ls.service].filter(Boolean);
  return <span className="chip chip-quiet">{parts.join(" · ") || "any logsource"}</span>;
}

function EventFields({ fields }: { fields: Record<string, unknown> }) {
  return (
    <dl className="Fields">
      {Object.entries(fields).map(([k, v]) => (
        <div key={k} className="Fields-row">
          <dt>{k}</dt>
          <dd>{typeof v === "string" ? v : JSON.stringify(v)}</dd>
        </div>
      ))}
    </dl>
  );
}

export function TechniqueDetail({ technique, results, scenarios, rules, onOpenRule }: Props) {
  const st = cellStatus(technique);
  const ruleById = new Map(rules.map((r) => [r.id, r]));
  const runs = results.filter((r) => r.malicious && r.technique === technique.technique);
  const ruleButton = (id: string) => {
    const r = ruleById.get(id);
    return (
      <li key={id}>
        <button className="RuleLink" onClick={() => r && onOpenRule(r.source)} disabled={!r}>
          <span className={`level level-${r?.level ?? "medium"}`}>{r?.level ?? "?"}</span>
          <span>{r?.title ?? id}</span>
          <code>{id}</code>
        </button>
      </li>
    );
  };

  return (
    <article className="Detail">
      <p className="eyebrow">{tacticLabel(technique.tactic)}</p>
      <h2 className="Detail-title">
        <span className="mono">{technique.technique}</span> {techniqueName(technique.technique)}
      </h2>
      <div className="Detail-meta">
        <span className={`pill is-${st}`}>{STATUS_LABEL[st]}</span>
        <span className="muted">
          {technique.detected} of {technique.scenarios} scenario{technique.scenarios === 1 ? "" : "s"} detected
        </span>
        <a className="ext" href={attackUrl(technique.technique)} target="_blank" rel="noreferrer noopener">
          MITRE ATT&CK ↗
        </a>
      </div>

      <section className="Detail-block">
        <h3>Caught by</h3>
        {technique.rules.length ? <ul className="RuleList">{technique.rules.map(ruleButton)}</ul> : <p className="muted">No rule fired on this technique.</p>}
      </section>

      {technique.claimedButSilent.length > 0 && (
        <section className="Detail-block is-warn">
          <h3>Tagged for this technique, but silent</h3>
          <p className="muted small">These rules claim {technique.technique} in their ATT&CK tags but never fired on its scenarios. Either the rule or the tag is wrong.</p>
          <ul className="RuleList">{technique.claimedButSilent.map(ruleButton)}</ul>
        </section>
      )}

      <section className="Detail-block">
        <h3>Scenarios</h3>
        <ol className="Scenarios">
          {runs.map((run) => {
            const sc = scenarios.find((s) => s.id === run.scenarioId);
            return (
              <li key={run.scenarioId} className={`Scenario ${run.detected ? "is-hit" : "is-miss"}`}>
                <div className="Scenario-head">
                  <span className={`dot ${run.detected ? "on" : ""}`} aria-hidden="true" />
                  <strong>{run.name}</strong>
                  <code className="muted">{run.scenarioId}</code>
                  <span className={`pill small is-${run.detected ? "full" : "gap"}`}>{run.detected ? "Detected" : "Missed"}</span>
                </div>
                {sc?.note && <p className="Scenario-note">{sc.note}</p>}
                {sc?.events.map((ev, i) => {
                  const fired = run.firings.filter((f) => f.eventIndex === i);
                  return (
                    <div key={i} className={`Event${fired.length ? " is-fired" : ""}`}>
                      <div className="Event-head">
                        <span className="muted small">Event {i + 1}</span>
                        <LogsourceChip ls={ev.logsource} />
                      </div>
                      <EventFields fields={ev.fields} />
                      {fired.map((f) => (
                        <p key={f.ruleId} className="Event-fired">
                          <span aria-hidden="true">⚡</span> {f.ruleTitle}
                          <span className="muted"> matched on </span>
                          {f.selections.map((s) => (
                            <code key={s} className="sel">
                              {s}
                            </code>
                          ))}
                        </p>
                      ))}
                    </div>
                  );
                })}
              </li>
            );
          })}
        </ol>
      </section>
    </article>
  );
}
