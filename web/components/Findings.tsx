import type { CoverageReport } from "../../src/coverage.js";
import { techniqueName } from "../attack.js";
import type { RuleMeta } from "../protocol.js";

interface Props {
  report: CoverageReport;
  rules: RuleMeta[];
  onSelectTechnique: (t: string) => void;
  onOpenRule: (source: string) => void;
}

const LIMIT = 50;

function Card({ title, count, tone, hint, children }: { title: string; count: number; tone: string; hint: string; children: React.ReactNode }) {
  return (
    <section className={`Finding tone-${tone}`}>
      <header>
        <h3>{title}</h3>
        <span className="Finding-count">{count}</span>
      </header>
      <p className="small muted">{hint}</p>
      {count === 0 ? <p className="small ok">Nothing here.</p> : children}
    </section>
  );
}

export function Findings({ report, rules, onSelectTechnique, onOpenRule }: Props) {
  const source = new Map(rules.map((r) => [r.id, r.source]));
  const gaps = report.techniques.filter((t) => t.status === "gap");
  const partial = report.techniques.filter((t) => t.detected > 0 && t.detected < t.scenarios);
  const silent = report.techniques.filter((t) => t.claimedButSilent.length > 0);
  const ruleBtn = (id: string, label: string) => (
    <button className="link" onClick={() => source.get(id) && onOpenRule(source.get(id) as string)}>
      {label}
    </button>
  );

  return (
    <div className="Findings">
      <Card title="Detection gaps" count={gaps.length} tone="bad" hint="Techniques with attack telemetry that no rule detects.">
        <ul>
          {gaps.map((t) => (
            <li key={t.technique}>
              <button className="link" onClick={() => onSelectTechnique(t.technique)}>
                <code>{t.technique}</code> {techniqueName(t.technique)}
              </button>
            </li>
          ))}
        </ul>
      </Card>

      <Card title="False positives" count={report.falsePositives.length} tone="bad" hint="Benign activity that fired a rule. Each one is alert fatigue in production.">
        <ul>
          {report.falsePositives.map((fp) => (
            <li key={fp.scenarioId}>
              <strong>{fp.name}</strong> <code className="muted">{fp.scenarioId}</code>
              <ul className="sub">
                {fp.firings.map((f, i) => (
                  <li key={i}>
                    {ruleBtn(f.ruleId, f.ruleTitle)} <span className="muted">matched on</span>{" "}
                    {f.selections.map((s) => (
                      <code key={s} className="sel">
                        {s}
                      </code>
                    ))}
                  </li>
                ))}
              </ul>
            </li>
          ))}
        </ul>
      </Card>

      <Card title="Partly evaded" count={partial.length} tone="warn" hint="Caught in some variants but missed in others. Attackers pick the variant you miss.">
        <ul>
          {partial.map((t) => (
            <li key={t.technique}>
              <button className="link" onClick={() => onSelectTechnique(t.technique)}>
                <code>{t.technique}</code> {techniqueName(t.technique)}
              </button>{" "}
              <span className="muted">
                {t.detected}/{t.scenarios}
              </span>
            </li>
          ))}
        </ul>
      </Card>

      <Card title="Tagged but silent" count={silent.length} tone="warn" hint="Rules tagged for a technique that never fire on it. The rule or its tag is wrong.">
        <ul>
          {silent.map((t) => (
            <li key={t.technique}>
              <code>{t.technique}</code>: {t.claimedButSilent.map((id, i) => <span key={id}>{i > 0 && ", "}{ruleBtn(id, id)}</span>)}
            </li>
          ))}
        </ul>
      </Card>

      <Card title="Rules that never fired" count={report.deadRules.length} tone="quiet" hint="No scenario exercises these. Write a scenario for each, or retire the rule.">
        <ul>
          {report.deadRules.slice(0, LIMIT).map((r) => (
            <li key={r.ruleId}>{ruleBtn(r.ruleId, r.title)}</li>
          ))}
        </ul>
        {report.deadRules.length > LIMIT && <p className="small muted">…and {report.deadRules.length - LIMIT} more. Export the JSON report for the full list.</p>}
      </Card>

      <Card title="Unsupported" count={report.unsupported.length} tone="quiet" hint="Valid Sigma that Assay does not evaluate. Listed so nothing is silently skipped.">
        <ul>
          {report.unsupported.slice(0, LIMIT).map((r) => (
            <li key={r.ruleId}>
              {ruleBtn(r.ruleId, r.title)} <span className="muted small">{r.reason}</span>
            </li>
          ))}
        </ul>
      </Card>

      <Card title="Invalid documents" count={report.invalid.length + report.duplicateRuleIds.length} tone="bad" hint="Rule documents that failed to load, and rule ids used more than once.">
        <ul>
          {report.invalid.slice(0, LIMIT).map((i, n) => (
            <li key={n}>
              <code className="muted">{i.source}</code> {i.message}
            </li>
          ))}
          {report.duplicateRuleIds.map((id) => (
            <li key={id}>
              Duplicate id <code>{id}</code>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
