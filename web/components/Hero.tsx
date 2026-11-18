import type { CoverageReport } from "../../src/coverage.js";

function Ring({ value }: { value: number }) {
  const r = 52;
  const c = 2 * Math.PI * r;
  return (
    <svg className="Ring" viewBox="0 0 120 120" aria-hidden="true">
      <circle cx="60" cy="60" r={r} className="Ring-track" />
      <circle cx="60" cy="60" r={r} className="Ring-value" strokeDasharray={`${c * value} ${c}`} transform="rotate(-90 60 60)" />
    </svg>
  );
}

const pct = (n: number) => `${Math.round(n * 1000) / 10}%`;

export function Hero({ report, ms, events, running }: { report: CoverageReport | null; ms: number; events: number; running: boolean }) {
  const s = report?.summary;
  return (
    <section className="Hero" aria-labelledby="hero-title">
      <div className="Hero-copy">
        <p className="eyebrow">Detection engineering, tested</p>
        <h1 id="hero-title">
          Prove what your detections <em>actually</em> catch.
        </h1>
        <p className="lede">
          Assay replays attack telemetry against your Sigma rules and maps the result onto MITRE ATT&CK, so you see the
          gaps, the evasions and the false positives before an attacker or your on-call team does.
        </p>
        <p className="privacy small">
          <svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true">
            <path d="M12 2l8 3v6c0 5-3.5 9-8 11-4.5-2-8-6-8-11V5z" fill="none" stroke="currentColor" strokeWidth="2" />
          </svg>
          Runs entirely in your browser. Your rules never leave this page.
        </p>
      </div>

      <div className="Kpis" aria-live="polite">
        <div className="Kpi Kpi-main">
          <Ring value={s?.techniqueCoverage ?? 0} />
          <div className="Kpi-ring-label">
            <span className="Kpi-value">{s ? pct(s.techniqueCoverage) : "–"}</span>
            <span className="Kpi-label">technique coverage</span>
            <span className="small muted">{s ? `${s.coveredTechniques} of ${s.techniques} techniques` : " "}</span>
          </div>
        </div>
        <div className="Kpi">
          <span className="Kpi-value">{s ? `${s.detectedScenarios}/${s.maliciousScenarios}` : "–"}</span>
          <span className="Kpi-label">attack scenarios detected</span>
        </div>
        <div className={`Kpi${s && s.falsePositives > 0 ? " is-bad" : ""}`}>
          <span className="Kpi-value">{s ? s.falsePositives : "–"}</span>
          <span className="Kpi-label">false positives in {s?.benignScenarios ?? 0} benign runs</span>
        </div>
        <div className="Kpi">
          <span className="Kpi-value">{s ? s.rules : "–"}</span>
          <span className="Kpi-label">
            rules evaluated
            {s && (s.unsupportedRules || s.invalidRules) ? ` · ${s.unsupportedRules} unsupported · ${s.invalidRules} invalid` : ""}
          </span>
        </div>
        <p className="Kpi-status small muted">
          {running ? "Evaluating…" : s ? `${s.rules.toLocaleString()} rules × ${events} events in ${ms < 10 ? ms.toFixed(1) : Math.round(ms)} ms` : ""}
        </p>
      </div>
    </section>
  );
}
