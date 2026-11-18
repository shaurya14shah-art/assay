import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { LEVELS, type Level } from "../src/coverage.js";
import { techniqueName } from "./attack.js";
import { Drawer } from "./components/Drawer.js";
import { Findings } from "./components/Findings.js";
import { Hero } from "./components/Hero.js";
import { Matrix } from "./components/Matrix.js";
import { RulesPanel } from "./components/RulesPanel.js";
import { TechniqueDetail } from "./components/TechniqueDetail.js";
import { EXAMPLE_RULES, NEW_RULE_TEMPLATE, SCENARIOS } from "./data.js";
import { readDataTransfer, type RuleFileState } from "./files.js";
import type { RunRequest, RunResponse, SourceFile } from "./protocol.js";

type Tab = "matrix" | "rules" | "findings";
type Ok = Extract<RunResponse, { ok: true }>;

const TABS: Array<{ id: Tab; label: string }> = [
  { id: "matrix", label: "Coverage matrix" },
  { id: "rules", label: "Rules" },
  { id: "findings", label: "Findings" },
];

const initialFiles = (): RuleFileState[] => EXAMPLE_RULES.map((f) => ({ ...f, enabled: true, origin: "example" }));

export function App() {
  const [files, setFiles] = useState<RuleFileState[]>(initialFiles);
  const [selectedFile, setSelectedFile] = useState<string | null>(EXAMPLE_RULES[0]?.name ?? null);
  const [minLevel, setMinLevel] = useState<Level>("informational");
  const [tab, setTab] = useState<Tab>("matrix");
  const [showEmpty, setShowEmpty] = useState(true);
  const [technique, setTechnique] = useState<string | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [result, setResult] = useState<Ok | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(true);
  const [dragging, setDragging] = useState(false);
  const [toast, setToast] = useState<string | null>(null);

  const worker = useRef<Worker | null>(null);
  const latest = useRef(0);

  useEffect(() => {
    const w = new Worker(new URL("./worker.ts", import.meta.url), { type: "module" });
    w.onmessage = (e: MessageEvent<RunResponse>) => {
      if (e.data.id !== latest.current) return; // a newer run superseded this one
      setRunning(false);
      if (e.data.ok) {
        setResult(e.data);
        setError(null);
      } else setError(e.data.error);
    };
    worker.current = w;
    return () => w.terminate();
  }, []);

  useEffect(() => {
    setRunning(true);
    const t = setTimeout(() => {
      const req: RunRequest = {
        id: ++latest.current,
        rules: files.filter((f) => f.enabled).map(({ name, text }) => ({ name, text })),
        scenarios: SCENARIOS,
        minLevel,
      };
      worker.current?.postMessage(req);
    }, 180);
    return () => clearTimeout(t);
  }, [files, minLevel]);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 5000);
    return () => clearTimeout(t);
  }, [toast]);

  const addFiles = useCallback((incoming: SourceFile[]) => {
    if (incoming.length === 0) return setToast("No .yml or .yaml files found in that selection.");
    setFiles((prev) => {
      const firstUpload = !prev.some((f) => f.origin === "user");
      const names = new Set(incoming.map((f) => f.name));
      const kept = prev
        .filter((f) => !names.has(f.name))
        .map((f) => (firstUpload && f.origin === "example" ? { ...f, enabled: false } : f));
      return [...kept, ...incoming.map((f) => ({ ...f, enabled: true, origin: "user" as const }))];
    });
    setSelectedFile(incoming[0]?.name ?? null);
    setToast(`Loaded ${incoming.length} rule file${incoming.length === 1 ? "" : "s"}. Example rules are switched off; turn them back on in Rules.`);
  }, []);

  // Page-wide drag and drop of rule files or folders.
  useEffect(() => {
    let depth = 0;
    const hasFiles = (e: DragEvent) => !!e.dataTransfer && [...e.dataTransfer.types].includes("Files");
    const enter = (e: DragEvent) => {
      if (!hasFiles(e)) return;
      depth++;
      setDragging(true);
    };
    const over = (e: DragEvent) => {
      if (hasFiles(e)) e.preventDefault();
    };
    const leave = (e: DragEvent) => {
      if (!hasFiles(e)) return;
      depth = Math.max(0, depth - 1);
      if (depth === 0) setDragging(false);
    };
    const drop = (e: DragEvent) => {
      if (!hasFiles(e) || !e.dataTransfer) return;
      e.preventDefault();
      depth = 0;
      setDragging(false);
      void readDataTransfer(e.dataTransfer).then((f) => {
        addFiles(f);
        setTab("rules");
      });
    };
    window.addEventListener("dragenter", enter);
    window.addEventListener("dragover", over);
    window.addEventListener("dragleave", leave);
    window.addEventListener("drop", drop);
    return () => {
      window.removeEventListener("dragenter", enter);
      window.removeEventListener("dragover", over);
      window.removeEventListener("dragleave", leave);
      window.removeEventListener("drop", drop);
    };
  }, [addFiles]);

  const report = result?.report ?? null;
  const hits = useMemo(() => {
    const m = new Map<string, number>();
    for (const s of report?.scenarios ?? []) for (const f of s.firings) m.set(f.ruleId, (m.get(f.ruleId) ?? 0) + 1);
    return m;
  }, [report]);
  const selected = report?.techniques.find((t) => t.technique === technique) ?? null;

  const openTechnique = (t: string) => {
    setTechnique(t);
    setDrawerOpen(true);
  };
  const openRule = (source: string) => {
    setDrawerOpen(false);
    setSelectedFile(source);
    setTab("rules");
  };

  const exportJson = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "assay-report.json";
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  };

  const onTabKey = (e: KeyboardEvent<HTMLDivElement>) => {
    const i = TABS.findIndex((t) => t.id === tab);
    const next = e.key === "ArrowRight" ? (i + 1) % TABS.length : e.key === "ArrowLeft" ? (i - 1 + TABS.length) % TABS.length : -1;
    if (next < 0) return;
    e.preventDefault();
    const id = TABS[next]!.id;
    setTab(id);
    document.getElementById(`tab-${id}`)?.focus();
  };

  const badge = (id: Tab) => {
    if (!report) return null;
    if (id === "findings") {
      const n = report.techniques.filter((t) => t.status === "gap").length + report.falsePositives.length + report.invalid.length;
      return n ? <span className="badge is-bad">{n}</span> : null;
    }
    if (id === "rules") return <span className="badge">{files.filter((f) => f.enabled).length}</span>;
    return null;
  };

  return (
    <>
      <header className="Top">
        <a className="Brand" href="#" aria-label="Assay home">
          <svg viewBox="0 0 32 32" width="26" height="26" aria-hidden="true">
            <rect x="3" y="3" width="26" height="26" rx="7" className="Brand-tile" />
            <path d="M10 21l6-11 6 11M12.5 17h7" className="Brand-mark" />
          </svg>
          <span>Assay</span>
        </a>
        <span className="chip chip-quiet Top-tag">Sigma · ATT&CK · synthetic reference telemetry</span>
        <div className="Top-actions">
          <label className="select small">
            <span>Min level</span>
            <select value={minLevel} onChange={(e) => setMinLevel(e.target.value as Level)}>
              {LEVELS.map((l) => (
                <option key={l} value={l}>
                  {l}
                </option>
              ))}
            </select>
          </label>
          <button className="btn" onClick={exportJson} disabled={!report}>
            Export JSON
          </button>
        </div>
      </header>

      <main className="Main">
        <Hero report={report} ms={result?.ms ?? 0} events={result?.events ?? 0} running={running} />

        {error && (
          <div className="Alert" role="alert">
            <strong>Run failed.</strong> {error}
          </div>
        )}

        <div className="Tabs" role="tablist" aria-label="Views" onKeyDown={onTabKey}>
          {TABS.map((t) => (
            <button
              key={t.id}
              id={`tab-${t.id}`}
              role="tab"
              aria-selected={tab === t.id}
              aria-controls={`panel-${t.id}`}
              tabIndex={tab === t.id ? 0 : -1}
              className="Tab"
              onClick={() => setTab(t.id)}
            >
              {t.label}
              {badge(t.id)}
            </button>
          ))}
        </div>

        <div id={`panel-${tab}`} role="tabpanel" aria-labelledby={`tab-${tab}`} className="Panel">
          {tab === "matrix" &&
            (report ? (
              <>
                <div className="Legend">
                  <span>
                    <i className="sw is-full" /> Fully detected
                  </span>
                  <span>
                    <i className="sw is-partial" /> Partly evaded
                  </span>
                  <span>
                    <i className="sw is-gap" /> Not detected
                  </span>
                  <span className="muted">Dots are individual scenarios. Click a technique for the evidence.</span>
                  <label className="toggle small">
                    <input type="checkbox" checked={showEmpty} onChange={(e) => setShowEmpty(e.target.checked)} /> Show empty tactics
                  </label>
                </div>
                <Matrix techniques={report.techniques} scenarios={report.scenarios} onSelect={openTechnique} showEmpty={showEmpty} />
              </>
            ) : (
              <div className="Skeleton" aria-busy="true">
                Evaluating rules…
              </div>
            ))}
          {tab === "rules" && (
            <RulesPanel
              files={files}
              selected={selectedFile}
              rules={result?.rules ?? []}
              issues={report?.invalid ?? []}
              hits={hits}
              onSelect={setSelectedFile}
              onToggle={(name) => setFiles((fs) => fs.map((f) => (f.name === name ? { ...f, enabled: !f.enabled } : f)))}
              onSetAll={(enabled) => setFiles((fs) => fs.map((f) => ({ ...f, enabled })))}
              onEdit={(name, text) => setFiles((fs) => fs.map((f) => (f.name === name ? { ...f, text } : f)))}
              onAdd={() => {
                let n = 1;
                while (files.some((f) => f.name === `my-rules/new-rule-${n}.yml`)) n++;
                const name = `my-rules/new-rule-${n}.yml`;
                setFiles((fs) => [...fs, { name, text: NEW_RULE_TEMPLATE.replace("my-rule-001", `my-rule-${String(n).padStart(3, "0")}`), enabled: true, origin: "user" }]);
                setSelectedFile(name);
              }}
              onDelete={(name) => {
                setFiles((fs) => fs.filter((f) => f.name !== name));
                setSelectedFile(null);
              }}
              onUpload={addFiles}
              onRestore={() => {
                setFiles(initialFiles());
                setSelectedFile(EXAMPLE_RULES[0]?.name ?? null);
              }}
            />
          )}
          {tab === "findings" && report && result && (
            <Findings report={report} rules={result.rules} onSelectTechnique={openTechnique} onOpenRule={openRule} />
          )}
        </div>

        <footer className="Foot small muted">
          Scenario telemetry is synthetic and written for this project. A pass means these rules catch these examples, not that you are protected.
        </footer>
      </main>

      <Drawer open={drawerOpen} label={selected ? `${selected.technique} ${techniqueName(selected.technique)} details` : "Technique details"} onClosed={() => setDrawerOpen(false)}>
        {selected && result && (
          <TechniqueDetail technique={selected} results={result.report.scenarios} scenarios={result.scenarios} rules={result.rules} onOpenRule={openRule} />
        )}
      </Drawer>

      {dragging && (
        <div className="Dropzone" aria-hidden="true">
          <p>Drop Sigma rules or a folder to test them</p>
          <span className="small">Read locally. Nothing is uploaded.</span>
        </div>
      )}
      {toast && (
        <div className="Toast" role="status">
          {toast}
        </div>
      )}
    </>
  );
}
