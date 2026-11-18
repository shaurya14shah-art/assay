import { useMemo, useRef, useState, type KeyboardEvent } from "react";
import type { RuleIssue } from "../../src/sigma/types.js";
import type { RuleFileState } from "../files.js";
import { readFileList } from "../files.js";
import type { RuleMeta, SourceFile } from "../protocol.js";

interface Props {
  files: RuleFileState[];
  selected: string | null;
  rules: RuleMeta[];
  issues: RuleIssue[];
  hits: Map<string, number>;
  onSelect: (name: string) => void;
  onToggle: (name: string) => void;
  onSetAll: (enabled: boolean, origin?: RuleFileState["origin"]) => void;
  onEdit: (name: string, text: string) => void;
  onAdd: () => void;
  onDelete: (name: string) => void;
  onUpload: (files: SourceFile[]) => void;
  onRestore: () => void;
}

const LIST_LIMIT = 300;

export function RulesPanel(p: Props) {
  const [query, setQuery] = useState("");
  const fileInput = useRef<HTMLInputElement>(null);
  const folderInput = useRef<HTMLInputElement>(null);

  const rulesByFile = useMemo(() => {
    const m = new Map<string, RuleMeta[]>();
    for (const r of p.rules) m.set(r.source, [...(m.get(r.source) ?? []), r]);
    return m;
  }, [p.rules]);
  const issuesByFile = useMemo(() => {
    const m = new Map<string, RuleIssue[]>();
    for (const i of p.issues) {
      const file = (i.source ?? "").replace(/ \(document \d+\)$/, "");
      m.set(file, [...(m.get(file) ?? []), i]);
    }
    return m;
  }, [p.issues]);

  const q = query.trim().toLowerCase();
  const filtered = q
    ? p.files.filter(
        (f) =>
          f.name.toLowerCase().includes(q) ||
          (rulesByFile.get(f.name) ?? []).some((r) => r.title.toLowerCase().includes(q) || r.techniques.some((t) => t.toLowerCase().includes(q))),
      )
    : p.files;
  const shown = filtered.slice(0, LIST_LIMIT);
  const current = p.files.find((f) => f.name === p.selected) ?? null;
  const currentRules = current ? rulesByFile.get(current.name) ?? [] : [];
  const currentIssues = current ? issuesByFile.get(current.name) ?? [] : [];
  const enabledCount = p.files.filter((f) => f.enabled).length;
  const hasUser = p.files.some((f) => f.origin === "user");

  const upload = async (list: FileList | null) => {
    if (!list || list.length === 0) return;
    const files = await readFileList(list);
    if (files.length) p.onUpload(files);
  };

  // Tab inserts two spaces instead of leaving the editor; Escape releases focus for keyboard users.
  const onKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Escape") return e.currentTarget.blur();
    if (e.key !== "Tab" || e.shiftKey || !current) return;
    e.preventDefault();
    const el = e.currentTarget;
    const { selectionStart: s, selectionEnd: end, value } = el;
    p.onEdit(current.name, value.slice(0, s) + "  " + value.slice(end));
    requestAnimationFrame(() => el.setSelectionRange(s + 2, s + 2));
  };

  return (
    <div className="Rules">
      <aside className="Rules-side" aria-label="Rule files">
        <div className="Rules-actions">
          <button className="btn btn-primary" onClick={() => fileInput.current?.click()}>
            Load rule files
          </button>
          <button className="btn" onClick={() => folderInput.current?.click()}>
            Load folder
          </button>
          <button className="btn" onClick={p.onAdd}>
            New rule
          </button>
          <input ref={fileInput} type="file" accept=".yml,.yaml" multiple hidden onChange={(e) => void upload(e.target.files).then(() => (e.target.value = ""))} />
          <input
            ref={folderInput}
            type="file"
            multiple
            hidden
            {...{ webkitdirectory: "" }}
            onChange={(e) => void upload(e.target.files).then(() => (e.target.value = ""))}
          />
        </div>
        <p className="small muted">Or drop .yml files or a folder anywhere on the page. Files are read in your browser and never uploaded.</p>
        <label className="search">
          <span className="visually-hidden">Filter rules</span>
          <input type="search" placeholder="Filter by file, title or technique" value={query} onChange={(e) => setQuery(e.target.value)} />
        </label>
        <div className="Rules-bulk small">
          <span className="muted">
            {enabledCount}/{p.files.length} files on
          </span>
          <button className="link" onClick={() => p.onSetAll(true)}>
            All on
          </button>
          <button className="link" onClick={() => p.onSetAll(false)}>
            All off
          </button>
          {hasUser && (
            <button className="link" onClick={p.onRestore}>
              Restore examples only
            </button>
          )}
        </div>
        <ul className="FileList">
          {shown.map((f) => {
            const rs = rulesByFile.get(f.name) ?? [];
            const bad = issuesByFile.get(f.name)?.length ?? 0;
            const fires = rs.reduce((n, r) => n + (p.hits.get(r.id) ?? 0), 0);
            return (
              <li key={f.name} className={`File${f.name === p.selected ? " is-active" : ""}${f.enabled ? "" : " is-off"}`}>
                <input type="checkbox" checked={f.enabled} onChange={() => p.onToggle(f.name)} aria-label={`Evaluate ${f.name}`} />
                <button className="File-main" onClick={() => p.onSelect(f.name)} aria-current={f.name === p.selected ? "true" : undefined}>
                  <span className="File-name">{f.name}</span>
                  <span className="File-sub small muted">
                    {rs.length} rule{rs.length === 1 ? "" : "s"}
                    {f.enabled && fires > 0 ? ` · ${fires} hit${fires === 1 ? "" : "s"}` : ""}
                    {bad > 0 && <span className="bad"> · {bad} invalid</span>}
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
        {filtered.length > LIST_LIMIT && <p className="small muted">Showing {LIST_LIMIT} of {filtered.length}. Refine the filter to see more.</p>}
      </aside>

      <section className="Editor" aria-label="Rule editor">
        {current ? (
          <>
            <header className="Editor-head">
              <code className="Editor-file">{current.name}</code>
              <span className="small muted">{current.enabled ? "Edits re-run the test instantly" : "This file is switched off"}</span>
              {current.origin === "user" && (
                <button className="link danger" onClick={() => p.onDelete(current.name)}>
                  Remove file
                </button>
              )}
            </header>
            <textarea
              className="Editor-text"
              spellCheck={false}
              autoCapitalize="off"
              autoCorrect="off"
              value={current.text}
              onChange={(e) => p.onEdit(current.name, e.target.value)}
              onKeyDown={onKeyDown}
              aria-label={`YAML for ${current.name}`}
            />
            {currentIssues.length > 0 && (
              <div className="Issues" role="status">
                {currentIssues.map((i, n) => (
                  <p key={n}>
                    <strong>Invalid:</strong> {i.message}
                  </p>
                ))}
              </div>
            )}
            <ul className="RuleCards">
              {currentRules.map((r, n) => (
                <li key={`${r.id}-${n}`} className="RuleCard">
                  <span className={`level level-${r.level}`}>{r.level}</span>
                  <strong>{r.title}</strong>
                  <span className="small muted">{r.techniques.join(", ") || "no technique tag"}</span>
                  <span className="RuleCard-state small">
                    {r.unsupported ? (
                      <span className="warn">Unsupported: {r.unsupported}</span>
                    ) : !r.evaluated ? (
                      <span className="muted">Below level filter</span>
                    ) : (p.hits.get(r.id) ?? 0) > 0 ? (
                      <span className="ok">Fired {p.hits.get(r.id)}×</span>
                    ) : (
                      <span className="muted">Never fired</span>
                    )}
                  </span>
                </li>
              ))}
            </ul>
          </>
        ) : (
          <p className="muted Editor-empty">Pick a rule file to read or edit it.</p>
        )}
      </section>
    </div>
  );
}
