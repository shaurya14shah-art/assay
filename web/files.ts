import type { SourceFile } from "./protocol.js";

export interface RuleFileState extends SourceFile {
  enabled: boolean;
  origin: "example" | "user";
}

const isYaml = (name: string) => /\.ya?ml$/i.test(name);

/** Read <input type=file> selections (files or a whole folder). Everything stays in memory. */
export async function readFileList(list: FileList | File[]): Promise<SourceFile[]> {
  const files = [...list].filter((f) => isYaml(f.name));
  return Promise.all(files.map(async (f) => ({ name: f.webkitRelativePath || f.name, text: await f.text() })));
}

function readEntry(entry: FileSystemEntry, out: Promise<SourceFile | null>[]): Promise<void> {
  if (entry.isFile) {
    const fe = entry as FileSystemFileEntry;
    out.push(
      new Promise((resolve) =>
        fe.file(
          async (f) => resolve(isYaml(f.name) ? { name: entry.fullPath.replace(/^\//, ""), text: await f.text() } : null),
          () => resolve(null),
        ),
      ),
    );
    return Promise.resolve();
  }
  if (!entry.isDirectory) return Promise.resolve();
  const reader = (entry as FileSystemDirectoryEntry).createReader();
  // readEntries returns results in batches; keep reading until it returns none.
  return new Promise((resolve) => {
    const next = () =>
      reader.readEntries(
        async (batch) => {
          if (batch.length === 0) return resolve();
          for (const child of batch) await readEntry(child, out);
          next();
        },
        () => resolve(),
      );
    next();
  });
}

/** Read a drag-and-drop payload, descending into dropped folders. */
export async function readDataTransfer(dt: DataTransfer): Promise<SourceFile[]> {
  const entries = [...dt.items].map((i) => i.webkitGetAsEntry?.()).filter((e): e is FileSystemEntry => !!e);
  if (entries.length === 0) return readFileList(dt.files);
  const out: Promise<SourceFile | null>[] = [];
  for (const e of entries) await readEntry(e, out);
  return (await Promise.all(out)).filter((f): f is SourceFile => f !== null);
}
