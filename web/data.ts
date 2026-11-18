import type { SourceFile } from "./protocol.js";

// Bundled at build time; nothing is fetched at runtime.
const ruleModules = import.meta.glob("../examples/rules/**/*.{yml,yaml}", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

const scenarioModules = import.meta.glob("../scenarios/**/*.{yml,yaml}", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

const toFiles = (mods: Record<string, string>, from: string, to: string): SourceFile[] =>
  Object.entries(mods)
    .map(([path, text]) => ({ name: path.replace(from, to), text }))
    .sort((a, b) => a.name.localeCompare(b.name));

export const EXAMPLE_RULES = toFiles(ruleModules, "../examples/rules/", "examples/");
export const SCENARIOS = toFiles(scenarioModules, "../scenarios/", "scenarios/");

export const NEW_RULE_TEMPLATE = `title: My New Detection
id: my-rule-001
status: experimental
description: Describe what this catches.
tags: [attack.execution, attack.t1059.001]
level: medium
logsource: { category: process_creation, product: windows }
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains|windash: ' -e '
  condition: selection
`;
