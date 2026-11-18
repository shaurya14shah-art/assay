/** Enterprise ATT&CK tactics in kill-chain order. */
export const TACTICS: Array<{ id: string; label: string }> = [
  { id: "reconnaissance", label: "Reconnaissance" },
  { id: "resource_development", label: "Resource Development" },
  { id: "initial_access", label: "Initial Access" },
  { id: "execution", label: "Execution" },
  { id: "persistence", label: "Persistence" },
  { id: "privilege_escalation", label: "Privilege Escalation" },
  { id: "defense_evasion", label: "Defense Evasion" },
  { id: "credential_access", label: "Credential Access" },
  { id: "discovery", label: "Discovery" },
  { id: "lateral_movement", label: "Lateral Movement" },
  { id: "collection", label: "Collection" },
  { id: "command_and_control", label: "Command and Control" },
  { id: "exfiltration", label: "Exfiltration" },
  { id: "impact", label: "Impact" },
];

/** Names for the techniques the bundled scenarios use, plus common neighbours. */
export const TECHNIQUE_NAMES: Record<string, string> = {
  T1003: "OS Credential Dumping",
  "T1003.001": "LSASS Memory",
  "T1003.003": "NTDS",
  T1021: "Remote Services",
  "T1021.001": "Remote Desktop Protocol",
  "T1021.002": "SMB/Windows Admin Shares",
  T1027: "Obfuscated Files or Information",
  T1033: "System Owner/User Discovery",
  T1047: "Windows Management Instrumentation",
  T1053: "Scheduled Task/Job",
  "T1053.003": "Cron",
  "T1053.005": "Scheduled Task",
  T1055: "Process Injection",
  T1059: "Command and Scripting Interpreter",
  "T1059.001": "PowerShell",
  "T1059.003": "Windows Command Shell",
  "T1059.004": "Unix Shell",
  "T1070.001": "Clear Windows Event Logs",
  T1082: "System Information Discovery",
  "T1087.001": "Local Account",
  "T1087.002": "Domain Account",
  T1105: "Ingress Tool Transfer",
  T1110: "Brute Force",
  "T1136.001": "Local Account",
  "T1204.002": "Malicious File",
  "T1218.005": "Mshta",
  "T1218.010": "Regsvr32",
  "T1218.011": "Rundll32",
  T1490: "Inhibit System Recovery",
  "T1505.003": "Web Shell",
  "T1547.001": "Registry Run Keys / Startup Folder",
  "T1562.001": "Disable or Modify Tools",
  "T1566.001": "Spearphishing Attachment",
};

export const techniqueName = (id: string) => TECHNIQUE_NAMES[id] ?? "";
export const attackUrl = (id: string) => `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
export const tacticLabel = (id?: string) => TACTICS.find((t) => t.id === id)?.label ?? "Unmapped";
