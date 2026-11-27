// All site content. Facts taken from the Rogue commit history are marked `source: 'commits'`.
// Anything the owner must confirm or replace is marked `placeholder: true`.

export const site = {
  name: 'Rogue',
  role: 'AI harness for offensive security',
  description:
    'Rogue is an AI agent harness for offensive security. A language model drives 78 tools for recon, scanning, exploit PoCs and CTFs, behind scope boundaries and a sandbox.',
  url: 'https://rogue.example.dev', // placeholder: production URL
  repo: { href: 'https://github.com/kartikeywastaken/rogue', placeholder: true },
  clone: 'git clone https://github.com/kartikeywastaken/rogue', // placeholder: matches repo
  version: { text: 'v0.1', placeholder: true },
  toolCount: 78, // source: commits ("78 tools, all tests pass")
  tagline: 'Offensive tooling, on a leash',
  strap: ['arsenal', 'scope gate', 'sandboxed exec', 'findings'],
  sibling: { name: 'mimir', note: 'Rogue shares its console with mimir, a TUI by the same author.' },
};

export type Stage = 'START' | 'RECON' | 'SCOPE' | 'EXEC' | 'HOLD' | 'FIND';

/** The idle trace the hero prints. Lab hosts and most tool names are illustrative. */
export const trace: { stage: Stage; detail: string }[] = [
  { stage: 'START', detail: 'session open · scope lab.local, 127.0.0.1' },
  { stage: 'RECON', detail: 'whois lab.local · passive' },
  { stage: 'RECON', detail: 'http_probe 3 hosts · 2 answer' },
  { stage: 'SCOPE', detail: 'nuclei_scan 10.0.8.14 · active, in scope' },
  { stage: 'EXEC', detail: 'nuclei_scan in sandbox · JSONL out' },
  { stage: 'HOLD', detail: 'port_scan 10.0.9.0/24 · not in scope' },
  { stage: 'FIND', detail: 'medium · exposed .git on lab.local' },
  { stage: 'EXEC', detail: 'exploit_poc 127.0.0.1:5000 · loopback' },
  { stage: 'FIND', detail: 'high · PoC confirms path traversal' },
];
export const tracePlaceholder = true; // tool names other than nuclei_scan are illustrative

export const statement = {
  lead: 'A language model with a shell is a loaded tool with the safety off.',
  rest: 'Rogue hands it 78 tools and one rule it cannot talk its way past: nothing active leaves loopback unless the target is in scope.',
  body: 'Rogue is the harness around the model. The model plans the engagement. Rogue decides what is reachable, runs each call sandboxed, and keeps a trace you can read back line by line.',
};

export type Family = { cmd: string; name: string; what: string; example: string; exampleReal?: boolean; placeholder?: boolean; detail: string };

export const arsenal: Family[] = [
  {
    cmd: '/recon',
    name: 'Recon',
    what: 'Passive first: names, records, certificates, what answers.',
    example: 'whois, dns_lookup, http_probe',
    placeholder: true,
    detail: 'The model builds a picture of the target before it sends anything that could break it. Recon calls are passive, so the gate lets them through at every scope setting.',
  },
  {
    cmd: '/web',
    name: 'Web scanning',
    what: 'Templated scans whose JSONL output parses straight into findings.',
    example: 'nuclei_scan',
    exampleReal: true,
    detail: 'nuclei_scan runs nuclei templates and reads its JSONL output line by line into findings, so a scan result is evidence the report can cite, not a wall of terminal text.',
  },
  {
    cmd: '/network',
    name: 'Network',
    what: 'Port and service discovery, gated by reachability.',
    example: 'port_scan, service_probe',
    placeholder: true,
    detail: 'Active by nature. Against loopback they run; against anything else they need the host in scope, or they wait in HOLD.',
  },
  {
    cmd: '/exploit',
    name: 'Exploit PoCs',
    what: 'Proof-of-concept runners that prove a bug and stop there.',
    example: 'exploit_poc',
    placeholder: true,
    detail: 'A PoC answers one question: is it real? It runs in the sandbox, records what it proved and leaves the target as it found it.',
  },
  {
    cmd: '/ctf',
    name: 'CTF runners',
    what: 'Runners for capture-the-flag targets, where the lab is the scope.',
    example: 'ctf_run',
    placeholder: true,
    detail: 'Practice against challenge boxes with the same gate and the same trace as a real engagement, so habits carry over.',
  },
  {
    cmd: '/report',
    name: 'Findings',
    what: 'Every tool returns one finding shape, so the trace becomes a report.',
    example: 'domain.Finding',
    exampleReal: true,
    detail: 'Severity, target, evidence and the call that produced it. Findings from different tools sort, merge and export together.',
  },
];

export const gate = {
  title: 'The scope gate',
  lead: 'Every tool call has a class: passive, active on loopback, or active on the network. Your scope sets the gate.',
  body: 'A call that fits rolls into the sandbox and runs. A call that does not fit stops at the lintel and goes back to the queue, held, with the reason written down.',
  try: 'Turn the knob and watch which calls reach the sandbox.',
  note: 'The figure is a physical model of the rule, not a picture of the code.',
};

export const stages: { stage: Stage; title: string; body: string; line: string }[] = [
  {
    stage: 'RECON',
    title: 'Map before you touch',
    body: 'The model starts passive. Lookups, probes and certificate data sketch the target without sending anything that could break it.',
    line: 'whois lab.local · 3 records',
  },
  {
    stage: 'SCOPE',
    title: 'Ask the gate',
    body: 'Before an active call runs, Rogue checks reachability. Is the host loopback? Is it in the scope file? Does the integration boundary allow this action?',
    line: 'nuclei_scan 10.0.8.14 · in scope',
  },
  {
    stage: 'EXEC',
    title: 'Run it in the box',
    body: 'Calls that pass run sandboxed. The model sees the output, never your shell, and every run is recorded with its arguments.',
    line: 'sandbox · nuclei_scan · exit 0',
  },
  {
    stage: 'HOLD',
    title: 'Stop and wait',
    body: 'A call that fails the gate is not retried with a cleverer prompt. It is held with its reason, for a person to approve or drop.',
    line: 'port_scan 10.0.9.0/24 · held',
  },
  {
    stage: 'FIND',
    title: 'Write it down',
    body: 'Output becomes findings: severity, target, evidence and the call that produced them. The trace you just read is the report’s appendix.',
    line: 'medium · exposed .git · 1 finding',
  },
];
export const stagesPlaceholder = true; // boundary wording to be checked against the code

export const rules: { name: string; body: string; placeholder?: boolean }[] = [
  { name: 'Loopback is home', body: 'Active tools may run against 127.0.0.1 and ::1 without a scope entry. Labs, CTF boxes and local services live here.', placeholder: true },
  { name: 'Off loopback needs scope', body: 'An active call to any other host must match the engagement’s scope. No match, no packet.', placeholder: true },
  { name: 'Passive stays passive', body: 'Recon that only reads public records runs at every scope setting, because it sends nothing to the target.', placeholder: true },
  { name: 'Integrations declare their edges', body: 'Each integration states which hosts and actions it may reach. Rogue checks the boundary, not the model’s intent.', placeholder: true },
  { name: 'Execution is sandboxed', body: 'Tools that pass the gate run sandboxed, away from the operator’s own shell and files.', placeholder: true },
  { name: 'Held means held', body: 'A refused call waits with its reason. Rephrasing the request does not reopen the gate; a person does.', placeholder: true },
];

/** Shape of a finding, shown on /boundaries. Field names are a placeholder for domain.Finding. */
export const sampleFinding = {
  placeholder: true,
  json: `{
  "id": "F-0007",
  "tool": "nuclei_scan",
  "target": "http://lab.local",
  "severity": "medium",
  "title": "Exposed .git directory",
  "evidence": "GET /.git/HEAD -> 200 ref: refs/heads/main",
  "call": "nuclei_scan -u http://lab.local -t exposures/",
  "stage": "FIND"
}`,
};

export const commands = [
  { name: '/home', desc: 'Back to the console', href: '/' },
  { name: '/arsenal', desc: 'The tool index: 78 tools in six families', href: '/arsenal' },
  { name: '/boundaries', desc: 'The rules a call must pass before it runs', href: '/boundaries' },
  { name: '/gate', desc: 'Turn the scope knob on the gate figure', href: '/#gate' },
  { name: '/engagement', desc: 'One engagement, stage by stage', href: '/#engagement' },
  { name: '/clone', desc: 'Copy the git clone command', action: 'clone' },
  { name: '/source', desc: 'Open the repository', href: site.repo.href, external: true },
] as const;

export const stageColor: Record<Stage, string> = {
  START: 'var(--c-green)',
  RECON: 'var(--c-cyan)',
  SCOPE: 'var(--c-yellow)',
  EXEC: 'var(--c-cyan)',
  HOLD: 'var(--c-yellow)',
  FIND: 'var(--c-green)',
};
