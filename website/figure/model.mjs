// The scope gate model: one pure module that the build and the live figure both read.
// A tool call is a cartridge whose height is its class. The cage lintel height is the scope
// policy. A call enters the sandbox only if it fits under the lintel.

export const BODY_TOP = 7; // top of the shuttle body, where a cartridge sits
export const CLEAR = 5; // clearance between a fitting cartridge and the lintel

export const CLASSES = [
  { id: "passive", H: 8, label: "passive" },
  { id: "loopback", H: 14, label: "active, loopback" },
  { id: "network", H: 20, label: "active, network" },
];

// Knob positions: which classes the scope admits.
export const SCOPES = [
  { id: "passive", label: "passive only", admits: 0 },
  { id: "loopback", label: "loopback allowed", admits: 1 },
  { id: "scoped", label: "scoped hosts allowed", admits: 2 },
];

// Lintel bottom for a scope position: the tallest admitted cartridge plus clearance.
export const lintelAt = (scope) => BODY_TOP + CLASSES[SCOPES[scope].admits].H + CLEAR;
export const fits = (cls, scope) => CLASSES[cls].H + BODY_TOP + CLEAR <= lintelAt(scope);

// The call queue the tour plays. Targets are illustrative.
export const CALLS = [
  { tool: "whois", target: "example.org", cls: 0 },
  { tool: "nuclei_scan", target: "127.0.0.1:8080", cls: 1 },
  { tool: "nuclei_scan", target: "10.0.8.14", cls: 2 },
  { tool: "http_probe", target: "example.org", cls: 0 },
  { tool: "exploit_poc", target: "127.0.0.1:5000", cls: 1 },
  { tool: "port_scan", target: "10.0.8.0/24", cls: 2 },
];

// Track stations (shuttle centre, world x).
export const HOME = -118;
export const FEEL = 25.2; // cartridge front touching the lintel's back face
export const INSIDE = 89.6; // carriage nose on the buffer pad
export const SWAP = 38; // depth slot changes as the shuttle passes the doorway mid-plane

// Phase timings in seconds.
export const T = { load: 0.7, approach: 1.6, judge: 0.6, enter: 1.1, run: 1.4, hold: 1.0, back: 1.9 };
