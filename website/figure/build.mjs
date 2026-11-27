// Builds the "scope gate" isometric figure (anatomy kit, framework-free path).
// Writes src/generated/scope-gate.json: the plate HTML and the numbers the live module needs.
// Run: node figure/build.mjs   (also runs as `prebuild` / `predev`)
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as k from "./kit/iso-kit.mjs";
import { BODY_TOP, CLASSES, SCOPES, HOME, lintelAt } from "./model.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, "../src/generated/scope-gate.json");

const WIDTH = 640;
const HEIGHT = 400;

// ---------- World plan (x along the track, y across it, z up; ~1 unit = 1 px) ----------
const PLATE = { x: -176, y: -66, w: 352, d: 132, r: 8 };
const PLATE_H = 12;
const FOOT_H = 5;

const RAILS = [-12, 12];
const RAIL_FROM = -156;
const RAIL_TO = 117;

const CAR = { x: -16, y: -18, w: 32, d: 36, r: 2.5 };
const CAR_Z = 3;

const CART = { x: -9, y: -11, w: 18, d: 22, r: 1.5 };

const POST_X = 34; // doorway posts x 34..42
const POST_W = 8;
const POST_FAR = { x: POST_X, y: -56, w: POST_W, d: 8, r: 1.2 };
const POST_NEAR = { x: POST_X, y: 44, w: POST_W, d: 8, r: 1.2 };
const POST_H = 64;
const HEAD = { x: 30, y: -58, w: 16, d: 112, r: 2 };
const HEAD_Z = POST_H;
const HEAD_H = 8;
const HEAD_TOP = HEAD_Z + HEAD_H;
const LINTEL = { x: 35, y: -48, w: 6, d: 92, r: 0.8 };
const LINTEL_H = 7;
const KNOB = [38, -2];
const KNOB_R = 5.4;
const KNOB_H = 5;
const TICK_R = 8.2;
const KNOB_FROM = -Math.PI / 3;
const KNOB_SPAN = (Math.PI * 2) / 3;
const LAMPS = { pass: [38, -40], hold: [38, 34] };

const CAGE_X0 = 42;
const CAGE_X1 = 118;
const END_POST_X = 118;
const CAGE_H = 64;
const BUFFER = { x: 108, y: -8, w: 8, d: 16, r: 1.2 };

const RACK = { x: -168, y: -60, w: 76, d: 18, r: 2 };
const RACK_Z = 5;
const RACK_CODES = [0, 2, 1, 0, 2];

// ---------- Camera ----------
const P = k.fitProjection(
  [...k.boxCorners(PLATE, -PLATE_H - FOOT_H, 0), [HEAD.x, HEAD.y, HEAD_TOP + 6], [HEAD.x + HEAD.w, HEAD.y + HEAD.d, HEAD_TOP + 6], [END_POST_X + 6, 52, CAGE_H]],
  WIDTH,
  HEIGHT,
  { pad: 26, azimuth: 52 },
);

const at = (p) => k.iso(p, P);
const S = (paths, style) => k.solidSvg(paths, style);
const L = (d, style) => k.lineSvg(d, style);
const D = (points, style) => k.dotsSvg(points, style);
const byDepth = (points) => [...points].sort((a, b) => k.depthOf([a[0], a[1], 0], P) - k.depthOf([b[0], b[1], 0], P));
const quad = (pts) => k.pathOf(pts.map(at), true);
const seg = (a, b) => k.segment(a, b, P);

// ---------- Base ----------
function base() {
  const out = [`<path class="iso-halo" d="${k.haloOf(PLATE, -PLATE_H - FOOT_H, PLATE_H, P)}"/>`];
  for (const [x, y] of byDepth(k.corners(PLATE, 24))) {
    out.push(S(k.cylinder(x, y, 7, -PLATE_H - FOOT_H, 1.6, P, 28), { tone: "lo" }));
    out.push(S(k.cylinder(x, y, 5.4, -PLATE_H - FOOT_H + 1.6, FOOT_H - 1.6, P, 28), { tone: "mid" }));
  }
  out.push(S(k.slabOf(PLATE, -PLATE_H, PLATE_H, P, 8, 1.6), { tone: "mid" }));
  out.push(L(k.planOutline(k.insetPlan(PLATE, 5), 0, P), { tone: "lo" }));
  const screws = k.corners(PLATE, 10);
  out.push(L(screws.map(([x, y]) => k.ring(x, y, 2.2, 0, P, 16)).join(""), { tone: "lo" }));
  out.push(D(screws.map(([x, y]) => at([x, y, 0])), { size: 0.5 }));

  // travel ruler along the front edge
  const strip = { x: -150, y: 52, w: 262, d: 6, r: 1 };
  out.push(S(k.slabOf(strip, 0, 0.6, P, 3), { tone: "lo", crease: "none" }));
  const ticks = k.topTicks(strip.x + 4, strip.x + strip.w - 4, 4, 5, strip.y + 0.8, 0.6, [1.8, 3.4], P);
  out.push(L(ticks.minor, { tone: "lo" }), L(ticks.major, { tone: "mid" }));
  out.push(D([at([strip.x + 2, strip.y + 3, 0.6]), at([strip.x + strip.w - 2, strip.y + 3, 0.6])], { size: 0.45 }));

  // label plate, one engraved word
  const label = { x: -166, y: 26, w: 34, d: 18, r: 1.5 };
  out.push(S(k.slabOf(label, 0, 0.8, P, 4), { tone: "lo", crease: "none" }));
  out.push(L(k.planOutline(k.insetPlan(label, 1.6), 0.8, P, 4), { tone: "faint" }));
  out.push(k.faceTextSvg(k.topMatrix([label.x + 4, label.y + 7], 0.8, P, "x"), "SCOPE", { size: 3.4, tone: "mid" }));
  for (const [y, len] of [[11, 24], [13.4, 18], [15.6, 12]]) out.push(L(k.lineOnTop([label.x + 4, label.y + y], [label.x + 4 + len, label.y + y], 0.8, P), { tone: "lo", free: true }));
  out.push(D([at([label.x + label.w - 3, label.y + 3, 0.8]), at([label.x + label.w - 3, label.y + label.d - 3, 0.8])], { size: 0.45 }));

  // sandbox floor: exec indicator grid (pulses while a call runs)
  out.push(`<g data-part="exec">${D(k.dotGrid(54, 21, 14, 5, 4, 0, P), { size: 0.55, tone: "hi" })}</g>`);
  out.push(L(k.planOutline({ x: 50, y: 17, w: 60, d: 24, r: 1.5 }, 0, P, 3), { tone: "faint" }));
  return out.join("");
}

// ---------- Queue rack (the agent's pending calls) ----------
function cartridge(plan, z, H, { lit = false, code = 0, grip = true } = {}) {
  const out = [S(k.slabOf(plan, z, H, P, 3, 0.5), { tone: "hi", crease: "lo", lit })];
  if (grip) out.push(L(k.planOutline(k.insetPlan(plan, 2.4), z + H, P, 3), { tone: "faint" }));
  // class marks: 1, 2 or 3 engraved bars
  const cx = plan.x + plan.w / 2;
  const marks = code + 1;
  for (let i = 0; i < marks; i++) {
    const y = plan.y + plan.d / 2 + (i - (marks - 1) / 2) * 2.4;
    out.push(L(k.lineOnTop([cx - plan.w * 0.18, y], [cx + plan.w * 0.18, y], z + H, P), { tone: lit ? "lit" : "mid", free: true }));
  }
  return out.join("");
}

function rack() {
  const out = [];
  out.push(`<path class="iso-halo" d="${k.haloOf(k.insetPlan(RACK, 2), 0, 0.1, P)}" style="filter:blur(4px)"/>`);
  const back = { x: RACK.x, y: RACK.y - 2.4, w: RACK.w, d: 2.4, r: 0.6 };
  out.push(S(k.slabOf(back, 0, 24, P, 3, 0.4), { tone: "mid" }));
  out.push(D([at([back.x + 4, back.y + 1.2, 24]), at([back.x + back.w - 4, back.y + 1.2, 24])], { size: 0.45 }));
  out.push(S(k.slabOf(RACK, 0, RACK_Z, P, 4, 0.6), { tone: "mid" }));
  out.push(L(k.planOutline(k.insetPlan(RACK, 1.8), RACK_Z, P, 4), { tone: "faint" }));
  RACK_CODES.forEach((code, i) => {
    const x = RACK.x + 5 + i * 14.4;
    const fin = { x: x - 2.6, y: RACK.y + 1.5, w: 1.2, d: RACK.d - 3, r: 0.4 };
    out.push(S(k.slabOf(fin, RACK_Z, 6, P, 2), { tone: "mid", crease: "none" }));
    out.push(cartridge({ x, y: RACK.y + 3, w: 10, d: 12, r: 1.2 }, RACK_Z, CLASSES[code].H, { code, grip: false }));
  });
  const lastFin = { x: RACK.x + 5 + 5 * 14.4 - 2.6, y: RACK.y + 1.5, w: 1.2, d: RACK.d - 3, r: 0.4 };
  out.push(S(k.slabOf(lastFin, RACK_Z, 6, P, 2), { tone: "mid", crease: "none" }));
  return out.join("");
}

// ---------- Cage, back half (behind the shuttle at every station) ----------
function wallSlots(x0, x1, y, zs, h) {
  return zs.map((z) => quad([[x0, y, z], [x1, y, z], [x1, y, z + h], [x0, y, z + h]])).join("");
}

function cageBack() {
  const out = [];
  out.push(`<path class="iso-halo" d="${k.haloOf({ x: CAGE_X0, y: -56, w: 80, d: 108, r: 2 }, 0, 0.1, P)}" style="filter:blur(6px);opacity:.5"/>`);
  // far wall with vent slots (closed outlines on its near face)
  const wall = { x: CAGE_X0, y: -56, w: END_POST_X - CAGE_X0, d: 4, r: 0.4 };
  const slots = wallSlots(52, 108, wall.y + wall.d, [12, 20, 28, 36, 44], 2.6);
  out.push(S(k.slabOf(wall, 0, CAGE_H - 4, P, 2, 0.4), { tone: "mid", inner: L(slots, { tone: "lo" }) }));
  out.push(D([[46, 4], [46, 56], [114, 4], [114, 56]].map(([x, z]) => at([x, wall.y + wall.d, z])), { size: 0.45 }));
  // far end post
  out.push(S(k.slabOf({ x: END_POST_X, y: -56, w: 6, d: 8, r: 1.2 }, 0, CAGE_H, P, 3, 0.5), { tone: "mid" }));
  // far top bar along the wall
  out.push(S(k.slabOf({ x: CAGE_X0, y: -56, w: END_POST_X - CAGE_X0, d: 6, r: 0.8 }, CAGE_H - 4, 4, P, 2, 0.4), { tone: "mid" }));
  return out.join("");
}

// ---------- Rails and stops ----------
function rails() {
  const out = [];
  for (const y of RAILS) {
    out.push(S(k.slabOf({ x: RAIL_FROM, y: y - 2, w: RAIL_TO - RAIL_FROM, d: 4, r: 1 }, 0, 3, P, 3, 0.4), { tone: "mid" }));
    out.push(D([RAIL_FROM + 6, -40, 60, RAIL_TO - 5].map((x) => at([x, y, 3])), { size: 0.4 }));
  }
  const stop = { x: RAIL_FROM - 6, y: -17, w: 5, d: 34, r: 1.2 };
  out.push(S(k.slabOf(stop, 0, 8, P, 3, 0.5), { tone: "mid" }));
  out.push(D([at([stop.x + 2.5, -12, 8]), at([stop.x + 2.5, 12, 8])], { size: 0.45 }));
  return out.join("");
}

// ---------- Shuttle (built at x = 0, moved with translateAlong) ----------
function shuttle() {
  const out = [`<path class="iso-halo" d="${k.haloOf(k.insetPlan(CAR, 3), CAR_Z, 0.1, P)}" style="filter:blur(4px)"/>`];
  const bush = (x, y) => ({ x: x - 4, y: y - 3.5, w: 8, d: 7, r: 1 });
  const bushings = [[-11, -12], [11, -12], [-11, 12], [11, 12]];
  for (const [x, y] of byDepth(bushings.filter(([, y]) => y < 0))) out.push(S(k.slabOf(bush(x, y), 1.4, 7.6, P, 2, 0.4), { tone: "mid" }));
  out.push(S(k.slabOf(CAR, CAR_Z, BODY_TOP - CAR_Z, P, 5, 0.6), { tone: "mid" }));
  for (const [x, y] of byDepth(bushings.filter(([, y]) => y > 0))) out.push(S(k.slabOf(bush(x, y), 1.4, 7.6, P, 2, 0.4), { tone: "mid" }));
  out.push(D([-7, -2.4, 2.4, 7].map((y) => at([13, y, BODY_TOP])), { size: 0.4, tone: "lo" }));
  // seat lips
  out.push(S(k.slabOf({ x: -12, y: -15, w: 24, d: 2.6, r: 0.6 }, BODY_TOP, 2, P, 2), { tone: "mid", crease: "none" }));
  out.push(S(k.slabOf({ x: -12, y: 12.4, w: 24, d: 2.6, r: 0.6 }, BODY_TOP, 2, P, 2), { tone: "mid", crease: "none" }));
  // cartridges: one per class, one visible at a time
  CLASSES.forEach((c, i) => {
    out.push(`<g data-cart="${i}"${i === 0 ? "" : ' opacity="0"'}>${cartridge(CART, BODY_TOP, c.H, { lit: true, code: i })}</g>`);
  });
  // handle on the near face
  out.push(S(k.slabOf({ x: -2, y: CAR.y + CAR.d - 0.5, w: 4, d: 3.4, r: 0.8 }, 3.6, 2.6, P, 2), { tone: "mid", crease: "none" }));
  out.push(S(k.cylinder(0, CAR.y + CAR.d + 4.6, 2.6, 2.8, 5, P, 20), { tone: "mid" }));
  out.push(L(k.knurl(0, CAR.y + CAR.d + 4.6, 2.6, 2.8, 7.8, 18, P), { tone: "lo" }));
  return out.join("");
}

// ---------- Doorway (lintel and its head) ----------
function farPost() {
  return S(k.slabOf(POST_FAR, 0, POST_H, P, 3, 0.5), { tone: "mid", inner: L(k.sideSeam(POST_FAR, 8, P, 3), { tone: "faint" }) });
}

function lintel() {
  const out = [S(k.slabOf(LINTEL, 0, LINTEL_H, P, 2, 0.5), { tone: "hi", crease: "lo" })];
  out.push(L(k.lineOnTop([LINTEL.x + LINTEL.w / 2, LINTEL.y], [LINTEL.x + LINTEL.w / 2, LINTEL.y + LINTEL.d], LINTEL_H, P), { tone: "faint" }));
  out.push(D([-40, -14, 12, 38].map((y) => at([LINTEL.x + LINTEL.w / 2, y, LINTEL_H])), { size: 0.45 }));
  return out.join("");
}

const knobPointer = (turn) => {
  const a = KNOB_FROM + turn * KNOB_SPAN;
  const [x, y] = KNOB;
  return k.lineOnTop([x - Math.sin(a) * 1.4, y + Math.cos(a) * 1.4], [x + Math.sin(a) * (KNOB_R - 0.9), y - Math.cos(a) * (KNOB_R - 0.9)], HEAD_TOP + KNOB_H, P);
};

function head() {
  const out = [];
  out.push(S(k.slabOf(HEAD, HEAD_Z, HEAD_H, P, 3, 0.8), { tone: "mid", inner: L(k.sideSeam(HEAD, HEAD_Z + 2.4, P, 3), { tone: "faint" }) }));
  out.push(D([HEAD.y + 4, HEAD.y + HEAD.d - 4].map((y) => at([HEAD.x + HEAD.w / 2, y, HEAD_TOP])), { size: 0.5 }));
  // detent ticks for the three scope positions
  const t = k.radialTicks(KNOB[0], KNOB[1], TICK_R, 2, 1, HEAD_TOP, [2, 2], P, KNOB_FROM, KNOB_SPAN);
  out.push(L(t.major, { tone: "hi" }));
  out.push(L(k.ring(KNOB[0], KNOB[1], KNOB_R + 0.9, HEAD_TOP, P, 40), { tone: "lo" }));
  // knob
  out.push(S(k.cylinder(KNOB[0], KNOB[1], KNOB_R, HEAD_TOP, KNOB_H, P, 40, 0.5), { tone: "hi", crease: "lo" }));
  out.push(L(k.knurl(KNOB[0], KNOB[1], KNOB_R, HEAD_TOP + 0.6, HEAD_TOP + KNOB_H, 40, P), { tone: "lo" }));
  out.push(`<path data-part="pointer" class="iso-line" data-tone="lit" data-free="start" d="${knobPointer(0.5)}" style="stroke-width:1.1"/>`);
  // lamps: pass (green) and hold (yellow)
  for (const [name, [x, y]] of Object.entries(LAMPS)) {
    out.push(S(k.cylinder(x, y, 3.6, HEAD_TOP, 2.4, P, 24), { tone: "mid" }));
    out.push(S(k.cylinder(x, y, 2.6, HEAD_TOP + 2.4, 1.6, P, 24, 0.3), { tone: "hi", crease: "lo" }));
    const [cx, cy] = at([x, y, HEAD_TOP + 4]);
    out.push(`<ellipse data-lamp="${name}" class="sg-lamp" cx="${cx.toFixed(1)}" cy="${cy.toFixed(1)}" rx="2.6" ry="1.4" opacity="0"/>`);
  }
  return out.join("");
}

// near doorway post with the scope scale on its front face
function nearPost() {
  const out = [];
  const slot = quad([[POST_X + POST_W, 46, 16], [POST_X + POST_W, 47.6, 16], [POST_X + POST_W, 47.6, 42], [POST_X + POST_W, 46, 42]]);
  out.push(S(k.slabOf(POST_NEAR, 0, POST_H, P, 3, 0.5), { tone: "mid", inner: L(k.sideSeam(POST_NEAR, 8, P, 3) + slot, { tone: "faint" }) }));
  const strip = { x: POST_X + POST_W, y: 48.6, w: 0.8, d: 2.8, r: 0.3 };
  out.push(S(k.slabOf(strip, 14, 30, P, 2), { tone: "lo", crease: "none" }));
  const fx = strip.x + strip.w;
  const minor = [];
  const major = [];
  for (let z = 16; z <= 42; z += 2) {
    const big = SCOPES.some((_, s) => lintelAt(s) + 3 === z);
    (big ? major : minor).push(seg([fx, strip.y, z], [fx, strip.y + (big ? 2.8 : 1.4), z]));
  }
  out.push(L(minor.join(""), { tone: "lo" }), L(major.join(""), { tone: "hi" }));
  out.push(D([at([fx, strip.y + 1.4, 15]), at([fx, strip.y + 1.4, 43])], { size: 0.35 }));
  return out.join("");
}

// the lintel's pointer tab, which shows through the post slot (moves with the lintel)
function tab() {
  return S(k.slabOf({ x: POST_X + POST_W - 0.4, y: 46.1, w: 2.4, d: 1.4, r: 0.3 }, 2.4, 1.2, P, 2), { tone: "hi", lit: true, crease: "none" });
}

// ---------- Cage, front half ----------
function cageFront() {
  const out = [];
  out.push(S(k.slabOf({ x: BUFFER.x - 2, y: -6, w: 2, d: 12, r: 0.6 }, 2, 7, P, 2), { tone: "lo", crease: "none" }));
  out.push(S(k.slabOf(BUFFER, 0, 10, P, 3, 0.5), { tone: "mid" }));
  out.push(D([at([BUFFER.x + 4, -4, 10]), at([BUFFER.x + 4, 4, 10])], { size: 0.45 }));
  // end bottom bar across the track end
  out.push(S(k.slabOf({ x: END_POST_X + 1, y: -48, w: 4, d: 92, r: 0.6 }, 0, 5, P, 2, 0.4), { tone: "mid" }));
  // near bottom bar
  out.push(S(k.slabOf({ x: CAGE_X0, y: 46, w: END_POST_X - CAGE_X0, d: 4, r: 0.6 }, 0, 5, P, 2, 0.4), { tone: "mid" }));
  // near end post
  out.push(S(k.slabOf({ x: END_POST_X, y: 44, w: 6, d: 8, r: 1.2 }, 0, CAGE_H, P, 3, 0.5), { tone: "mid" }));
  // top bars: near side and end
  out.push(S(k.slabOf({ x: CAGE_X0, y: 46, w: END_POST_X - CAGE_X0, d: 4, r: 0.6 }, CAGE_H - 4, 4, P, 2, 0.4), { tone: "mid" }));
  out.push(S(k.slabOf({ x: END_POST_X + 1, y: -48, w: 4, d: 92, r: 0.6 }, CAGE_H - 4, 4, P, 2, 0.4), { tone: "mid" }));
  out.push(D([[END_POST_X + 3, -52], [END_POST_X + 3, 48]].map(([x, y]) => at([x, y, CAGE_H])), { size: 0.5 }));
  return out.join("");
}

// ---------- Assemble ----------
const L0 = lintelAt(1);
const shuttleSvg = shuttle();
const svg = k.figureSvg({
  width: WIDTH,
  height: HEIGHT,
  label:
    "A go/no-go gauge on a bench plate. A shuttle on two rails carries one tool-call cartridge from a queue rack toward a sandbox cage. The cage doorway has a lintel whose height is set by a scope knob on top. Short cartridges are passive calls, taller ones are active calls on loopback or on the network. A cartridge that fits under the lintel rolls into the cage and runs; one that is too tall stops at the lintel and returns, held.",
  body: [
    base(),
    rack(),
    cageBack(),
    rails(),
    farPost(),
    `<g data-slot="out"><g data-part="shuttle" transform="${k.translateAlong(P, [HOME, 0, 0])}">${shuttleSvg}</g></g>`,
    `<g data-part="lintel" transform="${k.translateAlong(P, [0, 0, L0])}">${lintel()}</g>`,
    head(),
    nearPost(),
    `<g data-part="tab" transform="${k.translateAlong(P, [0, 0, L0])}">${tab()}</g>`,
    `<g data-slot="in"></g>`,
    cageFront(),
  ],
});

const plate = k.plateHtml({
  fig: "Fig 1",
  title: "Scope gate",
  hint: "Tap or press 1 2 3 to turn the knob",
  readout: "whois · passive · loading",
  keys: [
    { mark: "lit", label: "The call in flight, and the knob pointer" },
    { mark: "raised", label: "Cartridge height is the call class" },
    { mark: "green", label: "Ran in the sandbox" },
  ],
  caption: "",
  body: `<div class="iso-stage" tabindex="0" role="slider" aria-label="Scope knob. Arrow keys or 1, 2 and 3 choose what the gate admits." aria-valuemin="1" aria-valuemax="3" aria-valuenow="2" aria-valuetext="${SCOPES[1].label}">${svg}</div>`,
});

mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(
  OUT,
  JSON.stringify({ html: plate, P, HEAD_TOP, KNOB, KNOB_R, KNOB_H, KNOB_FROM, KNOB_SPAN }, null, 0),
);
console.log(`scope gate: wrote ${OUT} (${(plate.length / 1024).toFixed(1)} KB)`);

if (process.argv.includes("--preview")) {
  const css = `.iso{--anatomy-page:#11111B;--anatomy-card:#181825}.sg-lamp{fill:#00FF9D}`;
  const page = k.pageHtml({ title: "Scope gate preview", theme: "dark", body: `<style>${css}</style>` + plate, width: 900 });
  writeFileSync(join(HERE, "preview.html"), page.replace('<g data-slot="in"></g>', ""));
  console.log("wrote figure/preview.html");
}

if (process.argv.includes("--poses")) {
  const css = `.iso{--anatomy-page:#11111B;--anatomy-card:#181825}.sg-lamp{fill:#00FF9D}`;
  const poses = [[-40, 2, 32], [16, 2, 32], [30, 2, 32], [38, 2, 32], [46, 2, 32], [60, 2, 32], [89.6, 2, 32], [25.2, 2, 20]];
  const pages = poses.map(([x, cls, lz]) => {
    let s = svg.replace(/(<g data-slot="out">)<g data-part="shuttle" transform="[^"]*">/, `$1<g data-part="shuttle" transform="${k.translateAlong(P, [x, 0, 0])}">`);
    s = s.replace(/<g data-cart="(\d)"( opacity="0")?>/g, (m, i) => `<g data-cart="${i}"${Number(i) === cls ? "" : ' opacity="0"'}>`);
    s = s.replace(/(data-part="(?:lintel|tab)" transform=")[^"]*"/g, `$1${k.translateAlong(P, [0, 0, lz])}"`);
    if (x >= 38) {
      const m = s.match(/<g data-slot="out">([\s\S]*?)<\/g><g data-part="lintel"/);
      s = s.replace(m[0], `<g data-slot="out"></g><g data-part="lintel"`).replace('<g data-slot="in"></g>', `<g data-slot="in">${m[1]}</g>`);
    }
    return `<div style="margin:8px 0"><p style="color:#888;font:12px monospace">x=${x} cls=${cls} lintel=${lz}</p><div class="iso-plate">${s}</div></div>`;
  });
  writeFileSync(join(HERE, "poses.html"), k.pageHtml({ title: "poses", theme: "dark", body: `<style>${css}</style>` + pages.join(""), width: 900 }));
  console.log("wrote figure/poses.html");
}
