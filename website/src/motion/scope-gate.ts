// Live scope gate: one phase machine on gsap.ticker. Every position comes from figure/model.mjs,
// and "fits" is decided physically: cartridge top + clearance against the lintel's real height.
import { gsap } from 'gsap';
import { translateAlong, lineOnTop } from '../../figure/kit/iso-kit.mjs';
import { BODY_TOP, CLEAR, CLASSES, SCOPES, CALLS, HOME, FEEL, INSIDE, SWAP, T, lintelAt } from '../../figure/model.mjs';
import fig from '../generated/scope-gate.json';
import { prefersReducedMotion } from '../engine';

const P = fig.P as Parameters<typeof translateAlong>[0];
const CHECK = 16; // where the shuttle pauses to be judged, just short of the doorway
const SHORT = ['passive', 'loopback', 'network'];

type Phase = 'load' | 'approach' | 'judge' | 'enter' | 'run' | 'hold' | 'back';

const inOut = (t: number) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
const lerp = (a: number, b: number, t: number) => a + (b - a) * t;

function pointerD(turn: number) {
  const a = fig.KNOB_FROM + turn * fig.KNOB_SPAN;
  const [x, y] = fig.KNOB;
  const r = fig.KNOB_R - 0.9;
  return lineOnTop([x - Math.sin(a) * 1.4, y + Math.cos(a) * 1.4], [x + Math.sin(a) * r, y - Math.cos(a) * r], fig.HEAD_TOP + fig.KNOB_H, P);
}

export function mountScopeGate(root: HTMLElement) {
  const stage = root.querySelector<HTMLElement>('.iso-stage')!;
  const svg = stage.querySelector('svg')!;
  const shuttle = svg.querySelector<SVGGElement>('[data-part="shuttle"]')!;
  const slotOut = svg.querySelector<SVGGElement>('[data-slot="out"]')!;
  const slotIn = svg.querySelector<SVGGElement>('[data-slot="in"]')!;
  const lintel = svg.querySelector<SVGGElement>('[data-part="lintel"]')!;
  const tab = svg.querySelector<SVGGElement>('[data-part="tab"]')!;
  const pointer = svg.querySelector<SVGPathElement>('[data-part="pointer"]')!;
  const exec = svg.querySelector<SVGGElement>('[data-part="exec"]')!;
  const carts = [...svg.querySelectorAll<SVGGElement>('[data-cart]')];
  const lampPass = svg.querySelector<SVGElement>('[data-lamp="pass"]')!;
  const lampHold = svg.querySelector<SVGElement>('[data-lamp="hold"]')!;
  const readout = root.querySelector<HTMLElement>('[data-readout]')!;
  const calm = prefersReducedMotion();

  const s = {
    call: 0,
    phase: 'load' as Phase,
    t: 0,
    x: HOME,
    from: HOME,
    to: HOME,
    fits: true,
    scope: 1,
    lintel: lintelAt(1),
    turn: 0.5,
    held: false,
    tourCalls: 0,
    touchedAt: -1e9,
    clock: 0,
  };
  const TOUR = [1, 2, 0];
  let tourAt = 0;

  const call = () => CALLS[s.call % CALLS.length];
  const showCart = (cls: number) => carts.forEach((g, i) => g.setAttribute('opacity', i === cls ? '1' : '0'));
  const locked = () => s.phase === 'judge' || s.phase === 'enter' || s.phase === 'run' || s.phase === 'hold' || (s.phase === 'back' && s.x > CHECK - 0.5);
  const physicallyFits = (cls: number) => BODY_TOP + CLASSES[cls].H + CLEAR <= s.lintel + 0.25;

  function words() {
    const c = call();
    const cls = SHORT[c.cls];
    const w: Record<Phase, string> = {
      load: 'loading',
      approach: 'to the gate',
      judge: s.fits ? 'fits, gate open' : 'too tall, stopped',
      enter: 'entering sandbox',
      run: 'running in sandbox',
      hold: 'held, needs scope',
      back: s.held ? 'back to the queue' : 'done, returning',
    };
    const pending = locked() && lintelAt(s.scope) !== s.lintel ? ' · knob locked' : '';
    return `${c.tool} · ${cls} · ${w[s.phase]}${pending}`;
  }

  function describe() {
    stage.setAttribute('aria-valuenow', String(s.scope + 1));
    stage.setAttribute('aria-valuetext', SCOPES[s.scope].label);
  }

  function go(phase: Phase) {
    s.phase = phase;
    s.t = 0;
    const c = call();
    if (phase === 'load') {
      s.held = false;
      showCart(c.cls);
      lampPass.setAttribute('opacity', '0');
      lampHold.setAttribute('opacity', '0');
    }
    if (phase === 'approach') { s.from = s.x; s.to = CHECK; }
    if (phase === 'judge') {
      s.fits = physicallyFits(c.cls);
      s.from = s.x;
      s.to = s.fits ? CHECK : FEEL;
      (s.fits ? lampPass : lampHold).setAttribute('opacity', '1');
    }
    if (phase === 'enter') { s.from = s.x; s.to = INSIDE; }
    if (phase === 'run') exec.classList.add('is-on');
    if (phase === 'hold') s.held = true;
    if (phase === 'back') {
      exec.classList.remove('is-on');
      lampPass.setAttribute('opacity', '0');
      s.from = s.x;
      s.to = HOME;
    }
  }

  function next() {
    switch (s.phase) {
      case 'load': return go('approach');
      case 'approach': return go('judge');
      case 'judge': return go(s.fits ? 'enter' : 'hold');
      case 'enter': return go('run');
      case 'run': return go('back');
      case 'hold': return go('back');
      case 'back':
        lampHold.setAttribute('opacity', '0');
        s.call++;
        s.tourCalls++;
        // idle tour: turn the knob every third call while nobody is touching it
        if (s.clock - s.touchedAt > 10 && s.tourCalls % 3 === 0) setScope(TOUR[++tourAt % TOUR.length], false);
        return go('load');
    }
  }

  const duration = (p: Phase) => (p === 'back' ? (s.held ? T.back * 0.8 : T.back) : p === 'judge' ? T.judge : T[p as keyof typeof T]);

  function draw() {
    if (s.x >= SWAP && shuttle.parentNode !== slotIn) slotIn.appendChild(shuttle);
    if (s.x < SWAP && shuttle.parentNode !== slotOut) slotOut.appendChild(shuttle);
    shuttle.setAttribute('transform', translateAlong(P, [s.x, 0, 0]));
    const lz = translateAlong(P, [0, 0, s.lintel]);
    lintel.setAttribute('transform', lz);
    tab.setAttribute('transform', lz);
    pointer.setAttribute('d', pointerD(s.turn));
    const text = words();
    if (readout.textContent !== text) readout.textContent = text;
  }

  function step(dt: number) {
    s.clock += dt;
    s.t += dt;
    const d = duration(s.phase);
    const k = Math.min(1, s.t / d);
    if (s.phase === 'approach' || s.phase === 'enter' || s.phase === 'back' || (s.phase === 'judge' && !s.fits)) {
      const e = s.phase === 'judge' ? 1 - Math.pow(1 - k, 3) : inOut(k);
      s.x = lerp(s.from, s.to, e);
    }
    // lintel and knob follow the knob target, unless the interlock holds them
    if (!locked()) {
      const goal = lintelAt(s.scope);
      s.lintel += (goal - s.lintel) * (1 - Math.exp(-dt / 0.32));
      if (Math.abs(goal - s.lintel) < 0.01) s.lintel = goal;
    }
    const turnGoal = locked() ? s.turn : s.scope / 2;
    s.turn += (turnGoal - s.turn) * (1 - Math.exp(-dt / 0.22));
    if (Math.abs(turnGoal - s.turn) < 0.001) s.turn = turnGoal;
    if (k >= 1) next();
  }

  // ----- still frame for reduced motion: the current call judged at the gate -----
  function still() {
    const c = call();
    showCart(c.cls);
    s.lintel = lintelAt(s.scope);
    s.turn = s.scope / 2;
    s.fits = physicallyFits(c.cls);
    s.phase = s.fits ? 'run' : 'hold';
    s.held = !s.fits;
    s.x = s.fits ? INSIDE : FEEL;
    lampPass.setAttribute('opacity', s.fits ? '1' : '0');
    lampHold.setAttribute('opacity', s.fits ? '0' : '1');
    exec.classList.toggle('is-on', s.fits);
    draw();
  }

  function setScope(next: number, byUser = true) {
    s.scope = Math.max(0, Math.min(SCOPES.length - 1, next));
    if (byUser) s.touchedAt = s.clock;
    describe();
    if (calm) still();
  }

  // ----- clock, visibility, input -----
  let visible = false;
  let running = false;
  const tick = (_time: number, deltaMs: number) => {
    step(Math.min(deltaMs / 1000, 1 / 30));
    draw();
  };
  const run = () => {
    if (calm || running || !visible) return;
    running = true;
    gsap.ticker.add(tick);
  };
  const halt = () => {
    if (!running) return;
    running = false;
    gsap.ticker.remove(tick);
  };
  const io = new IntersectionObserver((entries) => {
    visible = entries[entries.length - 1].isIntersecting;
    if (visible) run(); else halt();
  }, { rootMargin: '120px 0px' });
  io.observe(stage);

  const onClick = () => setScope((s.scope + 1) % SCOPES.length);
  const onKey = (e: KeyboardEvent) => {
    let to: number | null = null;
    if (e.key >= '1' && e.key <= '3') to = Number(e.key) - 1;
    if (e.key === 'ArrowRight' || e.key === 'ArrowUp') to = s.scope + 1;
    if (e.key === 'ArrowLeft' || e.key === 'ArrowDown') to = s.scope - 1;
    if (e.key === 'Home') to = 0;
    if (e.key === 'End') to = SCOPES.length - 1;
    if (e.key === 'Enter' || e.key === ' ') to = (s.scope + 1) % SCOPES.length;
    if (to === null) return;
    e.preventDefault();
    setScope(to);
  };
  stage.addEventListener('click', onClick);
  stage.addEventListener('keydown', onKey);

  describe();
  if (calm) still();
  else { go('load'); draw(); }

  return () => {
    halt();
    io.disconnect();
    stage.removeEventListener('click', onClick);
    stage.removeEventListener('keydown', onKey);
  };
}
