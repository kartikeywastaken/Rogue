// The engagement driver. One variable, the current stage, set by whichever [data-stage] block
// crosses the middle of the viewport. Everything that carries the concept reads it: the status
// bar label and colour, the --stage colour on <html>, and the home page's decision trace.
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { onPage } from '../engine';

const COLOR: Record<string, string> = {
  START: 'var(--c-green)', RECON: 'var(--c-cyan)', SCOPE: 'var(--c-yellow)',
  EXEC: 'var(--c-cyan)', HOLD: 'var(--c-yellow)', FIND: 'var(--c-green)',
};
const STATUS: Record<string, string> = {
  START: 'Ready', RECON: 'Mapping the target', SCOPE: 'Checking scope',
  EXEC: 'Running in sandbox', HOLD: 'Held for review', FIND: 'Writing findings',
};

let current = '';
export function setStage(stage: string) {
  if (stage === current || !COLOR[stage]) return;
  current = stage;
  const html = document.documentElement;
  html.dataset.stage = stage;
  html.style.setProperty('--stage', COLOR[stage]);
  const label = document.querySelector<HTMLElement>('[data-stage-label]');
  const status = document.querySelector<HTMLElement>('[data-status]');
  if (label) printInto(label, stage);
  if (status) status.textContent = STATUS[stage];
}

// The label re-prints like terminal output: characters arrive on a stepped clock.
function printInto(el: HTMLElement, text: string) {
  gsap.killTweensOf(el);
  const s = { n: 0 };
  gsap.to(s, {
    n: text.length, duration: 0.24, ease: `steps(${text.length})`,
    onUpdate: () => { el.textContent = text.slice(0, Math.round(s.n)).padEnd(text.length, ' '); },
  });
}

export function initDriver() {
  onPage(() => {
    current = '';
    const first = document.querySelector<HTMLElement>('[data-stage]');
    setStage(first?.dataset.stage || document.documentElement.dataset.stage || 'START');

    document.querySelectorAll<HTMLElement>('[data-stage]').forEach((el) => {
      ScrollTrigger.create({
        trigger: el,
        start: 'top 55%',
        end: 'bottom 55%',
        onToggle: (self) => { if (self.isActive) setStage(el.dataset.stage!); },
      });
    });

    // Home: the sticky decision trace follows the chapters.
    const rows = [...document.querySelectorAll<HTMLElement>('[data-engage-row]')];
    const chapters = [...document.querySelectorAll<HTMLElement>('[data-chapter]')];
    const fill = document.querySelector<HTMLElement>('[data-engage-fill]');
    if (rows.length && chapters.length) {
      const mark = (i: number) => rows.forEach((r, j) => {
        r.classList.toggle('is-done', j < i);
        r.classList.toggle('is-now', j === i);
      });
      mark(-1);
      chapters.forEach((ch, i) => {
        ScrollTrigger.create({
          trigger: ch, start: 'top 55%', end: 'bottom 55%',
          onEnter: () => mark(i), onEnterBack: () => mark(i),
          onLeaveBack: () => { if (i === 0) mark(-1); },
        });
      });
      if (fill) {
        gsap.fromTo(fill, { scaleX: 0 }, {
          scaleX: 1, ease: 'none', transformOrigin: '0% 50%',
          scrollTrigger: { trigger: chapters[0].parentElement, start: 'top 55%', end: 'bottom 55%', scrub: true },
        });
      }
    }
  });
}
