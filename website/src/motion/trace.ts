// The hero's LATEST ACTIVITY panel keeps printing a scripted engagement while the visitor reads:
// the concept's idle state. One line every 1.9 s, three lines kept (as mimir does), on the GSAP
// clock, paused off screen, off under reduced motion.
import { gsap } from 'gsap';
import { prefersReducedMotion } from '../engine';

type Line = { stage: string; detail: string; color: string };

export function initTrace() {
  const list = document.querySelector<HTMLOListElement>('[data-trace]');
  const data = document.querySelector('[data-trace-script]');
  if (!list || !data || prefersReducedMotion()) return;
  const lines: Line[] = JSON.parse(data.textContent || '[]');
  let at = 3 % lines.length;
  let visible = true;
  let call: gsap.core.Tween | null = null;

  const print = () => {
    if (!visible) { call = gsap.delayedCall(0.6, print); return; }
    const line = lines[at++ % lines.length];
    const li = document.createElement('li');
    li.className = 'trace__row is-new';
    li.style.setProperty('--c', line.color);
    const st = document.createElement('span');
    st.className = 'trace__stage';
    st.textContent = line.stage;
    const de = document.createElement('span');
    de.className = 'trace__detail';
    li.append(st, de);
    list.append(li);
    while (list.children.length > 3) list.firstElementChild?.remove();
    const s = { n: 0 };
    gsap.to(s, {
      n: line.detail.length, duration: Math.min(0.9, line.detail.length * 0.022), ease: `steps(${line.detail.length})`,
      onUpdate: () => { de.textContent = line.detail.slice(0, Math.round(s.n)); },
      onComplete: () => li.classList.remove('is-new'),
    });
    call = gsap.delayedCall(1.9, print);
  };

  const io = new IntersectionObserver((e) => { visible = e[e.length - 1].isIntersecting; }, { rootMargin: '0px' });
  io.observe(list);
  call = gsap.delayedCall(2.4, print);
  return () => { io.disconnect(); call?.kill(); };
}
