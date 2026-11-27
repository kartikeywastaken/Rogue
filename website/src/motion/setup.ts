// Global motion and console behaviour for Rogue. Runs once on the client before the first page.
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { navigate } from 'astro:transitions/client';
import { setTransition, setLoaderFormat, setLoaderExit, onPage, ease, prefersReducedMotion, scrollToTarget } from '../engine';
import { initDriver } from './driver';
import { initPalette } from './palette';
import { initTrace } from './trace';

gsap.registerPlugin(ScrollTrigger);

let pendingPath = '';

export function setupMotion() {
  // Remember where a navigation is going, so the curtain can type it.
  document.addEventListener('astro:before-preparation', (e) => {
    const to = (e as unknown as { to: URL }).to;
    pendingPath = to.pathname === '/' ? '/home' : to.pathname.replace(/\/$/, '');
  });

  // Loader: a boot counter in tools, not percent.
  setLoaderFormat((p) => `${String(Math.round((p / 100) * 78)).padStart(2, '0')}/78`);
  setLoaderExit((root) => {
    const tl = gsap.timeline();
    tl.to(root.querySelectorAll('[data-loader-out]'), { yPercent: -120, autoAlpha: 0, duration: 0.45, ease: ease.inOut, stagger: 0.05 })
      .to(root, { clipPath: 'inset(0% 0% 100% 0%)', duration: 0.7, ease: 'steps(12)' }, '-=0.15');
    return tl;
  });

  // Page transition: terminal rows fill the screen top to bottom while the command types,
  // then clear. Stepped timing: printing, not sliding.
  setTransition({
    leave: (c) => {
      const rows = c.querySelectorAll('.curtain__row');
      const cmd = c.querySelector<HTMLElement>('[data-curtain-cmd]')!;
      const text = pendingPath || '/';
      cmd.textContent = '';
      const typed = { n: 0 };
      return gsap.timeline()
        .set(c, { autoAlpha: 1 })
        .set(c.querySelector('.curtain__cmd'), { autoAlpha: 0 })
        .fromTo(rows, { scaleY: 0, transformOrigin: '50% 0%' }, { scaleY: 1, duration: 0.18, ease: 'steps(3)', stagger: 0.018 })
        .set(c.querySelector('.curtain__cmd'), { autoAlpha: 1 }, '-=0.2')
        .to(typed, { n: text.length, duration: Math.min(0.32, text.length * 0.03), ease: `steps(${text.length})`, onUpdate: () => { cmd.textContent = text.slice(0, Math.round(typed.n)); } }, '-=0.18');
    },
    enter: (c) => {
      const rows = c.querySelectorAll('.curtain__row');
      return gsap.timeline()
        .to(c.querySelector('.curtain__cmd'), { autoAlpha: 0, duration: 0.12 })
        .to(rows, { scaleY: 0, transformOrigin: '50% 100%', duration: 0.18, ease: 'steps(3)', stagger: 0.016 }, 0.04)
        .set(c, { autoAlpha: 0 });
    },
  });

  initPalette();
  initDriver();

  // Per page: current nav item, the hero intro, the trace printer, copy buttons, hash scroll.
  onPage(({ intro, path }) => {
    document.querySelectorAll<HTMLAnchorElement>('[data-nav]').forEach((a) => {
      const here = a.dataset.nav === '/' ? path === '/' : path.startsWith(a.dataset.nav!);
      if (here) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    });

    const offs: (() => void)[] = [];
    const hero = document.querySelector<HTMLElement>('.hero');
    if (hero && !prefersReducedMotion()) {
      const lines = hero.querySelectorAll('.hero__mark [data-line]');
      gsap.set(lines, { autoAlpha: 0 });
      gsap.set(hero.querySelectorAll('[data-intro-line], .hero__rune'), { autoAlpha: 0, y: 6 });
      gsap.set(hero.querySelectorAll('[data-intro-panel]'), { autoAlpha: 0, clipPath: 'inset(0% 0% 100% 0%)' });
      intro.add(gsap.to(hero.querySelector('.hero__rune'), { autoAlpha: 1, y: 0, duration: 0.3, ease: 'steps(3)' }), 0.05);
      intro.add(gsap.to(lines, { autoAlpha: 1, duration: 0.01, stagger: 0.09 }), 0.18);
      intro.add(gsap.to(hero.querySelectorAll('[data-intro-line]'), { autoAlpha: 1, y: 0, duration: 0.5, ease: ease.out, stagger: 0.07 }), 0.45);
      intro.add(gsap.to(hero.querySelectorAll('[data-intro-panel]'), { autoAlpha: 1, clipPath: 'inset(0% 0% 0% 0%)', duration: 0.5, ease: 'steps(8)', stagger: 0.12 }), 0.6);
    }
    const tr = initTrace();
    if (tr) offs.push(tr);

    const onCopy = (e: Event) => {
      const btn = (e.target as HTMLElement).closest<HTMLElement>('[data-action="clone"]');
      if (!btn) return;
      copyClone(btn);
    };
    document.addEventListener('click', onCopy);
    offs.push(() => document.removeEventListener('click', onCopy));

    // In-page hash targets after a cross-page navigation (e.g. /#gate from the palette)
    if (location.hash) {
      const el = document.querySelector(location.hash);
      if (el) requestAnimationFrame(() => scrollToTarget(el as HTMLElement));
    }
    return () => offs.forEach((f) => f());
  });
}

export async function copyClone(btn?: HTMLElement | null) {
  const text = document.querySelector('[data-clone-text]')?.textContent || 'git clone';
  const say = document.querySelector<HTMLElement>('[data-announce]');
  try {
    await navigator.clipboard.writeText(text);
    if (say) say.textContent = 'Clone command copied';
    const label = btn?.querySelector<HTMLElement>('[data-clone-label]');
    if (label) {
      label.textContent = 'copied';
      setTimeout(() => { label.textContent = 'copy'; }, 1600);
    }
  } catch {
    if (say) say.textContent = 'Copy failed. Select the command and copy it.';
  }
}

export function go(href: string) {
  const url = new URL(href, location.href);
  if (url.pathname === location.pathname && url.hash) {
    const el = document.querySelector(url.hash);
    if (el) { history.replaceState(null, '', url.hash); scrollToTarget(el as HTMLElement); return; }
  }
  navigate(url.pathname + url.hash);
}
