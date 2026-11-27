// mimir's slash palette, on the web. "/" anywhere opens it; typing filters; arrows choose;
// Enter runs. The hero panel uses the same list inline. Event delegation, registered once.
import { gsap } from 'gsap';
import { prefersReducedMotion } from '../engine';
import { go, copyClone } from './setup';

const visibleItems = (list: HTMLElement) =>
  [...list.querySelectorAll<HTMLElement>('li[data-cmd]')].filter((li) => !li.hidden && li.offsetParent !== null);

function setActive(list: HTMLElement, index: number) {
  const items = visibleItems(list);
  items.forEach((li, i) => li.toggleAttribute('data-active', i === index));
  list.dataset.active = String(index);
}

function filter(input: HTMLInputElement) {
  const list = document.getElementById(input.dataset.cmdFilter!);
  if (!list) return;
  const q = input.value.trim().toLowerCase().replace(/^\//, '');
  let shown = 0;
  list.querySelectorAll<HTMLElement>('li[data-cmd]').forEach((li) => {
    const text = (li.dataset.cmd + ' ' + li.textContent).toLowerCase();
    const hit = !q || text.includes(q);
    li.hidden = !hit;
    if (hit) shown++;
  });
  const empty = list.querySelector<HTMLElement>('.cmds__empty');
  if (empty) empty.hidden = shown > 0;
  setActive(list, q ? 0 : -1);
}

function run(el: HTMLElement) {
  const dialog = document.getElementById('palette') as HTMLDialogElement | null;
  if (el.dataset.action === 'clone') {
    copyClone(document.querySelector('.finale [data-action="clone"]'));
    dialog?.open && dialog.close();
    return;
  }
  const a = el as HTMLAnchorElement;
  if (a.target === '_blank') { window.open(a.href, '_blank', 'noopener'); dialog?.open && dialog.close(); return; }
  dialog?.open && dialog.close();
  go(a.getAttribute('href') || '/');
}

export function openPalette() {
  const dialog = document.getElementById('palette') as HTMLDialogElement | null;
  const input = document.getElementById('palette-input') as HTMLInputElement | null;
  if (!dialog || !input || dialog.open) return;
  dialog.showModal();
  input.value = '/';
  filter(input);
  input.focus();
  input.setSelectionRange(1, 1);
  if (!prefersReducedMotion()) {
    const panel = dialog.querySelector('.palette__panel');
    gsap.fromTo(panel, { clipPath: 'inset(0% 0% 100% 0%)' }, { clipPath: 'inset(0% 0% 0% 0%)', duration: 0.32, ease: 'steps(6)' });
    gsap.fromTo(dialog.querySelectorAll('li[data-cmd]'), { autoAlpha: 0 }, { autoAlpha: 1, duration: 0.01, stagger: 0.03, delay: 0.1 });
  }
}

export function initPalette() {
  document.addEventListener('input', (e) => {
    const input = e.target as HTMLInputElement;
    if (input.matches?.('[data-cmd-filter]')) filter(input);
  });

  document.addEventListener('keydown', (e) => {
    const t = e.target as HTMLElement;
    const typing = t.closest('input, textarea, [contenteditable="true"]');
    if (e.key === '/' && !typing && !e.metaKey && !e.ctrlKey && !e.altKey) {
      e.preventDefault();
      openPalette();
      return;
    }
    if (!t.matches?.('[data-cmd-filter]')) return;
    const input = t as HTMLInputElement;
    const list = document.getElementById(input.dataset.cmdFilter!);
    if (!list) return;
    const items = visibleItems(list);
    let i = Number(list.dataset.active ?? -1);
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive(list, Math.min(items.length - 1, i + 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive(list, Math.max(0, i - 1)); }
    else if (e.key === 'Enter') {
      e.preventDefault();
      const pick = items[Math.max(0, i)];
      const target = pick?.querySelector<HTMLElement>('[data-cmd-run]');
      if (target) run(target);
    }
  });

  document.addEventListener('click', (e) => {
    const t = e.target as HTMLElement;
    if (t.closest('[data-palette-open]')) { openPalette(); return; }
    const dialog = document.getElementById('palette') as HTMLDialogElement | null;
    if (dialog?.open && t === dialog) { dialog.close(); return; }
    const runEl = t.closest<HTMLElement>('[data-cmd-run]');
    if (!runEl) return;
    const a = runEl as HTMLAnchorElement;
    if (a.tagName === 'A' && (a.target === '_blank' || e.metaKey || e.ctrlKey || e.shiftKey)) return; // let the browser open it
    e.preventDefault();
    run(runEl);
  });

  // Pointer hover moves the active row too, so keyboard and mouse agree.
  document.addEventListener('pointerover', (e) => {
    const li = (e.target as HTMLElement).closest<HTMLElement>('[data-cmds] li[data-cmd]');
    if (!li) return;
    const list = li.closest<HTMLElement>('[data-cmds]')!;
    const items = visibleItems(list);
    setActive(list, items.indexOf(li));
  });
}
