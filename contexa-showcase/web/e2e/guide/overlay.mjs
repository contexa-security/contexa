// What the recorder draws over a screen while it records (가이드영상-제작기획안.md 5절): a focus frame that lights the part the
// scene is about and dims the rest, a pointer that goes to what is pressed, numbered badges for the steps of a procedure,
// short name labels beside a target, and the end stamp. It is a layer of fixed boxes over the page: it never changes the
// page's own elements, and it is added by the recording only, never by the site. The words come from the dictionary of the
// recorded language.
export const OVERLAY_CSS = `
  html[data-guide-recording] [data-guide-slot] { visibility: hidden !important; }
  #guide-box, #guide-pointer, #guide-end, .guide-badge, .guide-label { position: fixed; z-index: 2147483647; pointer-events: none; }
  #guide-box { border: 3px solid #f2c14e; border-radius: 12px; box-shadow: 0 0 0 9999px rgb(4 8 16 / 45%);
    transition: left 260ms ease, top 260ms ease, width 260ms ease, height 260ms ease, opacity 200ms ease; opacity: 0; }
  #guide-pointer { inline-size: 36px; block-size: 36px; margin: -18px 0 0 -18px; border-radius: 50%;
    background: rgb(242 193 78 / 50%); border: 3px solid #fff; opacity: 0; left: 0; top: 0; }
  #guide-pointer[data-down] { animation: guide-press 320ms ease-out; }
  @keyframes guide-press { 0% { box-shadow: 0 0 0 0 rgb(242 193 78 / 80%); } 100% { box-shadow: 0 0 0 26px rgb(242 193 78 / 0%); } }
  .guide-badge { inline-size: 32px; block-size: 32px; margin: -16px 0 0 -16px; border-radius: 50%; background: #f2c14e;
    color: #171206; font: 800 19px/32px var(--font-sans, sans-serif); text-align: center; border: 2px solid #171206; }
  .guide-label { max-inline-size: 22rem; padding: 6px 14px; border-radius: 999px; background: #f2c14e; color: #171206;
    font: 700 18px/1.3 var(--font-sans, sans-serif); white-space: nowrap; }
  #guide-end { inset: auto 0 0 0; padding: 14px 20px; background: rgb(6 13 26 / 92%); color: #e8edf5;
    font: 600 20px/1.3 var(--font-sans, sans-serif); text-align: center; opacity: 0; }
  #guide-end[data-on] { opacity: 1; }
`;

/** Installed in every page of the recording (page.addInitScript): the layer's boxes and the window.__guide commands. */
export function installOverlay(css) {
  const mount = () => {
    if (document.getElementById('guide-box')) return;
    document.documentElement.setAttribute('data-guide-recording', '');
    const style = document.createElement('style');
    style.textContent = css;
    document.head.appendChild(style);
    for (const id of ['guide-box', 'guide-pointer', 'guide-end']) {
      const element = document.createElement('div');
      element.id = id;
      document.body.appendChild(element);
    }
    const pointer = document.getElementById('guide-pointer');
    document.addEventListener(
      'mousemove',
      (event) => {
        pointer.style.left = `${event.clientX}px`;
        pointer.style.top = `${event.clientY}px`;
        pointer.style.opacity = '1';
      },
      true,
    );
    document.addEventListener('mousedown', () => pointer.setAttribute('data-down', ''), true);
    document.addEventListener('mouseup', () => setTimeout(() => pointer.removeAttribute('data-down'), 340), true);
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount);
  else mount();
  window.__guide = {
    /** Lights `focus` (a box: x, y, width, height), draws the step badges and the name labels. */
    show({ focus, badges, labels }) {
      mount();
      const box = document.getElementById('guide-box');
      const pad = 8;
      box.style.left = `${focus.x - pad}px`;
      box.style.top = `${focus.y - pad}px`;
      box.style.width = `${focus.width + 2 * pad}px`;
      box.style.height = `${focus.height + 2 * pad}px`;
      box.style.opacity = '1';
      for (const old of document.querySelectorAll('.guide-badge, .guide-label')) old.remove();
      for (const badge of badges) {
        const element = document.createElement('div');
        element.className = 'guide-badge';
        element.textContent = String(badge.n);
        element.style.left = `${badge.x}px`;
        element.style.top = `${badge.y}px`;
        document.body.appendChild(element);
      }
      for (const label of labels) {
        const element = document.createElement('div');
        element.className = 'guide-label';
        element.textContent = label.text;
        element.style.left = `${label.x}px`;
        element.style.top = `${label.y}px`;
        document.body.appendChild(element);
      }
    },
    clear() {
      const box = document.getElementById('guide-box');
      if (box) box.style.opacity = '0';
      for (const old of document.querySelectorAll('.guide-badge, .guide-label')) old.remove();
    },
    stamp(text) {
      const end = document.getElementById('guide-end');
      end.textContent = text;
      end.setAttribute('data-on', '');
    },
  };
}
