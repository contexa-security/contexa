// Measures the new screens in a real browser (UX-R1 UC-6 · UC-7): the type sizes and weights in use, the heights of the
// buttons, horizontal page scroll, parts that leave their card, lines that hold one letter alone, and where gold is used.
// Writes one JSON file and one full-page picture per combination, and prints a summary. A page that threw (pageerror) or
// shows no h1 counts as a problem too: a screen that failed to draw has nothing to measure and must never pass as clean.
//
//   node ux_measure.mjs --base http://127.0.0.1:5180 --paths /design/ux --widths 1440,390 --themes dark,light \
//        --langs ko,en --out <dir>
//
// The theme and the language are set the way a visitor's browser keeps them (localStorage), before the page loads.
import { createRequire } from 'node:module';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const require = createRequire('E:/projects/contexa/contexa-showcase/web/package.json');
const { chromium } = require('playwright');
const AxeBuilder = require('@axe-core/playwright').default;

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index > 0 ? process.argv[index + 1] : fallback;
}
const base = arg('base', 'http://localhost:5180');
const paths = arg('paths', '/design/ux').split(',');
const widths = arg('widths', '1440,390').split(',').map(Number);
const themes = arg('themes', 'dark,light').split(',');
const langs = arg('langs', 'ko,en').split(',');
// A Git Bash path (/c/Users/...) as Windows writes it, so the files land where asked even with MSYS_NO_PATHCONV=1.
const out = arg('out', '.').replace(/^\/([a-z])\//i, (_, drive) => `${drive.toUpperCase()}:/`);
const shots = arg('shots', 'yes') === 'yes';
const axe = arg('axe', 'yes') === 'yes';
mkdirSync(out, { recursive: true });

// Runs inside the page.
function inspect() {
  const visible = (el) => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && Number(s.opacity) > 0;
  };
  const ownText = (el) =>
    [...el.childNodes].some((n) => n.nodeType === Node.TEXT_NODE && n.textContent.trim().length > 0);
  const label = (el) => {
    const cls = typeof el.className === 'string' ? el.className.split(' ')[0] : '';
    return `${el.tagName.toLowerCase()}${cls ? '.' + cls : ''} "${(el.textContent || '').trim().slice(0, 30)}"`;
  };
  // Text clipped away for assistive technology only (the sr-only pattern, the rail's names) is not on the screen.
  const clipped = (el) => {
    for (let up = el; up; up = up.parentElement) {
      const s = getComputedStyle(up);
      if (s.clipPath === 'inset(50%)' || (up.getBoundingClientRect().width <= 1 && s.overflow === 'hidden')) return true;
    }
    return false;
  };
  const all = [...document.querySelectorAll('body *')].filter((el) => visible(el) && !clipped(el));

  const sizes = {};
  const weights = {};
  for (const el of all) {
    if (!ownText(el)) continue;
    const s = getComputedStyle(el);
    sizes[s.fontSize] = (sizes[s.fontSize] || 0) + 1;
    weights[s.fontWeight] = (weights[s.fontWeight] || 0) + 1;
  }

  const buttons = {};
  for (const el of all.filter((el) => el.matches('[data-variant]'))) {
    const h = `${Math.round(el.getBoundingClientRect().height)}px`;
    buttons[h] = (buttons[h] || 0) + 1;
  }

  // A part leaves its box when it crosses the edge of the nearest bordered, rounded ancestor (a card, a panel, a
  // table frame) with no scrolling or clipping container in between.
  const leaks = [];
  const scrolls = (el) => /(auto|scroll|hidden|clip)/.test(getComputedStyle(el).overflowX);
  const isBox = (el) => {
    const s = getComputedStyle(el);
    return parseFloat(s.borderTopLeftRadius) >= 8 && parseFloat(s.borderTopWidth) > 0;
  };
  for (const el of all) {
    if (!ownText(el) && !el.matches('svg, button, input, select, img, [data-variant]')) continue;
    let box = null;
    for (let up = el.parentElement; up && up !== document.body; up = up.parentElement) {
      if (scrolls(up)) {
        box = null;
        break;
      }
      if (isBox(up)) {
        box = up;
        break;
      }
    }
    if (!box) continue;
    const r = el.getBoundingClientRect();
    const b = box.getBoundingClientRect();
    if (r.right > b.right + 1 || r.left < b.left - 1) {
      leaks.push(`${label(el)} in ${label(box)} by ${Math.round(Math.max(r.right - b.right, b.left - r.left))}px`);
    }
  }

  // A line that holds one letter alone: a line of an element's own text whose whole line, counting the other text the
  // element sets beside it (an inline code, a bold figure), is narrower than 1.6 letters of its size. A fragment such
  // as "(" that ends one text and is followed on its line by a code chip is not alone (I-7, 2026-11-01).
  const lonely = [];
  const textRects = (root) => {
    const rects = [];
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      const range = document.createRange();
      range.selectNodeContents(node);
      rects.push(...[...range.getClientRects()].filter((r) => r.width > 0));
    }
    return rects;
  };
  for (const el of all) {
    // Original text shown as written (raw JSON, a model's answer) keeps its own lines: a line of "{" is the text's.
    if (getComputedStyle(el).whiteSpace.startsWith('pre')) continue;
    let beside = null;
    for (const node of el.childNodes) {
      if (node.nodeType !== Node.TEXT_NODE || node.textContent.trim().length < 2) continue;
      const range = document.createRange();
      range.selectNodeContents(node);
      const rects = [...range.getClientRects()].filter((r) => r.width > 0);
      if (rects.length < 2) continue;
      const size = parseFloat(getComputedStyle(el).fontSize);
      beside ??= textRects(el);
      for (const r of rects) {
        // Every text of the element on the same line: the rectangles that overlap this one vertically.
        const width = beside
          .filter((other) => other.top < r.bottom - 1 && other.bottom > r.top + 1)
          .reduce((sum, other) => sum + other.width, 0);
        if (width < size * 1.6) lonely.push(label(el));
      }
    }
  }

  const brandRgb = getComputedStyle(document.documentElement).getPropertyValue('--ux-brand').trim();
  const probe = document.createElement('span');
  probe.style.color = brandRgb;
  document.body.appendChild(probe);
  const brand = getComputedStyle(probe).color;
  probe.remove();
  const gold = [];
  for (const el of all) {
    const s = getComputedStyle(el);
    const uses = [
      ['text', s.color],
      ['fill', s.backgroundColor],
      ['line', s.borderBottomColor !== s.borderTopColor ? s.borderBottomColor : s.borderTopWidth !== '0px' ? s.borderTopColor : ''],
      ['stripe', s.boxShadow.includes(brand) ? brand : ''],
    ].filter(([, value]) => value === brand || (value && value.includes && value.includes(brand) && value !== s.color));
    const own = uses.filter(([kind]) => kind !== 'text' || ownText(el) || el.matches('svg'));
    if (own.length) gold.push(`${own.map(([kind]) => kind).join('+')} ${label(el)}`);
  }

  // Text contrast against the colour actually behind it (backgrounds blended up the tree): 4.5:1, or 3:1 for large text
  // (24px, or 18.66px bold). Disabled controls are exempt (WCAG 1.4.3).
  const rgba = (value) => {
    const m = value.match(/rgba?\(([^)]+)\)/);
    if (!m) return null;
    const p = m[1].split(/[ ,/]+/).filter(Boolean).map(Number);
    return [p[0], p[1], p[2], p.length > 3 ? p[3] : 1];
  };
  const over = (top, bottom) => [0, 1, 2].map((i) => top[i] * top[3] + bottom[i] * (1 - top[3])).concat(1);
  const behind = (el) => {
    const layers = [];
    for (let up = el; up; up = up.parentElement) {
      const c = rgba(getComputedStyle(up).backgroundColor);
      if (c && c[3] > 0) {
        layers.push(c);
        if (c[3] >= 1) break;
      }
    }
    let colour = [255, 255, 255, 1];
    for (const layer of layers.reverse()) colour = over(layer, colour);
    return colour;
  };
  const luminance = (c) => {
    const [r, g, b] = c.slice(0, 3).map((v) => {
      const x = v / 255;
      return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4;
    });
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  };
  const contrast = [];
  for (const el of all) {
    if (!ownText(el) || el.closest('[aria-disabled="true"], :disabled')) continue;
    const s = getComputedStyle(el);
    const fg = rgba(s.color);
    if (!fg) continue;
    const bg = behind(el);
    const text = over(fg, bg);
    const [a, b] = [luminance(text), luminance(bg)].sort((x, y) => y - x);
    const ratio = (a + 0.05) / (b + 0.05);
    const size = parseFloat(s.fontSize);
    const large = size >= 24 || (size >= 18.66 && Number(s.fontWeight) >= 700);
    if (ratio < (large ? 3 : 4.5)) contrast.push(`${ratio.toFixed(2)} ${label(el)}`);
  }

  return {
    sizes,
    contrast: [...new Set(contrast)],
    weights,
    buttons,
    pageScroll: document.documentElement.scrollWidth > window.innerWidth + 1,
    scrollWidth: document.documentElement.scrollWidth,
    leaks,
    lonely: [...new Set(lonely)],
    gold: [...new Set(gold)],
  };
}

const browser = await chromium.launch();
const results = [];
try {
  for (const path of paths) {
    for (const width of widths) {
      for (const theme of themes) {
        for (const lang of langs) {
          const context = await browser.newContext({ viewport: { width, height: 900 }, deviceScaleFactor: 1 });
          await context.addInitScript(
            ([t, l]) => {
              try {
                localStorage.setItem('showcase.theme', t);
                localStorage.setItem('showcase.language', l);
              } catch {}
              // The script also runs in a document that has no root element yet; the stored theme covers that page.
              document.documentElement?.setAttribute('data-theme', t);
            },
            [theme, lang],
          );
          const page = await context.newPage();
          const errors = [];
          page.on('pageerror', (error) => errors.push(String(error?.message ?? error)));
          await page.goto(`${base}${path}${path.includes('?') ? '&' : '?'}lng=${lang}&theme=${theme}`, {
            waitUntil: 'networkidle',
          });
          await page.evaluate(() => document.fonts.ready);
          await page.waitForTimeout(300);
          const found = await page.evaluate(inspect);
          found.errors = errors;
          found.headings = await page.locator('h1').count();
          if (axe) {
            const report = await new AxeBuilder({ page }).analyze();
            found.axe = report.violations
              .filter((v) => v.impact === 'critical' || v.impact === 'serious')
              .map((v) => `${v.impact} ${v.id} x${v.nodes.length}: ${v.nodes.slice(0, 2).map((n) => n.target.join(' ')).join(' | ')}`);
          }
          const name = `${path.replace(/[^a-z0-9]+/gi, '_')}_${width}_${theme}_${lang}`;
          if (shots) await page.screenshot({ path: join(out, `${name}.png`), fullPage: true });
          results.push({ path, width, theme, lang, ...found });
          const sizes = Object.keys(found.sizes).sort((a, b) => parseFloat(b) - parseFloat(a)).join(' ');
          console.log(
            `${name}: sizes[${sizes}] buttons[${Object.keys(found.buttons).join(' ')}] scroll=${found.pageScroll} ` +
              `leaks=${found.leaks.length} lonely=${found.lonely.length} gold=${found.gold.length} ` +
              `contrast=${found.contrast.length} axe=${found.axe ? found.axe.length : '-'} ` +
              `errors=${found.errors.length} h1=${found.headings}`,
          );
          await context.close();
        }
      }
    }
  }
} finally {
  await browser.close();
}
writeFileSync(join(out, 'measure.json'), JSON.stringify(results, null, 2));
// A combination with a problem: it threw, it has no h1, the page scrolls sideways, a part leaves its card, a line holds
// one letter alone, a pair of colours is below 4.5:1, or axe finds a critical or serious violation.
const problems = results.filter(
  (found) =>
    found.errors.length > 0 ||
    found.headings === 0 ||
    found.pageScroll ||
    found.leaks.length > 0 ||
    found.lonely.length > 0 ||
    found.contrast.length > 0 ||
    (found.axe?.length ?? 0) > 0,
);
console.log(`combinations ${results.length}, with a problem ${problems.length}`);
for (const found of problems) {
  console.log(
    `PROBLEM ${found.path} ${found.width} ${found.theme} ${found.lang}: errors=${JSON.stringify(found.errors)} h1=${found.headings} ` +
      `scroll=${found.pageScroll} leaks=${found.leaks.length} lonely=${found.lonely.length} contrast=${found.contrast.length} ` +
      `axe=${found.axe ? found.axe.length : '-'}`,
  );
}
