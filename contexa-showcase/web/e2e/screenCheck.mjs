// The checks every screen capture runs (C-3, C-4, C-5): horizontal overflow, a line ending with one letter alone,
// serious or critical axe violations, and the main buttons, numbers and English words in the main area.
import AxeBuilder from '@axe-core/playwright';
import { join } from 'node:path';

export const WIDTHS = [390, 768, 1024, 1440];

/** `root` is the part whose limits are counted: the screen's main area, or an open window (S9). */
export async function inspect(page, root = 'main') {
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  const singleLetter = await page.evaluate(() => {
    const found = [];
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    const range = document.createRange();
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      const text = node.textContent ?? '';
      if (text.trim().length < 2 || node.parentElement?.closest('[aria-hidden="true"]')) continue;
      const tops = (from, to) => {
        range.setStart(node, from);
        range.setEnd(node, to);
        return [...range.getClientRects()]
          .filter((rect) => rect.width > 0)
          .map((rect) => Math.round(rect.top));
      };
      const lines = new Set(tops(0, text.length));
      if (lines.size < 2) continue;
      const last = Math.max(...lines);
      let letters = 0;
      for (let i = text.length - 1; i >= 0; i -= 1) {
        if (/\s/.test(text[i] ?? '')) continue;
        if (Math.max(...tops(i, i + 1)) !== last) break;
        if (/[\p{L}\p{N}]/u.test(text[i] ?? '')) letters += 1;
      }
      if (letters === 1) found.push(text.trim().slice(0, 40));
    }
    return found;
  });
  // C-3 and C-5: main buttons, numbers and (on Korean screens) English words in the main area; run IDs, product and
  // approach names and the "original" tags are the allowed exceptions (D-29), listed so a person reviews the rest.
  const limits = await page.evaluate((selector) => {
    const main = document.querySelector(selector);
    if (!main) return null;
    const visible = (element) => element.getClientRects().length > 0;
    const primaries = [...main.querySelectorAll('[class*="primary"], [data-main]')].filter(visible).length;
    // The bars' own labels (act and step numbers, the panel's cell numbers) are names, not values.
    const parts = [];
    const walker = document.createTreeWalker(main, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      const parent = node.parentElement;
      if (!parent || !visible(parent) || parent.closest('nav, ol[data-kind], [data-original]')) continue;
      if (/^\s*\d\s*$/.test(node.textContent ?? '')) continue;
      parts.push(node.textContent ?? '');
    }
    // Quantities only: a number inside a name or an address (Chrome/140, /24, GB-500, run IDs) is not one to read.
    const numbers = (parts.join(' ').match(/(?<![A-Za-z0-9/.\-])\d[\d,.]*(?![A-Za-z0-9/\-])/g) ?? []).length;
    // The original texts (marked data-original) are the allowed exception of C-5: the record as it is.
    const clone = main.cloneNode(true);
    clone.querySelectorAll('[data-original]').forEach((element) => element.remove());
    document.body.appendChild(clone);
    const text = clone.innerText;
    clone.remove();
    const english = [
      ...new Set(
        (text.match(/[A-Za-z][A-Za-z/-]{2,}/g) ?? []).filter(
          // A name cut off at a version number ("Chrome/140" reads as "Chrome/") is the same name.
          (word) =>
            !/^(Contexa|WAF|Spring|Security|Chrome|Windows|Mac|Safari|Cloudflare|Turnstile|PLM-OPS|GB-500|HX|Administrator|run|protocol|GB|pm|PC|AI|DB|SHA)$/i.test(
              word.replace(/[/-]+$/, ''),
            ),
        ),
      ),
    ];
    // The English edition (S11): Korean words left on an English screen, originals aside; and one headline a screen.
    const korean = [...new Set(text.match(/[가-힣]+/g) ?? [])].slice(0, 8);
    const headlines = main.querySelectorAll(selector === 'main' ? 'h1' : 'h2[data-modal-title]').length;
    return { primaries, numbers, english, korean, headlines };
  }, root);
  // The place band: its tabs must end before the difference badge begins (no part of the band covers another).
  const bandOverlap = await page.evaluate(() => {
    const band = document.querySelector('main nav');
    const last = band?.querySelector(':scope > ol')?.lastElementChild?.getBoundingClientRect();
    const badge = band?.querySelector(':scope > button')?.getBoundingClientRect();
    return last && badge && last.right > badge.left + 1 && last.bottom > badge.top + 1
      ? Math.round(last.right - badge.left)
      : 0;
  });
  const axe = await new AxeBuilder({ page }).analyze();
  const serious = axe.violations
    .filter((v) => v.impact === 'serious' || v.impact === 'critical')
    .map((v) => ({ id: v.id, nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 3) }));
  return { overflow, bandOverlap, singleLetter, serious, limits };
}

// The phone rules (mobile slide): text of at least 16 px and pressable targets of at least 44 px (the original records,
// marked data-original, and buttons inside a sentence are the stated exceptions), and the main button fixed at the
// bottom where the thumb reaches. Counted at phone widths only.
export async function mobile(page) {
  return page.evaluate(() => {
    const visible = (element) => {
      const style = getComputedStyle(element);
      return element.getClientRects().length > 0 && style.visibility !== 'hidden' && style.opacity !== '0';
    };
    const smallText = new Map();
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      const parent = node.parentElement;
      const text = (node.textContent ?? '').trim();
      if (!parent || text.length === 0 || !visible(parent)) continue;
      if (parent.closest('[data-original], [aria-hidden="true"], .skip-link, dialog:not([open])')) continue;
      const size = parseFloat(getComputedStyle(parent).fontSize);
      if (size < 15.5) smallText.set(text.slice(0, 30), size);
    }
    const smallTargets = [];
    const pressable = document.querySelectorAll(
      'a[href], button, summary, select, input, textarea, [role="tab"], [tabindex="0"]',
    );
    for (const control of pressable) {
      // A radio button or a check box is pressed through its label.
      const label = control.tagName === 'INPUT' ? control.closest('label') : null;
      const element = label ?? control;
      if (control.tagName === 'INPUT' && !label && control.classList.contains('visually-hidden')) continue;
      if (!visible(element) || element.closest('dialog:not([open])')) continue;
      // A term inside a sentence is part of the sentence (the inline exception of target size, WCAG 2.5.8).
      if (getComputedStyle(element).display === 'inline' || element.hasAttribute('data-term')) continue;
      const rect = element.getBoundingClientRect();
      if (rect.bottom < 0 || rect.width === 0) continue;
      if (rect.height < 43.5 || rect.width < 43.5) {
        smallTargets.push(
          `${element.tagName.toLowerCase()} ${Math.round(rect.width)}x${Math.round(rect.height)} ${(element.textContent ?? '').trim().slice(0, 24)}`,
        );
      }
    }
    const main = document.querySelector('main [data-main]');
    return {
      smallText: [...smallText.entries()].slice(0, 8).map(([text, size]) => `${size}px ${text}`),
      smallTextCount: smallText.size,
      smallTargets: [...new Set(smallTargets)].slice(0, 8),
      smallTargetCount: smallTargets.length,
      mainFixed: main ? getComputedStyle(main).position === 'fixed' : null,
    };
  });
}

export async function capture(page, out, language, name, report, root = 'main') {
  for (const width of WIDTHS) {
    await page.setViewportSize({ width, height: 900 });
    await page.waitForTimeout(300);
    if (width <= 390) {
      // On a phone the main button is fixed to the screen's bottom: one capture as the visitor sees the screen, and a
      // full-page one for reading the content with the button left in its place (a full page has no screen bottom).
      await page.screenshot({ path: join(out, `${name}-${language}-${width}-screen.png`) });
      const unfixed = await page.addStyleTag({ content: 'main [data-main] { position: static !important; }' });
      await page.screenshot({ path: join(out, `${name}-${language}-${width}.png`), fullPage: true });
      await unfixed.evaluate((element) => element.remove());
    } else {
      await page.screenshot({ path: join(out, `${name}-${language}-${width}.png`), fullPage: true });
    }
    report.push({
      language,
      name,
      width,
      ...(await inspect(page, root)),
      ...(width <= 390 ? { phone: await mobile(page) } : {}),
    });
  }
  await page.setViewportSize({ width: 1440, height: 900 });
}
