// The measuring and judging of the redesign's automatic check (docs/showcase/화면재편-구현계획.md R0-3, RC-1 to RC-3),
// shared by frame-audit.mjs (every screen by address) and frame-live.mjs (the screens that appear after a real send).
// Same definitions as the 2026-10-18 baseline (redesign-audit/audit.json).

export const LIMITS = { press: 3, boxes: 4, numbers: 8, height390: 1266, gapP10: 12, gapP50: 24 };
const SIZES = { 1440: 4, 390: 3 };
// The old column of the final design's term table (설계서 43~45장, 최종화면-구현계획 F3-6): words no screen shows.
const BANNED = [
  '계정을 훔친 사람', '진짜 직원', '본인 확인', '규칙 조여 보기', '정상 업무 막음', '업무를 막음', '평소 모습', '시간·건수 제한',
  '웹 방화벽', '로그인·권한 확인', '결재·담당 확인', '판정 자세히 보기', '응답 전에 막기', '다음 요청부터 막기',
  '보류(관리자 검토)', '출처 문장',
];
const BANNED_PATTERNS = [
  [/막\s?[1-4](?![0-9])|[1-4]막|막 끝|다음 막/, 'unit word 막'],
  [/(?<![0-9])[1-5]장(?![가-힣])/, 'unit word 장'],
  [/\b[A-Z][A-Z0-9]+(?:_[A-Z0-9]+)+\b/, 'engine code'],
  [/\bF\d{1,2}\b/, 'fact number'],
  [/run-[0-9a-f]{6,}/, 'run id'],
];

export function measure() {
  const visible = (element) => {
    const rect = element.getBoundingClientRect();
    const style = getComputedStyle(element);
    return rect.width > 2 && rect.height > 2 && style.visibility !== 'hidden' && style.display !== 'none' && style.opacity !== '0';
  };
  const pressSelector = 'button, a[href], [role="button"], summary, select, input, textarea';
  const dialog = document.querySelector('dialog[open]');
  const main = document.querySelector('main') || document.body;
  const zones = [...(dialog || document).querySelectorAll('[data-zone="title"], [data-zone="body"], [data-zone="source"]')];
  const framed = zones.length > 0;
  const roots = framed ? zones : [dialog || main];
  const inRoots = (selector) => roots.flatMap((root) => [...root.querySelectorAll(selector)]);
  const exempt = (element) => element.closest('[data-count="exempt"]') !== null;
  const h1 = document.querySelector(dialog ? 'dialog[open] h1, dialog[open] h2' : 'h1');
  let press = inRoots(pressSelector).filter(visible).filter((element) => !exempt(element));
  let bands = 0;
  if (!framed && h1 && !dialog) {
    bands = press.filter((element) => element.compareDocumentPosition(h1) & Node.DOCUMENT_POSITION_FOLLOWING).length;
    press = press.slice(bands);
  }
  const text = roots.map((root) => root.innerText || '').join('\n').trim();
  const quantities = [];
  for (const root of roots) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      const parent = node.parentElement;
      if (!parent || !visible(parent) || parent.closest('[data-original], [data-count="exempt"]')) continue;
      // A lone digit is a name (a numbered mark), not a quantity to read.
      if (/^\s*\d\s*$/.test(node.textContent || '')) continue;
      quantities.push(node.textContent || '');
    }
  }
  const numbers = framed
    ? (quantities.join(' ').match(/(?<![A-Za-z0-9/.\-])\d[\d,.]*(?![A-Za-z0-9/\-])/g) || []).length
    : (text.match(/\d[\d,.]*/g) || []).length;
  const boxes = inRoots('*').filter((element) => {
    if (!visible(element) || element.matches(pressSelector)) return false;
    const style = getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    const filled = style.backgroundColor !== 'rgba(0, 0, 0, 0)' && style.backgroundColor !== 'transparent';
    const bordered = parseFloat(style.borderTopWidth) > 0 && style.borderTopStyle !== 'none';
    return (filled || bordered) && rect.width > 80 && rect.height > 32 && !exempt(element);
  }).length;
  // A table or a list is one block for the gaps (plan 11: table rows 0 px apart must not sink p10).
  const blockSelector = 'h1,h2,h3,h4,p,li,button,a[href],summary,td,th,figcaption,label';
  const blocks = [];
  for (const element of inRoots(blockSelector)) {
    if (!visible(element)) continue;
    const group = framed ? element.closest('table, ul, ol, [data-block]') : null;
    const rect = (group || element).getBoundingClientRect();
    if (!blocks.some((b) => b.top === rect.top && b.bottom === rect.bottom)) blocks.push({ top: rect.top, bottom: rect.bottom });
  }
  blocks.sort((a, b) => a.top - b.top);
  const gaps = [];
  for (let i = 1; i < blocks.length; i++) {
    const gap = blocks[i].top - blocks[i - 1].bottom;
    if (gap >= 0 && gap < 200) gaps.push(Math.round(gap));
  }
  gaps.sort((a, b) => a - b);
  const quantile = (p) => (gaps.length ? gaps[Math.min(gaps.length - 1, Math.floor(gaps.length * p))] : null);
  const sizes = new Set(
    inRoots('*')
      .filter((element) => visible(element) && [...element.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim()))
      .map((element) => getComputedStyle(element).fontSize),
  );
  const guide = (() => {
    const zone = document.querySelector('[data-zone="title"] [data-guide]');
    if (zone) return zone.innerText.trim();
    if (!h1) return null;
    let element = h1.nextElementSibling;
    for (let i = 0; element && i < 4; i++, element = element.nextElementSibling) {
      const value = (element.innerText || '').trim();
      if (value) return value.split('\n')[0];
    }
    return null;
  })();
  const mainButton = document.querySelector('[data-zone="actions"] [data-main], [data-main]');
  // RC-2 reads every visible Korean word on the page except the originals and closed dialogs.
  const clone = document.body.cloneNode(true);
  clone.querySelectorAll('[data-original], dialog:not([open]), script, style, [aria-hidden="true"]').forEach((e) => e.remove());
  document.body.appendChild(clone);
  const pageText = clone.innerText;
  clone.remove();
  return {
    framed,
    type: document.querySelector('[data-type]')?.getAttribute('data-type') ?? null,
    title: h1 ? h1.innerText.trim() : null,
    guide,
    main: mainButton ? mainButton.innerText.trim() : null,
    press: press.length,
    bands,
    pressLabels: press.map((e) => (e.innerText || e.getAttribute('aria-label') || '').trim().replace(/\s+/g, ' ').slice(0, 40)).slice(0, 20),
    boxes,
    numbers,
    chars: text.length,
    fontSizes: sizes.size,
    gapP10: quantile(0.1),
    gapP50: quantile(0.5),
    pageHeight: document.documentElement.scrollHeight,
    overflow: document.documentElement.scrollWidth > document.documentElement.clientWidth,
    pageText,
  };
}

export function judge(screen, width, m, ko, measureOnly = false, lang = 'ko') {
  const fails = [];
  if (m.overflow) fails.push('horizontal overflow');
  if (measureOnly) return fails;
  if (m.press > LIMITS.press) fails.push(`press ${m.press} > ${LIMITS.press}`);
  if (m.boxes > LIMITS.boxes) fails.push(`boxes ${m.boxes} > ${LIMITS.boxes}`);
  // A table screen (plan 5) skips the number limit; a document (the privacy notice, R7-검수 V-40) skips the number and
  // the length limits, its facts staying whole. Every other limit and the words still apply to both.
  const document = m.type === 'doc';
  if (m.type !== 'table' && !document && m.numbers > LIMITS.numbers) fails.push(`numbers ${m.numbers} > ${LIMITS.numbers}`);
  if (m.fontSizes > SIZES[width]) fails.push(`font sizes ${m.fontSizes} > ${SIZES[width]}`);
  if (width === 390) {
    if (!document && m.pageHeight > LIMITS.height390) fails.push(`height ${m.pageHeight} > ${LIMITS.height390}`);
    if (m.gapP10 !== null && m.gapP10 < LIMITS.gapP10) fails.push(`gap p10 ${m.gapP10} < ${LIMITS.gapP10}`);
    if (m.gapP50 !== null && m.gapP50 < LIMITS.gapP50) fails.push(`gap median ${m.gapP50} < ${LIMITS.gapP50}`);
  }
  // The English edition: no Korean word left on the screen (originals aside); the banned words are Korean ones.
  if (lang === 'en') {
    const korean = m.pageText.match(/[가-힣]+/g);
    if (korean) fails.push(`korean '${korean.slice(0, 3).join(' ')}'`);
  }
  for (const word of lang === 'en' ? [] : BANNED) {
    if (m.pageText.includes(word)) fails.push(`word '${word}'`);
  }
  for (const [pattern, name] of lang === 'en' ? BANNED_PATTERNS.slice(2) : BANNED_PATTERNS) {
    const found = m.pageText.match(pattern);
    if (found) fails.push(`${name} '${found[0]}'`);
  }
  if (screen.number) {
    const key = (part) => ko[`screen.${screen.number}.${part}`];
    // A {{value}} in the copy is the server's value; any text stands in for it.
    const same = (shown, copy) => copy !== undefined && shown !== null && new RegExp(
      `^${copy.split(/\{\{[^}]+\}\}/).map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.+?')}$`,
    ).test(shown);
    // A try step opened before anything was sent shows the one 'send first' state (plan 10) on every step.
    const unsent = /^\/try\/(attacker|owner)\//.test(screen.path ?? '');
    const guides = [key('guide'), ...(screen.guideAlternatives ?? []).map((k) => ko[k]), ...(unsent ? [ko['p1.unsent.guide']] : [])].filter(Boolean);
    const titles = [key('title'), ...(screen.titleAlternatives ?? []).map((k) => ko[k])].filter(Boolean);
    if (titles.length && !screen.serverTitle && !titles.some((x) => same(m.title, x))) fails.push(`title '${m.title}' != '${titles[0]}'`);
    if (guides.length && !screen.serverGuide && !guides.some((g) => same(m.guide, g))) fails.push(`guide '${m.guide}' != '${guides[0]}'`);
    // A run screen (T4) has no main button while the run goes; it moves on by itself (화면재편-기획안 T4).
    const running = screen.type === 'T4' && m.main === null;
    const unsentMain = unsent && m.main === ko['p1.unsent.go'];
    const otherMain = (screen.mainAlternatives ?? []).some((k) => same(m.main, ko[k]));
    // A "learn more" screen names its topic's next screen, or leads back to the hub at the topic's end (F3-6).
    const expected = screen.expectMain ?? key('next');
    if (expected && !running && !unsentMain && !otherMain && !same(m.main, expected)) fails.push(`main '${m.main}' != '${expected}'`);
  }
  return fails;
}

