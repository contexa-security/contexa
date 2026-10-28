// 일회용: 내부자 실행 화면(5-2)에서 판단이 끝난 뒤 키보드 초점이 본문(body)으로 떨어지는 원인을, 키보드로 보낸 흐름에서 초점·노드 제거를 기록해 찾습니다.
import { chromium } from '@playwright/test';

const base = process.env.BASE ?? 'http://127.0.0.1:5180';
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ko-KR', reducedMotion: 'reduce' });
const page = await context.newPage();
await page.addInitScript(() => {
  window.__log = [];
  const started = Date.now();
  const describe = (el) =>
    el
      ? `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}${typeof el.className === 'string' && el.className ? '.' + el.className.split(' ')[0] : ''}`
      : 'null';
  document.addEventListener(
    'focusout',
    (e) => window.__log.push({ at: Date.now() - started, kind: 'focusout', target: describe(e.target), to: describe(e.relatedTarget), url: location.pathname }),
    true,
  );
  new MutationObserver((records) => {
    for (const record of records) {
      for (const node of record.removedNodes) {
        if (node.nodeType === 1 && document.activeElement && (node.contains(document.activeElement) || node === document.activeElement)) {
          window.__log.push({ at: Date.now() - started, kind: 'active-removed', node: describe(node), parent: describe(record.target), url: location.pathname });
        }
        if (node.nodeType === 1 && (node.tagName === 'H1' || node.querySelector?.('h1'))) {
          window.__log.push({ at: Date.now() - started, kind: 'h1-removed', node: describe(node), parent: describe(record.target), url: location.pathname });
        }
      }
    }
  }).observe(document, { childList: true, subtree: true });
});

await page.goto(`${base}/insider/request?lng=ko`, { waitUntil: 'networkidle' });
// 키보드만: 첫 보기를 Space로 고르고 Tab으로 보내기 단추까지 가서 Enter
await page.locator('main h1').focus();
for (let i = 0; i < 30; i += 1) {
  await page.keyboard.press('Tab');
  const kind = await page.evaluate(() => document.activeElement?.getAttribute('type') ?? '');
  if (kind === 'radio') {
    break;
  }
}
await page.keyboard.press('Space');
for (let i = 0; i < 30; i += 1) {
  await page.keyboard.press('Tab');
  const main = await page.evaluate(() => document.activeElement?.hasAttribute('data-main') ?? false);
  if (main) {
    break;
  }
}
await page.keyboard.press('Enter');
await page.waitForURL(/console/, { timeout: 30000 });
const startedAt = Date.now();
let last = '';
const deadline = Date.now() + 300000;
while (Date.now() < deadline) {
  const state = await page.evaluate(() => {
    const el = document.activeElement;
    return {
      active: !el || el === document.body ? 'body' : `${el.tagName.toLowerCase()}${el.hasAttribute('data-main') ? '[data-main]' : ''}`,
      main: document.querySelector('[data-main]')?.outerHTML.slice(0, 90) ?? 'none',
      url: location.pathname,
      ready: !!document.querySelector('a[data-main]:not([aria-disabled="true"])'),
    };
  });
  const line = `${state.url} 초점=${state.active}`;
  if (line !== last) {
    console.log(`${String(Date.now() - startedAt).padStart(6)}ms ${line} | ${state.main}`);
    last = line;
  }
  if (state.ready) {
    await page.waitForTimeout(1500);
    const after = await page.evaluate(() => (document.activeElement === document.body ? 'body' : document.activeElement?.tagName.toLowerCase()));
    console.log(`${String(Date.now() - startedAt).padStart(6)}ms 준비 완료 1.5초 뒤 초점=${after}`);
    break;
  }
  await page.waitForTimeout(250);
}
console.log(JSON.stringify(await page.evaluate(() => window.__log), null, 1));
await browser.close();
