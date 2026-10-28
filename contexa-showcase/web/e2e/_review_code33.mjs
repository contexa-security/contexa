// 일회용: 3-3의 AI 원문 JSON 상자(pre)가 줄 나뉨에서 한 글자만 홀로 남기는지 줄 단위로 봅니다. 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';

const base = process.env.BASE ?? 'http://127.0.0.1:19180';
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: Number(process.env.W ?? 1440), height: 900 }, locale: 'ko-KR', reducedMotion: 'reduce' });
const page = await context.newPage();
await page.goto(`${base}/evidence/verdict?lng=ko`, { waitUntil: 'networkidle' });
await page.waitForTimeout(800);
const out = await page.evaluate(() => {
  const pre = document.querySelector('pre[class*="_answer_"]');
  const node = pre.firstChild;
  const text = node.textContent;
  const NL = String.fromCharCode(10);
  const lines = [];
  let top = null;
  let buf = '';
  for (let i = 0; i < text.length; i += 1) {
    if (text[i] === NL) {
      lines.push(buf);
      buf = '';
      top = null;
      continue;
    }
    const range = document.createRange();
    range.setStart(node, i);
    range.setEnd(node, i + 1);
    const r = range.getClientRects()[0];
    if (r) {
      const t = Math.round(r.top);
      if (top === null) top = t;
      if (t !== top) {
        lines.push(buf);
        buf = '';
        top = t;
      }
    }
    buf += text[i];
  }
  lines.push(buf);
  const css = getComputedStyle(pre);
  const punctuation = /^[\]\[{},":]+$/;
  return {
    width: Math.round(pre.getBoundingClientRect().width),
    ws: css.whiteSpace,
    ow: css.overflowWrap,
    wb: css.wordBreak,
    fs: css.fontSize,
    lineCount: lines.length,
    shortLines: lines.map((l, k) => [k, l]).filter(([, l]) => l.trim().length > 0 && l.trim().length <= 2 && !punctuation.test(l.trim())).slice(0, 12),
    codeLines: lines.filter((l) => /PAST|RECORD|SAME|TARGET/.test(l)),
  };
});
console.log(JSON.stringify(out, null, 1));
await browser.close();
