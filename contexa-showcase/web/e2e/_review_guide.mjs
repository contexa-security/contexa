// 일회용: 새 영상 링크와 영상 창(자막 띠)을 실제 브라우저로 잽니다. 목록은 가로채서(기존 console.webm을 request로) 넣습니다.
// 삭제 대상 보조 파일. 사용: node e2e/_review_guide.mjs <출력 폴더> [화면 경로] [언어]
import { chromium } from '@playwright/test';
import fs from 'node:fs';

const out = process.argv[2];
const path = process.argv[3] ?? 'attack/request';
const lng = process.argv[4] ?? 'ko';
const base = process.env.BASE ?? 'http://127.0.0.1:5180';
const id = process.env.GUIDE_ID ?? 'request';
fs.mkdirSync(out, { recursive: true });

const manifest = JSON.parse(fs.readFileSync(new URL('../public/guides/guides.json', import.meta.url), 'utf8')).console;
const fake = {
  [id]: {
    ...manifest,
    captionsNarrow: manifest.captions,
  },
};

const browser = await chromium.launch();
for (const [name, width, height] of [['d', 1440, 900], ['m', 390, 844]]) {
  const context = await browser.newContext({ viewport: { width, height }, locale: lng === 'ko' ? 'ko-KR' : 'en-US', reducedMotion: 'reduce' });
  const page = await context.newPage();
  await page.route('**/guides/guides.json', (route) => route.fulfill({ contentType: 'application/json', body: JSON.stringify(fake) }));
  await page.goto(`${base}/${path}?lng=${lng}`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(600);
  const link = page.locator('[data-guide-link]').first();
  const box = await link.boundingBox();
  const info = await link.evaluate((el) => {
    const style = getComputedStyle(el);
    const title = document.querySelector('main h1');
    const tb = title ? title.getBoundingClientRect() : null;
    const lb = el.getBoundingClientRect();
    return {
      text: el.textContent,
      fontSize: style.fontSize,
      weight: style.fontWeight,
      height: Math.round(lb.height),
      left: Math.round(lb.left),
      top: Math.round(lb.top),
      right: Math.round(lb.right),
      bottom: Math.round(lb.bottom),
      titleRight: tb ? Math.round(tb.right) : null,
      titleTop: tb ? Math.round(tb.top) : null,
      inFirstView: lb.bottom <= window.innerHeight,
      pageHeight: document.documentElement.scrollHeight,
      scrollWidth: document.documentElement.scrollWidth,
    };
  });
  console.log(name, 'link', JSON.stringify(info));
  await page.screenshot({ path: `${out}/${name}-link.png` });
  await link.click();
  await page.waitForTimeout(500);
  const dialog = page.getByRole('dialog');
  const video = dialog.locator('video');
  await video.evaluate((el) => {
    el.muted = true;
  });
  // 장면 막대와 자막 띠: 20초(Contexa 판단 중 장면)로 가서 재생하며 자막이 뜰 때까지 기다린다
  await video.evaluate(async (el) => {
    el.currentTime = 36;
    await el.play().catch(() => undefined);
  });
  await page.waitForTimeout(2500);
  const band = await dialog.locator('[data-caption-band]').evaluate((el) => {
    const style = getComputedStyle(el);
    const b = el.getBoundingClientRect();
    const v = el.parentElement.querySelector('video').getBoundingClientRect();
    return {
      text: el.textContent,
      fontSize: style.fontSize,
      weight: style.fontWeight,
      color: style.color,
      background: style.backgroundColor,
      bandTop: Math.round(b.top),
      bandHeight: Math.round(b.height),
      videoBottom: Math.round(v.bottom),
      videoWidth: Math.round(v.width),
      textWidth: Math.round(el.scrollWidth),
      bandWidth: Math.round(el.clientWidth),
      oneLine: el.scrollWidth <= el.clientWidth + 1,
    };
  });
  console.log(name, 'band', JSON.stringify(band));
  await page.screenshot({ path: `${out}/${name}-window.png` });
  await context.close();
}
await browser.close();
