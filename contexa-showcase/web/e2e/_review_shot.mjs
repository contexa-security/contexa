// 일회용: 영상 링크가 있는 상태(가짜 목록)로 한 화면의 전체 사진과 높이를 뽑습니다. 삭제 대상 보조 파일.
// 사용: node e2e/_review_shot.mjs <출력 폴더> <화면 경로(맨 앞 / 없이)> [언어] [폭]
import { chromium } from '@playwright/test';
import fs from 'node:fs';

const out = process.argv[2];
const path = process.argv[3];
const lng = process.argv[4] ?? 'ko';
const width = Number(process.argv[5] ?? 390);
const base = process.env.BASE ?? 'http://127.0.0.1:5180';
fs.mkdirSync(out, { recursive: true });
const recorded = JSON.parse(fs.readFileSync(new URL('../public/guides/guides.json', import.meta.url), 'utf8')).console;
const list = JSON.parse(fs.readFileSync(new URL('../src/components/guide/guides.json', import.meta.url), 'utf8'));
const body = JSON.stringify(Object.fromEntries(Object.entries(list).filter(([, entry]) => entry.kind !== 'legacy').map(([id]) => [id, { ...recorded, captionsNarrow: recorded.captions }])));
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width, height: width <= 390 ? 844 : 900 }, locale: lng === 'ko' ? 'ko-KR' : 'en-US', reducedMotion: 'reduce' });
const page = await context.newPage();
await page.route('**/guides/guides.json', (request) => request.fulfill({ contentType: 'application/json', body }));
await page.goto(`${base}/${path}?lng=${lng}`, { waitUntil: 'networkidle' });
await page.waitForTimeout(1200);
const height = await page.evaluate(() => document.documentElement.scrollHeight);
console.log(path, width, 'height', height);
await page.screenshot({ path: `${out}/${path.replace(/\//g, '_')}-${width}.png`, fullPage: true });
await browser.close();
