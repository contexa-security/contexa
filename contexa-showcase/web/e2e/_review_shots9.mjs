// 일회용: 영어 휴대폰의 3-1·5-3 높이와 한 글자 줄을 확인합니다. 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';
const browser = await chromium.launch();
const page = await (await browser.newContext({ viewport: { width: 390, height: 844 }, locale: 'en-US', reducedMotion: 'reduce' })).newPage();
for (const [path, name] of [['/evidence/map', '3-1'], ['/insider/reason', '5-3']]) {
  await page.goto(`http://127.0.0.1:5180${path}?lng=en`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(1200);
  console.log(name, await page.evaluate(() => document.documentElement.scrollHeight));
  await page.screenshot({ path: `C:/Users/leaven/AppData/Local/Temp/claude/e--/315dfa71-b245-48d6-8b02-705f97cd4916/scratchpad/en_${name}.png`, fullPage: true });
}
await browser.close();
