// 일회용: 실행 중 칩("LIVE · …" + 실행 번호)을 머리글에 끼워 넣고 여러 폭에서 가로 넘침을 잽니다. 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';

const base = process.env.BASE ?? 'http://127.0.0.1:5180';
const widths = [1920, 1600, 1440, 1366, 1280, 1200, 1153, 1100, 1024, 900, 768, 600, 480, 390, 360];
const texts = {
  en: { live: 'LIVE · a real request is running', today: 'Real runs today', todayN: '283', dec: 'Decisions so far', decN: '13,682' },
  ko: { live: 'LIVE · 실제 요청 실행 중', today: '오늘 실제 실행', todayN: '283회', dec: '누적 판단', decN: '13,682건' },
};
const browser = await chromium.launch();
let failing = 0;
for (const lng of ['en', 'ko']) {
  const context = await browser.newContext({ viewport: { width: 1280, height: 720 }, locale: lng === 'en' ? 'en-US' : 'ko-KR', reducedMotion: 'reduce' });
  const page = await context.newPage();
  await page.goto(`${base}/choose?lng=${lng}`, { waitUntil: 'networkidle' });
  for (const width of widths) {
    await page.setViewportSize({ width, height: 720 });
    const m = await page.evaluate(
      ({ t }) => {
        const classOf = (part) => {
          for (const sheet of document.styleSheets) {
            let rules;
            try {
              rules = sheet.cssRules;
            } catch {
              continue;
            }
            for (const rule of rules) {
              const found = rule.selectorText?.match(new RegExp(`\\._${part}_[A-Za-z0-9]+_\\d+`));
              if (found) return found[0].slice(1);
            }
          }
          return null;
        };
        const bar = document.querySelector('header > div');
        const spacer = bar.querySelector('[class*="_spacer_"]');
        let chip = document.querySelector('[data-test-live]');
        if (!chip) {
          chip = document.createElement('span');
          chip.setAttribute('data-test-live', '');
          chip.className = classOf('live') ?? '';
          chip.setAttribute('data-live', '');
          chip.innerHTML = `<span class="${classOf('liveDot')}"></span><span class="${classOf('liveText')}">${t.live}</span><span class="${classOf('liveRun')}">live-3f6c0c2d9cba</span>`;
          bar.insertBefore(chip, spacer);
        }
        const stats = bar.querySelector('[class*="_stats_"]');
        if (stats) {
          stats.innerHTML = `${t.today} <b>${t.todayN}</b> · ${t.dec} <b>${t.decN}</b>`;
        }
        const header = document.querySelector('header');
        const over = [...header.querySelectorAll('*')].filter((e) => e.getBoundingClientRect().right > window.innerWidth + 1).slice(0, 4).map((e) => `${e.tagName}.${String(e.className).slice(0, 26)}:${Math.round(e.getBoundingClientRect().right)}`);
        return {
          over,
          scroll: document.documentElement.scrollWidth,
          inner: window.innerWidth,
          headerHeight: Math.round(header.getBoundingClientRect().height),
          stats: stats && getComputedStyle(stats).display !== 'none',
          liveRun: getComputedStyle(chip.lastElementChild).display !== 'none',
          liveRunWidth: Math.round(chip.lastElementChild.getBoundingClientRect().width),
        };
      },
      { t: texts[lng] },
    );
    const bad = m.scroll > m.inner + 1;
    if (bad) failing += 1;
    console.log(`${lng} ${String(width).padStart(4)} ${bad ? 'OVER' : 'ok  '} scroll ${m.scroll} header ${m.headerHeight}px stats ${m.stats ? 'on ' : 'off'} runId ${m.liveRun ? m.liveRunWidth + 'px' : 'hidden'}${bad ? ' ' + JSON.stringify(m.over) : ''}`);
  }
  await context.close();
}
await browser.close();
console.log(failing === 0 ? '넘침 0건' : `넘침 ${failing}건`);
process.exit(failing === 0 ? 0 : 1);
