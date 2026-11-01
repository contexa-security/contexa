// Renders the shared app shell (left navigation + top bar) of the UX-R1 mockups and swaps icon placeholders for Lucide SVGs.
// <body data-active="ato" data-lang="ko" data-crumbs="위협 시뮬레이션|계정 탈취 · 내부자 위협"> ... <main class="content">…</main>
(function () {
  const ICON = {
    home: 'play', overview: 'layout-dashboard', log: 'list-checks', metrics: 'activity', ato: 'user-round-x', agent: 'bot', burst: 'layers',
    policy: 'sliders-horizontal', engine: 'cpu', compare: 'git-compare-arrows', bench: 'clipboard-check', scenario: 'target',
    deploy: 'plug-zap', tour: 'circle-play', glossary: 'book-open-text', privacy: 'shield-check',
  };
  // Menu order follows the visitor: start the demo, run a threat simulation, read the results, check validation, adopt.
  const MENU = {
    ko: [
      ['라이브 데모', [['home', '데모 시작']]],
      ['위협 시뮬레이션', [['ato', '계정 탈취 · 내부자 위협'], ['agent', 'AI 에이전트 위임 남용'], ['burst', '요청 급증 대응'], ['policy', '정책 시뮬레이터']]],
      ['결과 분석', [['log', '판정 이력', '2,046'], ['engine', 'AI 판정 엔진'], ['compare', '탐지 방식 비교']]],
      ['검증', [['bench', '표준 벤치마크'], ['scenario', '시나리오 검증']]],
      ['도입 · 운영', [['deploy', '도입 · 연동 가이드'], ['metrics', '운영 지표'], ['tour', '제품 투어']]],
    ],
    en: [
      ['LIVE DEMO', [['home', 'Start the demo']]],
      ['THREAT SIMULATION', [['ato', 'ATO & insider threat'], ['agent', 'AI agent delegation abuse'], ['burst', 'Request surge handling'], ['policy', 'Policy simulator']]],
      ['RESULTS & ANALYSIS', [['log', 'Decision log', '2,046'], ['engine', 'AI decision engine'], ['compare', 'Detection comparison']]],
      ['VALIDATION', [['bench', 'Standard benchmarks'], ['scenario', 'Scenario validation']]],
      ['ADOPTION & OPERATIONS', [['deploy', 'Deployment & integration'], ['metrics', 'Operational metrics'], ['tour', 'Product tour']]],
    ],
  };
  const FOOT = { ko: [['glossary', '보안 용어집'], ['privacy', '개인정보 처리방침']], en: [['glossary', 'Security glossary'], ['privacy', 'Privacy']] };
  const TOP = {
    ko: { search: '메뉴 · 실행 ID · 용어 검색', live: '실시간 판정 가동', today: '오늘 방문자 실행', total: '누적 판정' },
    en: { search: 'Search runs, menus, terms', live: 'Live decisions on', today: 'Visitor runs today', total: 'Decisions' },
  };
  if (window.innerWidth <= 480) document.documentElement.classList.add('phone');
  if (/theme=light/.test(location.search)) document.documentElement.setAttribute('data-theme', 'light');
  const b = document.body;
  const lang = b.dataset.lang || 'ko';
  const active = b.dataset.active;
  const crumbs = (b.dataset.crumbs || '').split('|').filter(Boolean);
  const icon = (name, cls = 'i') => `<i data-lucide="${name}" class="${cls}"></i>`;
  const side = `
    <aside class="side">
      <div class="brand"><span class="brand-mark">C</span><span class="brand-name">Contexa</span><span class="brand-tag">${lang === 'ko' ? '라이브 데모' : 'Live demo'}</span></div>
      <nav class="nav">${MENU[lang].map(([group, items]) => `
        <div class="nav-group">${group}</div>
        ${items.map(([id, label, count]) => `<a class="nav-item" title="${label}" ${id === active ? 'aria-current="page"' : ''}>${icon(ICON[id])}<span>${label}</span>${count ? `<span class="nav-count">${count}</span>` : ''}</a>`).join('')}`).join('')}
      </nav>
      <div class="nav-foot">${FOOT[lang].map(([id, label]) => `<a class="nav-item">${icon(ICON[id])}<span>${label}</span></a>`).join('')}</div>
    </aside>`;
  const t = TOP[lang];
  const top = `
    <header class="top">
      <button class="icon-btn mobile-only">${icon('menu')}</button>
      <span class="mobile-only brand-mark">C</span>
      <div class="crumbs hide-phone">${crumbs.map((c, i) => (i ? icon('chevron-right') : '') + (i === crumbs.length - 1 ? `<b>${c}</b>` : `<span>${c}</span>`)).join('')}</div>
      <div class="top-right">
        <div class="search">${icon('search')}<span>${t.search}</span><kbd>Ctrl K</kbd></div>
        <span class="pill hide-phone"><span class="dot"></span>${t.live}</span>
        <span class="pill hide-phone">${t.today} <b>8</b><span class="muted">·</span>${t.total} <b>13,733</b></span>
        <button class="icon-btn" style="width:auto;padding:0 10px;font-size:13px;font-weight:600;gap:4px;display:flex;align-items:center">${icon('globe')}${lang === 'ko' ? 'KO' : 'EN'}</button>
        <button class="icon-btn hide-phone">${icon('moon')}</button>
      </div>
    </header>`;
  if (b.dataset.focus === '1') document.documentElement.classList.add('focus');
  const main = document.querySelector('main');
  const app = document.createElement('div');
  app.className = 'app';
  app.innerHTML = side + top;
  main.parentNode.insertBefore(app, main);
  app.appendChild(main);
  document.querySelectorAll('[data-icon]').forEach((el) => { el.outerHTML = icon(el.dataset.icon, el.className || 'i'); });
  const done = () => { if (window.lucide) window.lucide.createIcons({ attrs: { 'stroke-width': 1.75 } }); document.documentElement.dataset.ready = '1'; };
  const s = document.createElement('script');
  s.src = 'https://unpkg.com/lucide@0.460.0/dist/umd/lucide.min.js';
  s.onload = done; s.onerror = done;
  document.head.appendChild(s);
})();
