import pathlib, re
s = pathlib.Path('s-overview.html').read_text(encoding='utf-8')
R = [
 ('<html lang="ko">', '<html lang="en">'), ('<title>보안 현황</title>', '<title>Security Overview</title>'),
 ('data-lang="ko" data-crumbs="모니터링|보안 현황"', 'data-lang="en" data-crumbs="Monitor|Security overview"'),
 ('<h1 class="ph-title">보안 현황</h1>', '<h1 class="ph-title">Security overview</h1>'),
 ('<p class="ph-desc">로그인 이후의 요청을 행위 기준선과 업무 컨텍스트로 판정하는 AI 보안 — 실시간 판정 현황과 표준 벤치마크 결과</p>',
  '<p class="ph-desc">AI security that decides post-login requests against behavioral baselines and business context — live decision activity and standard benchmark results.</p>'),
 ('<i data-icon="clipboard-check"></i>표준 벤치마크</button>', '<i data-icon="clipboard-check"></i>Standard benchmarks</button>'),
 ('<i data-icon="play"></i>위협 시뮬레이션 시작</button>', '<i data-icon="play"></i>Start a threat simulation</button>'),
 ('<span class="kpi-label">누적 판정</span><span class="kpi-value num">13,733<small>건</small></span><span class="kpi-foot"><i data-icon="calendar" style="width:14px;height:14px"></i>2026-10-05 ~ 10-31 · 실제 모델 판정</span>',
  '<span class="kpi-label">Total decisions</span><span class="kpi-value num">13,733</span><span class="kpi-foot"><i data-icon="calendar" style="width:14px;height:14px"></i>Oct 5–31, 2026 · live models</span>'),
 ('<span class="kpi-label">판정 시간 (중앙값)</span><span class="kpi-value num">6.0<small>초</small></span><span class="kpi-foot">p95 16.3초 · 판정 13,733건</span>',
  '<span class="kpi-label">Decision latency (p50)</span><span class="kpi-value num">6.0<small>s</small></span><span class="kpi-foot">p95 16.3 s · 13,733 decisions</span>'),
 ('<span class="kpi-label">오늘 방문자 실행</span><span class="kpi-value num">8<small>회</small></span><span class="kpi-foot">누적 방문자 실행 2,046회 · UTC 기준</span>',
  '<span class="kpi-label">Visitor runs today</span><span class="kpi-value num">8</span><span class="kpi-foot">2,046 visitor runs in total · UTC</span>'),
 ('<span class="kpi-label">AgentDojo 표적 공격 성공률</span><span class="kpi-value num">1.36<small>%</small></span><span class="kpi-foot">보호 없음 10.54% · 95% 구간 0.62~2.56%</span>',
  '<span class="kpi-label">AgentDojo targeted ASR</span><span class="kpi-value num">1.36<small>%</small></span><span class="kpi-foot">Unprotected 10.54% · CI 0.62–2.56%</span>'),
 ('<h2 class="card-title">판정 분포</h2><p class="card-sub">Contexa가 내린 판정 13,733건</p>', '<h2 class="card-title">Decision mix</h2><p class="card-sub">13,733 decisions issued by Contexa</p>'),
 ('<i data-icon="ban"></i>차단</span>', '<i data-icon="ban"></i>Block</span>'), ('<i data-icon="check"></i>허용</span>', '<i data-icon="check"></i>Allow</span>'),
 ('<i data-icon="key-round"></i>추가 인증</span>', '<i data-icon="key-round"></i>Step-up</span>'),
 ('</i>허용</span>', '</i>Allow</span>'), ('</i>추가 인증</span><span class="v">', '</i>Step-up authentication</span><span class="v">'),
 ('</i>검토 보류</span>', '</i>Hold for review</span>'), ('</i>차단</span><span class="v">', '</i>Block</span><span class="v">'),
 ('<span>판정 수에 넣지 않은 요청 — 기술적 실패 572건 · 직전 판정 재사용 6,844건</span>', '<span>Not counted as decisions — 572 technical failures · 6,844 reused prior decisions</span>'),
 ('<h2 class="card-title">표준 벤치마크</h2><p class="card-sub">공식 하니스 · 공식 채점 그대로, Contexa 보호 없음 대 적용</p>', '<h2 class="card-title">Standard benchmarks</h2><p class="card-sub">Official harnesses and official scoring, unchanged · unprotected vs. Contexa</p>'),
 ('>전체 결과<i data-icon="arrow-right"></i></a>', '>All results<i data-icon="arrow-right"></i></a>'),
 ('<span class="badge b-allow">완료</span>', '<span class="badge b-allow">Complete</span>'),
 ('Targeted ASR · 표적 공격 성공률(낮을수록 좋음) · 664건', 'Targeted ASR · lower is better · 664 cases'),
 ('ASR-valid (Direct Harm) · 공격 성공률(낮을수록 좋음) · base 1,054건', 'ASR-valid (Direct Harm) · lower is better · base, 1,054 cases'),
 ('Pass rate · 공격을 견딘 비율(높을수록 좋음) · 195건', 'Pass rate · higher is better · 195 cases'),
 ('<h2 class="card-title">최근 판정</h2><p class="card-sub">방문자가 실행한 시뮬레이션 · 2026-10-31 UTC</p>', '<h2 class="card-title">Recent decisions</h2><p class="card-sub">Visitor-run simulations · Oct 31, 2026 UTC</p>'),
 ('>판정 이력<i data-icon="arrow-right"></i></a>', '>Decision log<i data-icon="arrow-right"></i></a>'),
 ('<thead><tr><th>시각</th><th>시나리오</th><th>판정</th><th class="r">판정 시간</th><th>실행 ID</th></tr></thead>', '<thead><tr><th>Time</th><th>Scenario</th><th>Decision</th><th class="r">Latency</th><th>Run ID</th></tr></thead>'),
 ('정책 시뮬레이터 · 조건 변경', 'Policy simulator · custom conditions'), ('내부자 위협 · 영업 기밀 반출', 'Insider threat · trade-secret exfiltration'),
 ('계정 탈취 · 대량 반출', 'Account takeover · bulk export'), ('정상 사용자 · 같은 요청', 'Legitimate user · same request'),
 ('<td style="white-space:nowrap"><span class="badge b-block"><i data-icon="ban"></i>Block</span> <span class="muted" style="font-size:13px">2번째 요청</span></td>', '<td><span class="badge b-block"><i data-icon="ban"></i>Block</span><span class="muted" style="font-size:13px;display:block;margin-top:4px">at request 2</span></td>'),
 ('초</td>', ' s</td>'),
 ('<h2 class="card-title">위협 시뮬레이션</h2><p class="card-sub">실제 AI 판정으로 직접 실행합니다</p>', '<h2 class="card-title">Threat simulations</h2><p class="card-sub">Run them yourself against the live AI decision engine</p>'),
 ('<div class="sim-t">계정 탈취 (ATO)</div><div class="sim-d">탈취 계정의 대량 반출 · 정상 사용자 대조</div>', '<div class="sim-t">Account takeover (ATO)</div><div class="sim-d">Bulk export from a hijacked account</div>'),
 ('<div class="sim-t">내부자 위협</div><div class="sim-d">권한 안의 업무 외 목적 반출</div>', '<div class="sim-t">Insider threat</div><div class="sim-d">Exfiltration within granted permissions</div>'),
 ('<div class="sim-t">AI 에이전트 위임 남용</div><div class="sim-d">위임 범위 · 기간을 벗어난 에이전트 요청</div>', '<div class="sim-t">AI agent delegation abuse</div><div class="sim-d">Out-of-scope or expired delegations</div>'),
 ('<div class="sim-t">요청 급증 대응</div><div class="sim-d">같은 요청 60건 동시 유입 시 판정 통합</div>', '<div class="sim-t">Request surge handling</div><div class="sim-d">60 identical concurrent requests</div>'),
]
for a, b in R:
    assert a in s, a
    s = s.replace(a, b)
print('korean left:', re.findall(r'[가-힣]+', s)[:20])
pathlib.Path('s-overview-en.html').write_text(s, encoding='utf-8')
