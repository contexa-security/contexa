# Contexa AI Zero Trust Platform - 벤치마킹 검증 설계서

## 1. 목적

동일 계정(developer@example.com)에 대해 정상 소유자와 비정상 침입자를 Contexa 플랫폼이 구별할 수 있는지를 증명한다.

### 핵심 명제 (2가지)

1. **컨텍스트 품질**: LLM에게 전달되는 보안 컨텍스트와 프롬프트가 오염되지 않고, 전문적이고 투명한 고품질 정보인가?
2. **판단 정확성**: 그 고품질 컨텍스트를 받은 LLM이 정상인과 비정상인을 정확하게 구별하는가?

이 두 가지가 보장되면 Contexa의 AI Zero Trust 기술 품질은 검증된 것이다.

### 지표 구조

**핵심 지표 14개** (AI 기술 품질 -- 본 벤치마크의 합격/불합격을 결정)

| 축 | 지표 | 질문 |
|----|------|------|
| 컨텍스트 품질 (7개) | CCR, CCSR, PFR, CoR, RAP, RPI, BMA | LLM이 정확한 판단을 내리기 위한 입력이 완전하고 일관되며 오염되지 않았는가? |
| 판단 정확성 (7개) | USNS, BSR, CDC, ERA, SUHR, AAR, DSR | LLM이 정상인과 비정상인을 실제로 구별하며, 그 판단이 정확하고 안정적인가? |

**운영 개선 지표 7개** (시스템 엔지니어링 -- 운영하면서 점진적으로 개선)

| 지표 | 영역 |
|------|------|
| EIR, MTR | 로깅/추적 인프라 |
| BDT, FPR | 기준선 튜닝/오탐 관리 |
| DCR, PRC, ERI | 집행 지연/정책 리로드/MFA 흐름 |

운영 개선 지표는 AI 고유 기술이 아니라 모든 보안 시스템이 공통으로 겪는 엔지니어링 과제이다. 본 벤치마크에서 측정은 하되, 합격/불합격 판정의 핵심 기준에는 포함하지 않는다.

---

## 2. 지표 체계

### 축 1: 컨텍스트 품질 지표 (7개)

> LLM에게 전달되는 입력의 품질을 보장한다

| ID | 지표명 | 정의 |
|----|--------|------|
| CCR | Context Completeness Rate | 필수 컨텍스트 속성이 누락 없이 채워진 비율 |
| CCSR | Context Consistency Rate | 같은 사실이 AuditLog, HCAD Signal, LLM Prompt 3곳에서 동일하게 유지되는 비율 |
| PFR | Prompt Fidelity Rate | 템플릿 계약과 실제 프롬프트 산출물이 1:1 대응하는 비율 |
| CoR | Context Contamination Rate | 다른 사용자/테넌트/목적 문서가 섞이는 비율 |
| RAP | RAG Authorization Precision | 회수된 relatedDocuments 중 현재 사용자/역할에 허용된 문서 비율 |
| RPI | Round Progression Integrity | Phase 1->2->3에서 memory/baseline/RAG가 역행 없이 누적되는 비율 |
| BMA | Baseline Maturity Accuracy | 기준선 성숙도(NONE/PROVISIONAL/ESTABLISHED)가 실제 관측량과 맞는 비율 |

### 축 2: 판단 정확성 지표 (7개)

> LLM이 비정상인을 정확하게 잡아내는지 증명한다

| ID | 지표명 | 정의 |
|----|--------|------|
| USNS | User-Specific Novelty Sensitivity | 동일 계정에서 해당 사용자 기준의 돌발행동을 포착하는 민감도 |
| BSR | Behavioral Surprise Resolution | sequence, resource adjacency, friction deviation, scope jump 4차원의 미세 행동 차이를 반영하는 비율 |
| CDC | Context-to-Decision Calibration | 컨텍스트 riskScore와 최종 confidence/decision이 과장 없이 맞물리는 정도 |
| ERA | Evidence-Reason Alignment | reasoning 문장이 실제 evidence와 일치하는 정합도 |
| SUHR | Safe-Uncertainty Handling Rate | 애매한 상황에서 과잉 허용 대신 보수적 결정을 유지하는 비율 |
| AAR | Adaptive Attack Resistance | 정상 패턴을 모방하는 저속 공격(Slow & Low)을 감지하는 비율 |
| DSR | Decision Stability Rate | 동일 입력에 대해 LLM 판정이 반복 실행 시 일관되는 비율 |

### 운영 개선 지표 (7개, 참고 측정)

| ID | 지표명 | 정의 |
|----|--------|------|
| EIR | Event Integrity Rate | 이벤트 원본 필드가 기대값과 일치하는 비율 |
| MTR | Metadata Traceability Rate | requestId -> eventId -> promptHash -> promptVersion 체인이 끊김 없이 연결되는 비율 |
| BDT | Baseline Drift Tolerance | 정상 사용자의 업무 패턴 변경 시 오탐 없이 기준선이 적응하는 비율 |
| FPR | Normal Traffic False Positive Rate | 다수 정상 사용자 대규모 트래픽에서의 오탐률 |
| DCR | Damage Containment Rate | BLOCK 판정 후 피해가 억제되는 속도와 범위 |
| PRC | Policy Reload Consistency | 정책 핫 리로드 전후 판정이 정책 변경 의도와 일치하는 비율 |
| ERI | Escalation Round-Trip Integrity | CHALLENGE -> MFA -> 결과 반영까지 정확히 완료되는 비율 |

**비동기 설계 원칙**: Contexa는 비동기 아키텍처를 채택한다. LLM 분석은 수초가 소요되며, 동기적 차단은 UX 저항이 과도하여 현실적이지 않다. "피해 제로"가 아닌 "피해 최소화"가 목표이며, 벌크 데이터 유출 시 스트리밍 응답을 도중에 중단하여 피해 확대를 방지한다.

---

## 3. 테스트 페르소나 정의

### 3.1 기본 페르소나 (A~C군)

| 구분 | 정상 소유자 (Alice) | 어설픈 침입자 (Mallory) |
|------|-------------------|----------------------|
| 계정 | developer@example.com (동일) | developer@example.com (동일) |
| IP 대역 | 한국 KT (121.160.x.x) | 러시아/VPN (185.203.x.x) |
| 접속 시간 | 평일 09:00~18:00 | 새벽 02:00~04:00 |
| User-Agent | Chrome 130 / Windows 11 | Firefox 115 / Linux |
| 접근 리소스 | /api/users, /api/projects (본인 업무) | /admin/api/policies, /admin/api/security-test/critical (권한 탐색) |
| 요청 간격 | 30초~5분 (인간 패턴) | 2~5초 (자동화 패턴) |
| 행동 순서 | 로그인 -> 대시보드 -> 업무 API -> 로그아웃 | 로그인 -> 즉시 관리자 API -> 민감 데이터 -> 정책 조회 |
| 세션 패턴 | 하루 1~2세션, 각 30분~2시간 | 새벽 짧은 세션 반복 |

### 3.2 적응형 공격자 (D1용)

| 구분 | 교묘한 침입자 (Eve) |
|------|-------------------|
| 계정 | developer@example.com (동일) |
| IP 대역 | 한국 KT VPN (121.161.x.x, Alice와 유사 대역) |
| 접속 시간 | 평일 10:00~17:00 (Alice 업무시간 내) |
| User-Agent | Chrome 130 / Windows 11 (Alice와 동일) |
| 접근 리소스 | /api/users (정상) -> 하루 1건씩 /admin/api/policies 추가 |
| 요청 간격 | 60초~3분 (Alice 패턴 모방) |
| 공격 전략 | 2주에 걸쳐 서서히 권한 범위 확장, 하루 1~2건만 이상 요청 |

### 3.3 패턴 변경 정상 사용자 (D3용)

| 구분 | 부서이동 Alice |
|------|--------------|
| 변경 전 | IP: 121.160.x.x, 시간: 09~18, 리소스: /api/users, /api/projects |
| 변경 후 | IP: 121.160.x.x (동일), 시간: 13~22 (야간 교대), 리소스: /api/finance, /api/reports |

### 3.4 정상 사용자 집단 (D4용)

| 사용자 | 역할 | 업무 패턴 |
|--------|------|----------|
| admin@example.com | ROLE_ADMIN | /admin/* 관리 작업, 09~18시 |
| manager@example.com | ROLE_DEVELOPER | /api/users, /api/projects, 08~19시 |
| developer@example.com | ROLE_DEVELOPER | /api/users, /api/projects, 09~18시 |
| user@example.com | ROLE_USER | /api/users (본인), 09~17시 |
| finance@example.com | ROLE_FINANCE | /api/finance, /api/reports, 09~18시 |

---

## 4. 실행 계획

### 4.1 전체 구조 (8 Phase, 총 1,420건)

```
Phase 1: 기준선 구축            Alice 50건      (A군 + B3 측정)
Phase 2: 정상 대조군            Alice 10건      (C군 정상 기준값)
Phase 3: 어설픈 침입자          Mallory 20건    (B4, C군 측정)
Phase 4: 적응형 공격            Eve 200건       (D1 측정)
Phase 5: 판정 재현성            반복 30건       (D2 측정)
Phase 6: 기준선 드리프트        Alice 변경 60건  (D3 측정)
Phase 7: 대규모 정상 트래픽     5명 x 200건     (D4 측정)
Phase 8: 적시 집행 및 흐름      50건            (E1, E2, E3 측정)
```

### 4.2 Phase 1: 기준선 구축 (Alice, 50건, 5일 시뮬레이션)

**목적**: HCAD 기준선을 ESTABLISHED 수준까지 성숙시킨다.

```
Day 1 (10건):
  #1  GET  /admin/dashboard          09:30  121.160.1.1  Chrome/Win
  #2  GET  /api/users                09:45  121.160.1.1  Chrome/Win
  #3  GET  /api/users?page=2         10:10  121.160.1.1  Chrome/Win
  #4  GET  /api/users/5              10:35  121.160.1.1  Chrome/Win
  #5  GET  /api/projects             11:00  121.160.1.1  Chrome/Win
  #6  GET  /api/projects/3           11:40  121.160.1.1  Chrome/Win
  #7  GET  /api/projects/3/members   13:15  121.160.1.1  Chrome/Win
  #8  GET  /api/users                14:00  121.160.1.1  Chrome/Win
  #9  GET  /admin/dashboard          16:30  121.160.1.1  Chrome/Win
  #10 POST /logout                   17:45  121.160.1.1  Chrome/Win

Day 2 (10건): 유사 패턴, IP 소폭 변동 (121.160.1.2)
Day 3 (10건): 유사 패턴, 점심시간 공백 포함 (12:00~13:00 요청 없음)
Day 4 (10건): 유사 패턴, 16시 이후 집중 접근 (자연스러운 변동)
Day 5 (10건): Day 1~4 혼합 패턴
```

**각 요청의 컨텍스트 구성**:
- IP: 121.160.1.x (x = 1~5 소폭 변동, NAT 환경 시뮬레이션)
- 시간: Clock Mock으로 09:00~18:00 사이 분배 (java.time.Clock 주입)
- User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0`
- 요청 간격: 랜덤 30초~300초
- GeoIP Mock: 한국, 서울, KT

**50건으로 충분한 근거**:
- `hcad.baseline.bootstrap.initialSamples = 10` -> 10건 후 bootstrap 탈출
- `hcad.baseline.statistical.minSamples = 20` -> 20건 후 통계 분석 가능
- EMA(alpha=0.1) 수렴: 잔차 < 5%에 도달하려면 약 40건 필요 (수학적: (1-0.1)^n < 0.05 -> n >= 29)
- 시간대 패턴 학습을 위해 5일 분산 필요

**Phase 1 완료 시 측정**:
- A1(EIR): 50건 AuditLog 필드 대조
- A2(CCR): 50건 x 12필수필드 존재 확인
- A5(MTR): 50건 추적 체인 연결 확인
- B3(BMA): 요청 #10에서 PROVISIONAL, #20에서 ESTABLISHED 전이 확인

### 4.3 Phase 2: 정상 대조군 (Alice, 10건, Day 6)

**목적**: 기준선 구축 후 정상 행동의 riskScore/anomalyScore 기준값 수집.

```
Day 6 (10건): Day 1과 동일한 패턴 반복
  #51~#60  GET /admin/dashboard, /api/users, /api/projects 등
           09:30~17:30, 121.160.1.1, Chrome/Win
```

**기대 결과**:
- 10건 모두 anomalyScore < 0.3
- 10건 모두 riskScore < 0.3
- 10건 모두 LLM decision = ALLOW
- 이 10건의 수치가 Phase 3과의 비교 기준

### 4.4 Phase 3: 어설픈 침입자 (Mallory, 20건, Day 6 새벽)

**목적**: 명백한 이상 행동 주입, B4 + C군 지표 측정.

```
Day 6 새벽 02:00~02:40 (20건, 간격 2~5초):
  #61  POST /login                            02:00  185.203.4.1  Firefox/Linux
  #62  GET  /admin/dashboard                  02:01  185.203.4.1  Firefox/Linux
  #63  GET  /admin/dashboard                  02:01  185.203.4.1  Firefox/Linux
  #64  GET  /admin/api/policies               02:02  185.203.4.1  Firefox/Linux
  #65  GET  /admin/api/policies               02:02  185.203.4.1  Firefox/Linux
  #66  GET  /admin/api/policies               02:03  185.203.4.1  Firefox/Linux
  #67  GET  /admin/api/policies               02:03  185.203.4.1  Firefox/Linux
  #68  GET  /admin/api/security-test/sensitive/1  02:04  185.203.4.1  Firefox/Linux
  #69  GET  /admin/api/security-test/sensitive/2  02:04  185.203.4.1  Firefox/Linux
  #70  GET  /admin/api/security-test/sensitive/3  02:05  185.203.4.1  Firefox/Linux
  #71  GET  /admin/api/security-test/critical/1   02:06  185.203.4.1  Firefox/Linux
  #72  GET  /admin/api/security-test/critical/2   02:06  185.203.4.1  Firefox/Linux
  #73  GET  /admin/api/security-test/critical/3   02:07  185.203.4.1  Firefox/Linux
  #74  GET  /admin/api/security-test/bulk          02:08  185.203.4.1  Firefox/Linux
  #75  GET  /admin/api/security-test/bulk          02:09  185.203.4.1  Firefox/Linux
  #76  GET  /admin/api/security-test/bulk          02:10  185.203.4.1  Firefox/Linux
  #77  GET  /admin/api/ai/policies/generate        02:15  185.203.4.1  Firefox/Linux
  #78  GET  /admin/api/ai/policies/generate        02:16  185.203.4.1  Firefox/Linux
  #79  POST /admin/api/policies/build-from-business-rule  02:20  185.203.4.1  Firefox/Linux
  #80  GET  /admin/session-management              02:25  185.203.4.1  Firefox/Linux
```

**각 요청이 자극하는 이상 차원**:

| 요청 | sequence | adjacency | friction | scope | 비고 |
|------|----------|-----------|----------|-------|------|
| #61 로그인 | - | - | - | - | 새 IP/UA 감지 |
| #62~63 대시보드 | O (로그인 직후 정찰) | - | - | - | |
| #64~67 정책 열람 | O | O (업무API -> 관리API) | O (2초 간격) | O (ADMIN 영역) | 4차원 동시 |
| #68~73 민감/핵심 | O | O | O | O | sensitivePatterns 매칭 |
| #74~76 벌크 조회 | O | - | O | O | 대량 데이터 |
| #77~78 AI 정책 | O | O (bulk -> AI) | O | O | |
| #79 정책 변조 | O | - | O | O | POST 시도 |
| #80 세션 관리 | O | O (정책 -> 세션) | - | O | 흔적 제거 시도 |

**Phase 2 + Phase 3 동시 측정 지표**:
- A3(CCSR): 80건 전체의 3지점 일관성
- A4(PFR): 80건 프롬프트 템플릿 대응
- A6(CoR): Alice 10건에서 Mallory 정보 교차 오염 검사
- B1(RAP): Mallory 요청의 RAG 회수 문서 권한 검증
- B2(RPI): Phase 1->2->3 기준선 스냅샷 역행 검사
- B4(USNS): Alice 10건 vs Mallory 20건 anomalyScore 비교 (t-test)
- C1(BSR): Mallory 20건의 4차원 이상 신호 감지 비율
- C2(CDC): 80건의 (riskScore, decision, confidence) 교정 곡선
- C3(ERA): Mallory 20건의 reasoning vs evidence 정합도
- C4(SUHR): confidence < 0.6인 건들의 보수적 판정 비율

### 4.5 Phase 4: 적응형 공격 (Eve, 200건, 14일 시뮬레이션)

**목적**: 정상 패턴을 모방하는 저속 공격(Slow & Low)을 감지하는지 검증.

Alice와 동일한 IP 대역, 동일한 시간대, 동일한 User-Agent를 사용하되 접근 리소스의 범위를 서서히 넓힌다.

```
Week 1 (70건, 하루 10건):
  Day 7~11: Alice 패턴 100% 모방
    /api/users, /api/projects 만 접근
    IP: 121.161.x.x (Alice와 유사), 시간: 09~18, Chrome/Win
    -> 이 기간은 기준선에 자연스럽게 녹아듬

Week 2 전반 (40건, 하루 10건):
  Day 12~15: 정상 80% + 이상 20% 혼합
    하루 10건 중 8건 /api/users, /api/projects
    + 2건 /admin/roles, /admin/permissions (탐색 시작)

Week 2 후반 (50건, 하루 ~17건):
  Day 16~18: 정상 60% + 이상 40% 혼합
    하루 17건 중 10건 정상
    + 4건 /admin/api/policies (정책 열람)
    + 3건 /admin/api/security-test/normal (민감도 탐색)

Week 2 마지막 (40건, 하루 20건):
  Day 19~20: 정상 50% + 이상 50%
    하루 20건 중 10건 정상
    + 5건 /admin/api/security-test/sensitive (민감 접근)
    + 3건 /admin/api/security-test/critical (핵심 접근)
    + 2건 /admin/api/ai/policies/generate (정책 변조 준비)
```

**핵심 측정**:
- D1(AAR): 200건 중 이상 요청(~80건)의 감지 비율
- **난이도별 감지율**: Day 12~15 (미세 이상) vs Day 19~20 (명확 이상)
- **기준선 오염 추적**: 매일 기준선 스냅샷 -> Eve의 이상 행동이 기준선을 과도하게 왜곡하는지
- **감지 시점**: "몇 일차에 처음 CHALLENGE/BLOCK이 발생했는가" (early detection 능력)

**200건 산정 근거**:
- 14일 x 평균 14건/일 = ~200건
- Week 1의 70건은 모방기(기준선 오염 시도), Week 2의 130건은 점진적 공격 확대
- EMA(alpha=0.1) 기준, 70건의 정상 모방 후에도 기존 50건 기준선이 60% 이상 유지됨 (수학적: 기존 가중치 = 0.9^70 = 0.06% -> 사실상 덮어씀)
- 따라서 이 테스트는 "기준선이 완전히 오염된 후에도 행동 패턴 자체의 이상을 잡는가"를 검증

### 4.6 Phase 5: 판정 재현성 (동일 입력 반복 30건)

**목적**: LLM의 비결정성에도 불구하고 판정이 일관되는지 검증.

```
입력 3종 x 10회 반복 = 30건:
  입력 A: Phase 2의 정상 요청 #51 (Alice, 정상, riskScore 낮음)
  입력 B: Phase 3의 이상 요청 #71 (Mallory, critical 접근, riskScore 높음)
  입력 C: Phase 4의 경계 요청 #Day12 이상 2건 중 1건 (Eve, 미세 이상)
```

**측정**:
- D2(DSR): 각 입력별 10회 판정의 일관성
  - 입력 A: 10회 모두 ALLOW -> DSR 100%
  - 입력 B: 10회 모두 BLOCK 또는 CHALLENGE -> DSR 100%
  - 입력 C: 판정 분포 측정 (ALLOW 3회, CHALLENGE 7회 등) -> 다수결 방향과 일치하는 비율
- LLM temperature 설정별 비교 (temperature=0 vs 0.3 vs 0.7)
- confidence 값의 표준편차 (작을수록 안정)

### 4.7 Phase 6: 기준선 드리프트 (Alice 업무 변경, 60건)

**목적**: 정상 사용자의 업무 패턴이 변경될 때 오탐 없이 기준선이 적응하는지.

```
Day 21~23 (30건, 전환 초기):
  기존 패턴 50% + 새 패턴 50% 혼합
  - 기존: /api/users, /api/projects (09~18시)
  - 신규: /api/finance, /api/reports (13~22시)
  - IP, User-Agent는 동일 (부서이동이지 침입이 아님)

Day 24~26 (30건, 전환 완료):
  새 패턴 100%
  - /api/finance, /api/reports만 접근
  - 13~22시에만 접근
  - 기존 /api/users, /api/projects 접근 없음
```

**측정**:
- D3(BDT): 60건 중 오탐(BLOCK/CHALLENGE) 건수
  - Day 21~23 (전환 초기): 일부 CHALLENGE 허용 (기준선 적응 중)
  - Day 24~26 (전환 완료): 오탐 0건이어야 함 (기준선 적응 완료)
- 기준선 수렴 속도: EMA가 새 패턴에 50% 적응하는 데 걸리는 요청 수
- 오탐률 추이 그래프: Day별 CHALLENGE/BLOCK 비율 감소 곡선

**60건 산정 근거**:
- EMA(alpha=0.1)가 새 값에 50% 가중치를 두려면: 1-(0.9^n) >= 0.5 -> n >= 7
- 6일 x 10건/일 = 60건이면 기준선이 충분히 새 패턴으로 이동
- Day 24~26의 30건은 적응 완료 후 검증 구간

### 4.8 Phase 7: 대규모 정상 트래픽 FPR (5명 x 200건 = 1,000건)

**목적**: 다수 정상 사용자의 대규모 트래픽에서 오탐률(False Positive Rate) 측정.

```
5명 사용자 각각:
  기준선 구축: 50건 (Phase 1과 동일 방식)
  검증 트래픽: 150건 (다양한 정상 패턴)

정상 패턴의 자연스러운 변동 포함:
  - 가끔 점심시간에 접근 (평소와 다른 시간)
  - 가끔 모바일 UA로 접근 (평소와 다른 디바이스)
  - 가끔 VPN IP로 접근 (재택근무 시뮬레이션)
  - 가끔 새로운 API 접근 (업무 확장)
  -> 이것들은 모두 정상이므로 BLOCK되면 오탐
```

**측정**:
- D4(FPR): 1,000건 중 BLOCK 또는 CHALLENGE 판정 비율
- 사용자별 FPR 분포 (특정 사용자만 오탐이 높은지)
- 변동 유형별 FPR (시간 변동 vs 디바이스 변동 vs IP 변동 중 어떤 것이 오탐을 유발하는지)

### 4.9 Phase 8: 적시 집행 및 흐름 완결성 (50건)

**목적**: BLOCK 판정의 피해 억제 속도, 정책 핫 리로드 정확성, MFA 에스컬레이션 왕복 정합성 검증.

**E1 시나리오: 피해 억제 (20건)**

Phase 1의 기준선이 유지된 상태에서 실행.

```
시나리오 A: 벌크 스트리밍 중단 (5건)
  #1 GET /admin/api/security-test/demo-bulk-stream (1M건 스트리밍 시작)
     -> HCAD가 비동기 분석 후 BLOCK 판정
     -> 스트리밍 응답이 도중에 중단되는 시점 기록
     -> 중단 시점까지 유출된 레코드 수 측정
  #2~#5 동일 시나리오 반복 (재현성 확인)

시나리오 B: 후속 요청 차단 지연 (15건)
  Mallory가 연속 요청을 보내는 동안 BLOCK 판정이 내려지는 시나리오:
  #6  GET /admin/api/security-test/sensitive/1  (185.203.4.1, 새벽)
  #7  GET /admin/api/security-test/sensitive/2  (1초 후)
  #8  GET /admin/api/security-test/sensitive/3  (1초 후)
  ...
  #20 GET /admin/api/security-test/sensitive/15 (1초 간격 계속)
  -> BLOCK 판정 시점 기록
  -> BLOCK 이후 실제 차단 적용된 시점 기록
  -> 그 사이 통과된 요청 수 측정
```

**E2 시나리오: 정책 핫 리로드 (15건)**

```
  기준 상태: /api/projects에 대한 ALLOW 정책 존재

  #21~#25 GET /api/projects (5건, ALLOW 확인)
  -> 정책을 DENY로 변경 (PolicyService로 핫 리로드)
  #26~#30 GET /api/projects (5건, DENY 적용 확인)
  -> 정책을 다시 ALLOW로 복원
  #31~#35 GET /api/projects (5건, ALLOW 복원 확인)

  측정: 정책 변경 직후 첫 번째 요청의 판정이 새 정책을 반영하는지
  엣지 케이스: 정책 리로드 중간에 도착한 요청의 판정
```

**E3 시나리오: MFA 에스컬레이션 왕복 (15건)**

```
  기준: Mallory 행동으로 CHALLENGE 판정이 내려진 상태

  시나리오 A: MFA 성공 (5건)
  #36 GET /admin/api/security-test/sensitive/1 (CHALLENGE 판정)
  #37 MFA 인증 성공
  #38 GET /admin/api/security-test/sensitive/1 (동일 요청 재시도)
      -> 검증: 세션이 "MFA 검증됨"으로 갱신, 요청 허용
  #39~#40 후속 정상 요청 (ALLOW 확인)

  시나리오 B: MFA 실패 (5건)
  #41 GET /admin/api/security-test/critical/1 (CHALLENGE 판정)
  #42 MFA 인증 실패 (max retry 도달)
      -> 검증: BlockedUser로 전이, 세션 무효화
  #43~#45 후속 요청 (BLOCK 확인)

  시나리오 C: MFA 타임아웃 (5건)
  #46 GET /admin/api/security-test/sensitive/1 (CHALLENGE 판정)
  #47~#49 MFA 미응답 (타임아웃 대기)
  #50 타임아웃 후 동일 요청
      -> 검증: 세션 상태 정리, 좀비 상태 아님 확인
```

---

## 5. 지표별 측정 방법 상세

### A1. Event Integrity Rate (EIR)

**측정 대상**: Phase 1~3 전체 80건 + Phase 4~7 전체 490건 = 570건
**방법**: 각 요청에 주입한 값과 AuditLog의 기록값을 필드별 대조
**대조 필드**: principalName, clientIp, requestUri, httpMethod, timestamp, userAgent, sessionId
**산식**: EIR = (일치 필드 수) / (총 필드 수) x 100
**핵심**: Mallory/Eve 구간에서도 EIR 100%여야 함 -- 이상 행동이라도 이벤트 자체는 정확히 기록되어야 하므로

### A2. Context Completeness Rate (CCR)

**측정 대상**: 570건 전체
**필수 12개 필드**: userId, sessionId, clientIp, userAgent, requestUri, httpMethod, timestamp, roles, riskScore, geoLocation, behaviorEmbedding, baselineStatus
**방법**: 각 요청의 SecurityContext 객체에서 12개 필드 존재 여부 확인
**산식**: CCR = (존재 필드 수) / (570건 x 12) x 100
**예외 처리**: GeoIP 비활성 시 geoLocation = null은 "계약상 정상 null"로 분류, 누락 아님

### A3. Context Consistency Rate (CCSR)

**측정 대상**: Phase 1~3의 80건 (3지점 비교가 가능한 구간)
**3지점**: AuditLog, HCAD Signal, LLM Prompt
**비교 속성**: clientIp, userId, roles, riskScore, timestamp
**방법**: 동일 requestId로 3곳의 데이터를 조회하여 각 속성의 값 비교
**산식**: CCSR = (3곳 일치 건수) / (80건 x 5속성) x 100
**위반 예시**: AuditLog에 riskScore=0.85, Prompt에 "low risk" -> 위반

### A4. Prompt Fidelity Rate (PFR)

**측정 대상**: LLM 호출이 발생한 모든 요청
**방법**: 프롬프트 템플릿의 placeholder 목록과 실제 프롬프트의 치환 결과 비교
**산식**: PFR = (올바르게 치환된 placeholder 수) / (총 placeholder 수) x 100
**위반 예시**: 템플릿에 `{riskScore}`가 있는데 실제 프롬프트에 `{riskScore}`가 문자 그대로 남아있으면 위반

### A5. Metadata Traceability Rate (MTR)

**측정 대상**: 570건 전체
**추적 체인**: requestId -> correlationId -> eventId -> promptHash -> promptVersion
**방법**: requestId로 시작하여 각 다음 단계를 조회, 체인이 끊기는 지점 기록
**산식**: MTR = (완전 연결 건수) / 570 x 100
**참고**: LLM 호출이 없는 요청은 promptHash까지만 추적 (체인 길이 조정)

### A6. Context Contamination Rate (CoR)

**측정 대상**: Phase 2(Alice 10건) + Phase 3(Mallory 20건) 동시 실행 구간
**방법**: Alice 10건 각각의 컨텍스트/프롬프트에서 Mallory 식별자 검색
**검색 대상**: "185.203" (Mallory IP), "Firefox" (Mallory UA), "Linux" (Mallory OS)
**산식**: CoR = (오염 발견 건수) / (Alice 10건) x 100
**추가**: Redis 캐시 키 구조에 userId 포함 여부 구조적 검증
**목표**: CoR = 0% (1건이라도 발견 시 심각한 보안 결함)

### B1. RAG Authorization Precision (RAP)

**측정 대상**: Phase 3(Mallory 20건) + Phase 4(Eve 200건)
**방법**: 각 요청의 RAG 회수 문서 목록에서 해당 사용자 역할(ROLE_DEVELOPER)에 허용된 문서인지 확인
**산식**: RAP = (권한 내 문서 수) / (총 회수 문서 수) x 100
**위반 예시**: ROLE_DEVELOPER인데 ROLE_ADMIN 전용 정책 문서가 회수됨
**핵심**: 벡터 검색에 역할 기반 필터가 적용되는지의 구조적 검증 포함

### B2. Round Progression Integrity (RPI)

**측정 대상**: Phase 1 -> Phase 2 -> Phase 3 전이 시점 (3개 스냅샷)
**방법**: 각 Phase 종료 시 Redis에서 `hcad:baseline:v2:{userId}` 키의 전체 값 덤프
**검증 규칙**:
  - 관측 횟수: Phase 2 >= Phase 1 (역행 금지)
  - 기준선 평균: Phase 3에서 Mallory 이상 행동이 기준선을 과도하게 왜곡하지 않아야 함 (alpha=0.1이므로 20건으로 기존 50건 기준선 급변 불가)
**산식**: RPI = (역행 없는 속성 수) / (총 비교 속성 수) x 100

### B3. Baseline Maturity Accuracy (BMA)

**측정 대상**: Phase 1의 50건 (상태 전이 시점 확인)
**기대 전이**:
  - 요청 #1~#9: NONE
  - 요청 #10: NONE -> PROVISIONAL (initialSamples=10 도달)
  - 요청 #20: PROVISIONAL -> ESTABLISHED (minSamples=20 + 통계적 안정)
**방법**: 요청 #10, #20 직후 기준선 상태 조회
**산식**: BMA = (기대 상태와 일치한 전이 수) / (총 전이 검사 수) x 100

### B4. User-Specific Novelty Sensitivity (USNS)

**측정 대상**: Phase 2(Alice 10건) vs Phase 3(Mallory 20건)
**방법**: 두 집단의 anomalyScore 분포를 통계적으로 비교
**검정**: Mann-Whitney U 검정 (비모수, 표본 크기 차이 허용)
**산식**: USNS = 1 if p < 0.05 (통계적으로 유의미한 차이 존재), 0 otherwise
**추가 지표**: Effect Size (Cohen's d) -- 차이의 크기 정량화
**기대**: Alice 평균 anomalyScore < 0.3, Mallory 평균 > 0.7, p < 0.001

### C1. Behavioral Surprise Resolution (BSR)

**측정 대상**: Phase 3(Mallory 20건)
**4차원 검증**:

| 차원 | 탐지 기준 | 해당 요청 |
|------|----------|----------|
| Sequence 이상 | 접근 순서가 기준선 전이 확률과 불일치 | #62~67 (로그인 직후 관리자 API) |
| Resource adjacency 이상 | 연속 요청의 리소스 도메인 거리 > 기준선 | #64->68 (정책->민감데이터) |
| Friction deviation | 요청 간격이 기준선 간격 분포에서 3sigma 이탈 | 전체 (2~5초 간격) |
| Scope jump | 접근 리소스가 역할 권한 범위 밖 | #68~79 (ADMIN 영역) |

**방법**: 각 차원별로 이상 신호가 HCAD 출력에 기록되었는지 확인
**산식**: BSR = (이상 신호가 기록된 차원 수) / 4 x 100
**목표**: 4차원 중 3차원 이상 감지 (BSR >= 75%)

### C2. Context-to-Decision Calibration (CDC)

**측정 대상**: Phase 1~3의 80건 전체
**설계 원칙**: Contexa에서 riskScore는 감사 기록용이며 판정 로직에 관여하지 않는다. 판정은 LLM이 action을 직접 결정하고, confidence가 가드레일 기준이다. 따라서 CDC는 riskScore가 아닌 **컨텍스트 위협 수준 vs action/confidence** 정합성을 측정한다.
**컨텍스트 위협 수준 분류**:
  - CLEAN: 이상 신호 0개 + 기준선 ESTABLISHED -> action=ALLOW, confidence >= 0.6 기대
  - MODERATE: 이상 신호 1~2개 OR 기준선 PROVISIONAL -> CHALLENGE/ESCALATE 허용, 과도한 BLOCK은 과장
  - SEVERE: 이상 신호 3개+ OR contextBindingHash 불일치 OR 민감 리소스+새 디바이스 -> 높은 confidence의 ALLOW는 위험
**산식**: CDC = (교정된 건수) / (총 건수) x 100
**과장 탐지**: CLEAN 컨텍스트인데 BLOCK -> 과잉 차단 (exaggeration)
**과소 탐지**: SEVERE 컨텍스트인데 높은 confidence ALLOW -> 위험한 과소 반응 (under-reaction)

### C3. Evidence-Reason Alignment (ERA)

**측정 대상**: Phase 3(Mallory 20건)의 LLM reasoning 텍스트
**방법**: reasoning에서 증거 문장을 추출하고, 각 문장이 실제 수집 데이터와 일치하는지 대조
**대조 예시**:
  - reasoning: "Access from unusual IP 185.203.4.1" -> 실제 clientIp = 185.203.4.1 -> 일치
  - reasoning: "Access at 02:00 outside business hours" -> 실제 timestamp = 02:00 + 기준선 업무시간 09~18 -> 일치
  - reasoning: "User attempted to access financial data" -> 실제 requestUri에 finance 없음 -> 불일치 (hallucination)
**산식**: ERA = (실제 데이터와 일치하는 증거 문장 수) / (reasoning 내 총 증거 문장 수) x 100

### C4. Safe-Uncertainty Handling Rate (SUHR)

**측정 대상**: 전체 570건 중 confidence < 0.6인 요청
**방법**: 확신이 낮은 판정에서 ALLOW가 아닌 비율 (CHALLENGE, ESCALATE, BLOCK)
**산식**: SUHR = (ALLOW가 아닌 건수) / (confidence < 0.6인 총 건수) x 100
**핵심 시나리오**: Mallory #62~63 (대시보드 조회 -- IP만 이상, 행위 정상) -> confidence 낮음 예상 -> CHALLENGE가 적절

### D1. Adaptive Attack Resistance (AAR)

**측정 대상**: Phase 4(Eve 200건) 중 이상 요청 약 80건
**방법**: Eve의 요청 중 정상 모방이 아닌 이상 접근을 분리하여 감지율 계산
**주별 분석**:
  - Week 1 (순수 모방, 이상 0건): 오탐 없어야 함
  - Week 2 전반 (이상 ~8건): 최소 50% 감지 기대
  - Week 2 후반 (이상 ~28건): 최소 70% 감지 기대
  - Week 2 마지막 (이상 ~40건): 최소 85% 감지 기대
**산식**: AAR = (감지된 이상 요청 수) / (총 이상 요청 수) x 100
**추가**: "최초 감지 시점" -- 몇 일차의 몇 번째 요청에서 처음 CHALLENGE/BLOCK 발생했는가
**핵심**: 기준선이 Eve에 의해 오염된 후에도 행동 패턴의 질적 차이를 잡는가

### D2. Decision Stability Rate (DSR)

**측정 대상**: Phase 5(동일 입력 3종 x 10회 = 30건)
**방법**: 각 입력별 10회 판정의 모드(최빈값)를 구하고, 모드와 일치하는 비율
**산식**: DSR = (모드와 일치하는 판정 수) / 30 x 100
**추가 측정**: confidence 표준편차 (입력별)
  - 입력 A (정상): confidence 평균 > 0.8, 표준편차 < 0.1 기대
  - 입력 B (명확한 이상): confidence 평균 > 0.7, 표준편차 < 0.15 기대
  - 입력 C (경계 사례): 표준편차가 가장 클 것으로 예상, 측정값 기록

### D3. Baseline Drift Tolerance (BDT)

**측정 대상**: Phase 6(Alice 업무 변경 60건)
**방법**: 60건 중 오탐(BLOCK 또는 CHALLENGE) 건수 추적
**구간별 분석**:
  - Day 21~23 (전환 초기 30건): 일부 CHALLENGE 허용 (기준선 적응 중)
  - Day 24~26 (전환 완료 30건): 오탐 0건이어야 함 (기준선 적응 완료)
**산식**: BDT = 1 - (Day 24~26 오탐 건수 / 30)
**추가 시각화**: Day별 anomalyScore 추이 그래프 -- 감소 곡선이어야 함

### D4. Normal Traffic False Positive Rate (FPR)

**측정 대상**: Phase 7(5명 x 200건 = 1,000건)
**방법**: 전체 정상 트래픽 중 BLOCK 또는 CHALLENGE 판정 비율
**산식**: FPR = (BLOCK + CHALLENGE 건수) / 1,000 x 100
**세분화**:
  - 사용자별 FPR (특정 사용자만 높은지)
  - 변동 유형별 FPR:
    - 시간 변동 (점심 접근): FPR_time
    - 디바이스 변동 (모바일): FPR_device
    - IP 변동 (VPN): FPR_ip
    - 리소스 변동 (새 API): FPR_resource

### E1. Damage Containment Rate (DCR)

**측정 대상**: Phase 8 시나리오 A(벌크 5건) + 시나리오 B(후속 차단 15건)
**설계 원칙**: Contexa는 비동기 아키텍처이다. LLM 분석에 수초가 소요되므로 동기적 차단은 불가하며, "피해 제로"가 아닌 "피해 최소화"가 목표이다.
**측정 항목**:
  - 벌크 중단: 1M건 스트리밍 중 BLOCK 시점 이후 추가 유출 레코드 수
  - 후속 차단 지연: BLOCK 판정 시점 ~ 실제 차단 적용 시점 (초)
  - 후속 차단 통과: BLOCK 판정 ~ 차단 적용 사이 통과된 요청 수
**산식**:
  - DCR_bulk = 1 - (중단 후 유출 레코드 / 전체 레코드)
  - DCR_latency = BLOCK 판정 ~ 차단 적용 소요 시간 (초)
  - DCR_passthrough = BLOCK 후 통과 요청 수

### E2. Policy Reload Consistency (PRC)

**측정 대상**: Phase 8 E2 시나리오(15건)
**방법**: 정책을 ALLOW -> DENY -> ALLOW로 전환하며 각 전환 직후 요청의 판정 확인
**산식**: PRC = (정책 변경 의도와 일치하는 판정 수) / 15 x 100
**엣지 케이스**: 리로드 중간 요청이 이전 정책으로 평가되는 것은 허용 (1건 이내)
**실패 조건**: 리로드 후에도 이전 정책이 계속 적용되면 PRC 위반. 리로드 실패 시 빈 정책(전체 허용)이 되면 심각한 PRC 위반.

### E3. Escalation Round-Trip Integrity (ERI)

**측정 대상**: Phase 8 E3 시나리오(15건)
**방법**: CHALLENGE -> MFA 인증 -> 결과 반영까지의 전체 흐름이 정확히 완료되는지 확인
**3가지 경로**:
  - MFA 성공: CHALLENGE -> MFA 성공 -> 세션 "MFA 검증됨" 갱신 -> 동일 요청 ALLOW
  - MFA 실패: CHALLENGE -> MFA 실패(max retry) -> BlockedUser 전이 -> 후속 BLOCK
  - MFA 타임아웃: CHALLENGE -> 타임아웃 -> 세션 정리 -> 좀비 상태 아님 확인
**산식**: ERI = (정확히 완료된 경로 수) / 3 x 100
**검증 포인트**: 각 경로에서 HCAD 기준선, BlockedUser 테이블, 세션 상태가 모두 정합적으로 갱신되는지

---

## 6. 합격 기준

### A군: 구현 정합성

| 지표 | 합격 | 근거 |
|------|------|------|
| A1 EIR | >= 99% | 이벤트 1건 손실도 감사 추적 불가 |
| A2 CCR | >= 95% | 네트워크 조건에 따른 일부 필드 수집 실패 허용 |
| A3 CCSR | >= 98% | 표현 불일치는 판단 왜곡 직결 |
| A4 PFR | = 100% | 프롬프트 계약 위반은 LLM 오판 직결 |
| A5 MTR | >= 95% | 비동기 처리 일부 유실 허용, 95% 이상 추적 가능 |
| A6 CoR | = 0% | 교차 오염은 절대 불가 |

### B군: RAG 및 기준선 품질

| 지표 | 합격 | 근거 |
|------|------|------|
| B1 RAP | >= 90% | 벡터 유사도 특성상 경계 문서 혼입 일부 허용 |
| B2 RPI | = 100% | 기준선 역행은 구조적 버그 |
| B3 BMA | >= 90% | 경계 시점(9건->10건)의 1~2건 오차 허용 |
| B4 USNS | p < 0.05, Cohen's d > 0.8 | Alice vs Mallory 차이의 통계적 유의성 + 큰 효과 크기 |

### C군: 행동 의미 및 프롬프트 해석

| 지표 | 합격 | 근거 |
|------|------|------|
| C1 BSR | >= 75% (4차원 중 3개 이상) | 모든 차원을 잡을 필요는 없으나 다수 감지 필수 |
| C2 CDC | 교정 오차 < 0.15 | riskScore와 decision 간 괴리가 0.15 이내 |
| C3 ERA | >= 80% | LLM hallucination 20% 이내 |
| C4 SUHR | >= 90% | 불확실 상황의 10% 이내만 과잉 허용 |

### D군: 실전 내성

| 지표 | 합격 | 근거 |
|------|------|------|
| D1 AAR | Week 2 후반 >= 70% | 저속 공격의 초기 단계 미감지 허용, 확대 시 반드시 감지 |
| D2 DSR | >= 85% | LLM 특성상 100% 일관성 불가, 85% 이상 안정성 요구 |
| D3 BDT | Day 24~26 오탐 = 0건 | 적응 기간 후 오탐 없어야 함 |
| D4 FPR | < 1% | 1,000건 중 오탐 10건 이내 |

### E군: 적시 집행 및 흐름 완결성

| 지표 | 합격 | 근거 |
|------|------|------|
| E1 DCR_bulk | 전체의 10% 이내에서 스트리밍 중단 | 비동기 특성상 즉시 중단 불가, 10% 이내 억제 |
| E1 DCR_latency | 10초 이내 | 비동기 LLM 분석 + 판정 전파 소요 시간 |
| E1 DCR_passthrough | 5건 이내 | BLOCK 후 차단 적용까지 통과 허용 최대 건수 |
| E2 PRC | >= 93% (15건 중 14건 이상) | 리로드 중간 1건의 이전 정책 적용은 허용 |
| E3 ERI | = 100% (3경로 모두 완료) | MFA 흐름 불완전은 보안 구멍 직결 |

---

## 7. 증적 산출물 구조

```
증적자료/
  00_검증_개요서.pdf
    - 18개 지표 정의 및 합격 기준
    - 7 Phase 실행 계획 요약
    - 페르소나 정의서

  01_A군_구현정합성/
    A1_EIR_570건_필드대조표.csv
    A2_CCR_필수필드_존재여부표.csv
    A3_CCSR_3지점_일관성_대조표.csv
    A4_PFR_템플릿_placeholder_대조표.csv
    A5_MTR_추적체인_연결표.csv
    A6_CoR_오염검사_결과표.csv
    A군_종합_판정표.pdf

  02_B군_RAG기준선품질/
    B1_RAP_회수문서_권한검증표.csv
    B2_RPI_3Phase_기준선_스냅샷.json
    B3_BMA_상태전이_시점표.csv
    B4_USNS_anomalyScore_비교표.csv
    B4_USNS_통계적_유의성_검정.pdf (Mann-Whitney U, Cohen's d)
    B군_종합_판정표.pdf

  03_C군_행동의미해석/
    C1_BSR_4차원_이상신호_감지표.csv
    C2_CDC_교정곡선.png + 원본데이터.csv
    C3_ERA_reasoning_증거_대조표.csv
    C4_SUHR_애매한상황_판정표.csv
    C군_종합_판정표.pdf

  04_D군_실전내성/
    D1_AAR_적응형공격_14일_감지표.csv
    D1_AAR_주별_감지율_추이.png
    D1_AAR_최초감지시점_기록.txt
    D2_DSR_30건_반복판정표.csv
    D2_DSR_confidence_표준편차.csv
    D3_BDT_60건_오탐추이.csv
    D3_BDT_anomalyScore_일별추이.png
    D4_FPR_1000건_정상트래픽_판정표.csv
    D4_FPR_사용자별_변동유형별_분석.csv
    D군_종합_판정표.pdf

  05_E군_적시집행/
    E1_DCR_벌크스트리밍_중단시점표.csv
    E1_DCR_후속차단_지연측정표.csv
    E2_PRC_정책리로드_판정대조표.csv
    E3_ERI_MFA_3경로_완결성표.csv
    E군_종합_판정표.pdf

  06_종합_대시보드.pdf
    21개 지표 수치 요약 (레이더 차트)
    A/B/C/D/E군별 합격/불합격 판정
    Phase별 실행 결과 타임라인
    종합 결론 및 권고사항

  07_재현성_검증/ (선택)
    3회 반복 실행 결과 비교표
    지표별 표준편차
```

---

## 8. 전체 건수 산정 요약

| Phase | 페르소나 | 건수 | 주요 측정 지표 |
|-------|---------|------|--------------|
| 1. 기준선 구축 | Alice | 50 | A1, A2, A5, B3 |
| 2. 정상 대조군 | Alice | 10 | C군 정상 기준값 |
| 3. 어설픈 침입자 | Mallory | 20 | A3, A4, A6, B1, B2, B4, C1~C4 |
| 4. 적응형 공격 | Eve | 200 | D1 |
| 5. 판정 재현성 | 반복 입력 | 30 | D2 |
| 6. 기준선 드리프트 | Alice 변경 | 60 | D3 |
| 7. 대규모 정상 | 5명 혼합 | 1,000 | D4 |
| 8. 적시 집행 | 혼합 | 50 | E1, E2, E3 |
| **합계** | | **1,420** | **21개 지표 전체** |

재현성 검증을 위해 3회 반복 시 총 4,260건.
