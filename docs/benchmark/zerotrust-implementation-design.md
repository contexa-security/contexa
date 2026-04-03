# zerotrust 패키지 구현 설계안

## 1. 핵심 원칙

sandbox 팀의 8개 시나리오(24라운드, 3주 기준선 + 미세 이상)를 그대로 사용한다.
새로운 시나리오를 만들지 않는다.
sandbox의 시나리오가 이미 "LLM이 필요한 수준의 미세 변화"를 설계했기 때문이다.

zerotrust가 하는 일은 단 하나:
**sandbox의 시나리오를 실제 LLM으로 실행하고, 그 판정 결과를 수집하여 CDC/ERA/SUHR/DSR을 측정한다.**

---

## 2. sandbox가 이미 증명하는 것 (건드리지 않는다)

sandbox의 SandboxFullStackPromptBenchmarkTest가 8개 시나리오 x 24라운드를 실행하며 검증하는 11개 지표:

| 지표 | sandbox의 검증 방식 |
|------|-------------------|
| EIR | requestId 체인, 이벤트 필드 대조 |
| CCR | 12+ 필수 필드 존재 확인 |
| CCSR | AuditLog/HCAD/Prompt 3지점 속성 비교 |
| PFR | 18+ 체크: 해시, 섹션, 길이, 메타데이터 |
| MTR | 23포인트 계약 검증 |
| CoR | 사용자별 벡터 격리, 교차 오염 0% |
| RAP | relatedDocuments userId/purpose 검증 |
| RPI | 24라운드 역행 검지, progression scorecard |
| BMA | PROVISIONAL/ESTABLISHED 전이 확인 |
| USNS | isNewUser/Session/Device + anomalySignal 대비 프롬프트 반영 |
| BSR | 8개 anomalySignal별 프롬프트 섹션 반영 확인 |

이것은 LLM Mock(StableLlmBoundary) 상태에서 동작한다.
LLM 판정 결과와 무관하게 "컨텍스트와 프롬프트가 고품질인가"를 검증한다.
**zerotrust는 이 11개를 복제하지 않는다. sandbox 것을 그대로 쓴다.**

---

## 3. zerotrust가 추가로 증명해야 하는 것 (3개 + 1개)

### 3.1 CDC (Context-to-Decision Calibration)

**질문**: 프롬프트에 담긴 컨텍스트의 위협 수준과, LLM이 내린 판정이 비례하는가?

**sandbox가 이미 제공하는 것**:
- 8개 시나리오의 각 라운드에 `behaviorPhase`(BASELINE/ANOMALY/RECOVERY)와 `anomalySignal`이 라벨링되어 있다
- 각 라운드의 `ZeroTrustPromptTraceSnapshot`에 프롬프트 전문, 메타데이터, 이벤트가 캡처된다

**zerotrust가 추가하는 것**:
- LLM Mock을 해제하고 실제 LLM으로 실행
- 캡처된 snapshot에서 `SecurityDecision`의 action, confidence를 추출
- behaviorPhase와 대조:
  - BASELINE 라운드 → ALLOW + 높은 confidence 기대
  - ANOMALY 라운드 → CHALLENGE/BLOCK/ESCALATE + 낮은 confidence 허용
  - RECOVERY 라운드 → ALLOW로 복귀 기대 (단, confidence가 BASELINE보다 낮을 수 있음)
- 가드레일(DefaultPromptConfidenceGuardrail)의 cap 적용 여부도 확인:
  - ANOMALY인데 confidence > 0.85(cap 안 됨) + ALLOW → 가드레일 실패 = CDC 위반

**측정 단위**: 시나리오당 24라운드 x 8시나리오 = 192건
**산식**: (behaviorPhase와 판정이 비례하는 건수) / 192 x 100

### 3.2 ERA (Evidence-Reason Alignment)

**질문**: LLM의 reasoning 텍스트가 프롬프트에 실제로 포함된 증거에 기반하는가?

**sandbox가 이미 제공하는 것**:
- 각 라운드의 userPrompt 전문 (12개 섹션)
- 각 라운드의 anomalySignal 라벨 (RESOURCE_SENSITIVITY_SURGE, DEVICE_FINGERPRINT_SHIFT 등)
- 각 라운드의 event 메타데이터 (sourceIp, requestPath, clientIp 등)

**zerotrust가 추가하는 것**:
- 실제 LLM의 reasoning 텍스트를 SecurityDecision.reasoning에서 추출
- reasoning에서 주장하는 사실을 userPrompt와 대조:
  - reasoning이 "device fingerprint changed"라 했으면 → userPrompt의 OBSERVED_WORK_PATTERN 섹션에 device shift 언급이 있어야 함
  - reasoning이 "unusual resource access"라 했으면 → userPrompt의 SESSION_NARRATIVE 섹션에 해당 리소스가 있어야 함
  - reasoning이 프롬프트에 없는 사실을 언급하면 → hallucination
- **검증 기준**: reasoning의 주장 ⊆ userPrompt의 사실

**측정 단위**: ANOMALY 라운드에서만 측정 (시나리오당 4~6건 x 8시나리오 = 32~48건)
**산식**: (userPrompt에 근거가 있는 reasoning 주장 수) / (reasoning 내 총 사실 주장 수) x 100

### 3.3 SUHR (Safe-Uncertainty Handling Rate)

**질문**: 가드레일이 confidence를 cap한 경우(불확실 상황), LLM의 최종 판정이 보수적인가?

**sandbox가 이미 제공하는 것**:
- SecurityDecision.autonomyConstraintApplied (가드레일 적용 여부)
- SecurityDecision.confidence vs SecurityDecision.llmAuditConfidence (cap 전후)
- PromptExecutionMetadata.promptEvidenceCompleteness (컨텍스트 완전도)

**zerotrust가 추가하는 것**:
- 가드레일이 적용된 건(autonomyConstraintApplied == true)을 필터링
- 그 건들의 최종 판정(autonomousAction)이 ALLOW가 아닌 비율
- 가드레일이 confidence를 0.54로 cap했는데 여전히 ALLOW이면 → SUHR 위반

**측정 단위**: 가드레일 적용 건수 (시나리오/컨텍스트 상태에 따라 가변)
**산식**: (가드레일 적용 건 중 ALLOW가 아닌 건수) / (가드레일 적용 총 건수) x 100

### 3.4 DSR (Decision Stability Rate)

**질문**: 같은 시나리오를 여러 번 실행하면 LLM 판정이 일관되는가?

**sandbox가 이미 제공하는 것**:
- SandboxPromptBenchmarkBatchRunner가 sampleCount 파라미터로 동일 시나리오 반복 실행 지원
- 반복 실행 결과를 SandboxPromptBenchmarkStatistics로 통계 처리 (mean, stdDev, p90, p95, ci95)

**zerotrust가 추가하는 것**:
- sampleCount를 3~5로 올려서 동일 시나리오 반복 실행
- 각 실행의 ANOMALY 라운드에서 action을 수집
- 동일 라운드의 action 일관성 측정 (모드 일치율)
- confidence의 표준편차 측정 (작을수록 안정)

**측정 단위**: 시나리오당 ANOMALY 라운드 수 x sampleCount
**산식**: (모드 action과 일치하는 판정 수) / (총 반복 판정 수) x 100

---

## 4. 구현 구조

### 4.1 변경하지 않는 파일 (sandbox에서 복사한 53개)

전부 그대로 유지한다. 특히:
- ZeroTrustFullStackPromptReplayHarness: 실제 웹/MFA 리플레이 엔진
- ZeroTrustPromptBenchmarkBatchRunner: 다중 시나리오 x 다중 샘플 배치 실행
- ZeroTrustPromptBenchmarkMetricExtractor: 라운드별 11개 지표 추출
- ZeroTrustPromptReplayScenarioCatalog: 8개 시나리오 카탈로그
- ZeroTrustPromptLongHorizonScenarioFactory: 24라운드 시나리오 생성
- ZeroTrustPromptBenchmarkReportWriter: NDJSON/JSON/Markdown 증적 생성
- ZeroTrustPromptBenchmarkStatistics: 통계 계산 (mean, stdDev, CI 등)

### 4.2 수정하는 파일

**ZeroTrustPromptBenchmarkMetricCatalog.java**
- CDC, ERA, SUHR: `implemented = true` 전환 (완료)
- DSR 추가 (완료)

**ZeroTrustPromptBenchmarkMetricExtractor.java**
- `evaluateRun()` 메서드에 CDC/ERA/SUHR 추출 로직 추가
- 실제 LLM 모드일 때만 측정 (stable 모드에서는 건너뜀)
- snapshot에서 SecurityDecision 필드 추출: action, confidence, llmAuditConfidence, autonomyConstraintApplied, reasoning

**ZeroTrustFullStackPromptBenchmarkTest.java**
- LLM 모드 분기: `zerotrust.llm.mode=real`이면 RealLlmBoundary 사용
- CDC/ERA/SUHR assertion 추가 (real 모드에서만)
- DSR: sampleCount > 1일 때 반복 판정 일관성 assertion 추가

### 4.3 유지하는 신규 파일 (쓸모있는 4개)

| 파일 | 역할 | 연결 지점 |
|------|------|----------|
| ZeroTrustRealLlmBoundary | LLM Mock 해제 | BenchmarkTest의 @BeforeEach에서 모드별 분기 |
| ZeroTrustCdcCalibrationValidator | behaviorPhase vs action/confidence 교정 | MetricExtractor.evaluateRun()에서 호출 |
| ZeroTrustSuhrValidator | 가드레일 적용 건의 보수적 판정 비율 | MetricExtractor.evaluateRun()에서 호출 |
| ZeroTrustDsrValidator | 반복 실행 판정 일관성 | BenchmarkTest에서 sampleCount > 1일 때 호출 |

### 4.4 전면 재작성하는 파일 (2개)

**ZeroTrustCdcCalibrationValidator.java** (재작성 완료)
- riskScore 기반 → 컨텍스트 위협 수준 기반으로 이미 수정함
- 추가 수정: behaviorPhase(BASELINE/ANOMALY/RECOVERY)를 직접 입력으로 받도록 변경

**ZeroTrustEraReasoningValidator.java** (재작성 필요)
- 정규식 IP/경로 매칭 → userPrompt 섹션 내용과 reasoning 텍스트의 의미적 대조로 변경
- reasoning의 각 주장이 userPrompt의 어느 섹션에 근거하는지 추적

### 4.5 폐기하는 파일 (4개)

| 파일 | 폐기 이유 |
|------|----------|
| ZeroTrustAdversarialPersona | sandbox의 시나리오를 그대로 쓰므로 불필요 |
| ZeroTrustAdversarialBenchmarkTest | sandbox의 BenchmarkTest 구조 위에 구축하므로 별도 테스트 불필요 |
| ZeroTrustBsrDimensionValidator | sandbox의 anomalySignal 기반 BSR이 이미 충분 |
| ZeroTrustAarValidator | sandbox의 8개 시나리오가 이미 적응형 공격 수준 |
| ZeroTrustStatisticalTestUtils | DSR의 반복 실행 통계는 sandbox의 BenchmarkStatistics 재사용 |

---

## 5. 실행 흐름

### stable 모드 (기존 sandbox와 동일)

```
ZeroTrustFullStackPromptBenchmarkTest
  → ZeroTrustStableLlmBoundary.configure() (LLM Mock)
  → ZeroTrustPromptBenchmarkBatchRunner.execute(시나리오 8개, sampleCount=1, roundCount=24)
    → 시나리오마다 ZeroTrustFullStackPromptReplayHarness.replayScenario()
      → 24라운드 실제 웹/MFA 실행
      → 라운드마다 ZeroTrustPromptTraceSnapshot 캡처
    → ZeroTrustPromptBenchmarkMetricExtractor.evaluateRun()
      → 기존 11개 지표 계산 (EIR, CCR, CCSR, PFR, MTR, CoR, RAP, RPI, BMA, USNS, BSR)
      → CDC/ERA/SUHR = skip (LLM Mock이므로)
  → 11개 지표 assertion (>= 95%, CoR <= 0%)
  → ZeroTrustPromptBenchmarkReportWriter.writeReport() → 증적 출력
```

### real 모드 (zerotrust 추가분)

```
ZeroTrustFullStackPromptBenchmarkTest
  → ZeroTrustRealLlmBoundary.configure() (LLM Mock 해제, 실제 Ollama 실행)
  → ZeroTrustPromptBenchmarkBatchRunner.execute(시나리오 8개, sampleCount=3, roundCount=24)
    → 시나리오마다 3회 반복 실행
    → 24라운드 x 3회 = 72회 실제 LLM 판정
    → 라운드마다 SecurityDecision 필드 추가 캡처:
        action, confidence, llmAuditConfidence,
        autonomyConstraintApplied, autonomyConstraintReasons,
        reasoning, riskScore(감사용)
  → ZeroTrustPromptBenchmarkMetricExtractor.evaluateRun()
    → 기존 11개 지표 계산
    → 추가 3개:
      → ZeroTrustCdcCalibrationValidator:
          각 라운드의 behaviorPhase와 action/confidence 대조
          BASELINE → ALLOW 기대, ANOMALY → !ALLOW 기대, RECOVERY → ALLOW 기대
      → ZeroTrustEraReasoningValidator:
          ANOMALY 라운드의 reasoning vs userPrompt 섹션 대조
          reasoning 주장이 프롬프트 섹션에 근거하는지 확인
      → ZeroTrustSuhrValidator:
          autonomyConstraintApplied == true인 건에서 ALLOW 비율 측정
  → DSR 계산:
    → 3회 반복의 동일 라운드 action을 비교
    → 모드 일치율 = DSR
  → 14개 + DSR assertion
  → ZeroTrustPromptBenchmarkReportWriter.writeReport() → 증적 출력 (CDC/ERA/SUHR/DSR 포함)
```

---

## 6. 증적 산출물 (real 모드)

기존 sandbox 보고서 구조에 추가:

```
build/reports/zerotrust-fullstack-benchmark/
  summary.json           ← 기존 11개 + CDC/ERA/SUHR/DSR 4개 추가
  summary.md
  runs.ndjson
  rounds.ndjson
  metrics.ndjson         ← CDC, ERA, SUHR, DSR 행 추가
  prompt-fidelity.ndjson
  defects.ndjson
  scenarios.ndjson
  metric-catalog.ndjson  ← 16개 공식 지표 (14 + AAR + DSR → CDC/ERA/SUHR + DSR)

  # 추가 증적 (real 모드에서만 생성)
  cdc-calibration.ndjson   ← 라운드별 behaviorPhase vs action/confidence
  era-alignment.ndjson     ← ANOMALY 라운드별 reasoning 주장 vs 프롬프트 근거
  suhr-decisions.ndjson    ← 가드레일 적용 건별 판정 상세
  dsr-stability.ndjson     ← 반복 실행별 action/confidence 비교
```

---

## 7. 합격 기준

### 기존 11개 (sandbox와 동일)
| 지표 | 기준 |
|------|------|
| EIR, CCR, CCSR, PFR, MTR | >= 95% |
| CoR | <= 0% |
| RAP, RPI, BMA, USNS, BSR | >= 95% |

### 추가 4개 (real 모드에서만 적용)
| 지표 | 기준 | 근거 |
|------|------|------|
| CDC | >= 85% | ANOMALY 16라운드 중 13건 이상 적절한 판정 |
| ERA | >= 80% | reasoning의 사실 주장 중 80% 이상 프롬프트에 근거 |
| SUHR | >= 90% | 가드레일 적용 건 중 90% 이상 보수적 판정 |
| DSR | >= 80% | 3회 반복 중 action 모드 일치율 |

---

## 8. 왜 이 설계가 sandbox의 수준에 부합하는가

1. **sandbox의 시나리오를 그대로 쓴다**: 3주 기준선 + 미세 이상(하나의 차원만 변경)이 이미 LLM이 필요한 수준의 테스트다. 유치한 4차원 동시 변경 시나리오를 만들지 않는다.

2. **sandbox의 인프라를 그대로 쓴다**: ReplayHarness, BatchRunner, MetricExtractor, ReportWriter, Statistics 전부 재사용. 별도 HTTP 호출 코드를 만들지 않는다.

3. **LLM Mock만 해제한다**: sandbox의 StableLlmBoundary 대신 RealLlmBoundary를 사용. 나머지 파이프라인은 100% 동일하게 실행된다.

4. **판정 결과만 추가 수집한다**: sandbox가 이미 캡처하는 snapshot에서 SecurityDecision 필드를 추가로 읽을 뿐, 새로운 캡처 메커니즘을 만들지 않는다.

5. **증적 형식도 sandbox와 동일하다**: NDJSON/JSON/Markdown 보고서에 CDC/ERA/SUHR/DSR 행만 추가된다.
