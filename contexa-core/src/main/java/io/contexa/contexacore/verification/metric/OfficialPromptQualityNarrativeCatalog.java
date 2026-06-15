package io.contexa.contexacore.verification.metric;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import org.springframework.util.StringUtils;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Converts raw official metric observations into operator-readable diagnostic evidence
 * before the result is persisted to the official verification ledger.
 */
public class OfficialPromptQualityNarrativeCatalog {

    public static final String CATALOG_VERSION = "PQA-OFFICIAL-DIAGNOSTIC-CATALOG-2026.05.11-ACTUAL-PROMPT-LEDGER";

    private static final Map<String, MetricNarrative> METRICS = Map.ofEntries(
            Map.entry("EIR", new MetricNarrative(
                    "요청 사실 보존",
                    "실제 요청에서 수집한 사용자, 테넌트, 리소스, 인증 상태가 봉인 증거와 최종 프롬프트까지 같은 의미로 유지되는지 확인합니다.",
                    "요청 사실이 프롬프트에 정확히 전달되지 않으면 LLM은 실제 요청과 다른 상황을 기준으로 판단할 수 있습니다.",
                    "문제 해결 단계에서 요청 컨텍스트와 프롬프트 조립 값을 같은 식별자로 정렬하십시오.",
                    "재검증 시 요청 증거, 봉인 증거, 최종 프롬프트의 요청 사실이 같은 값으로 확인되어야 합니다.")),
            Map.entry("CCR", new MetricNarrative(
                    "컨텍스트 완전성",
                    "LLM 판단에 필요한 요청, 인증, 리소스, 기준선, 거버넌스 컨텍스트가 누락 없이 준비되었는지 확인합니다.",
                    "필수 컨텍스트가 비어 있으면 프롬프트 품질 보증서가 실제 운영 조건을 충분히 설명하지 못합니다.",
                    "문제 해결 단계에서 누락된 컨텍스트 생산자를 지정하고 봉인 증거에 같은 값이 저장되도록 보강하십시오.",
                    "재검증 시 필수 컨텍스트 섹션이 누락 없이 확인되어야 합니다.")),
            Map.entry("CCSR", new MetricNarrative(
                    "컨텍스트 일관성",
                    "같은 사실이 요청 증거, 봉인 증거, 최종 프롬프트, 공식 원장에 서로 다른 값으로 저장되지 않았는지 확인합니다.",
                    "같은 사실이 서로 다르게 보이면 공식검사 결과는 문제 해결과 감사 근거로 사용할 수 없습니다.",
                    "문제 해결 단계에서 증거 캡처, 해시 생성, 프롬프트 조립 경로의 필드 매핑을 정렬하십시오.",
                    "재검증 시 요청 경로, 리소스, 사용자, 테넌트, 해시 값이 같은 흐름으로 일치해야 합니다.")),
            Map.entry("PFR", new MetricNarrative(
                    "프롬프트 충실성",
                    "최종 LLM 프롬프트가 공식 템플릿, 계약 버전, 해시, 섹션, 정책 규칙, 토큰 예산을 지키는지 확인합니다.",
                    "프롬프트 계약이나 원문 추적성이 깨지면 보증서가 실제 LLM 입력을 대표한다고 말할 수 없습니다.",
                    "프롬프트 거버넌스 단계에서 템플릿, 조립, 압축, 릴리스 정보를 보증 가능한 버전으로 정리하십시오.",
                    "재검증 시 프롬프트 계약 위반이 없고 원문과 최종 프롬프트의 추적성이 확인되어야 합니다.")),
            Map.entry("MTR", new MetricNarrative(
                    "검사 추적성",
                    "요청 증거, 공식검사 실행, 보증서, 문제 해결 건이 하나의 추적 체인으로 연결되는지 확인합니다.",
                    "추적 체인이 끊기면 감사 보고서와 재검증에서 같은 사실을 재현할 수 없습니다.",
                    "문제 해결 공정과 공식검사 원장이 packageId, aggregateRunId, officialRunId, 보증서, 문제 건을 함께 추적하도록 연결하십시오.",
                    "재검증 시 packageId에서 공식검사 실행, 보증서, 문제 해결 건을 모두 역추적할 수 있어야 합니다.")),
            Map.entry("COR", new MetricNarrative(
                    "컨텍스트 오염 방지",
                    "다른 사용자, 다른 테넌트, 다른 목적, 권한 없는 문서 또는 테스트 경로가 최종 컨텍스트에 섞이지 않았는지 확인합니다.",
                    "오염된 컨텍스트가 포함되면 권한 범위 밖의 정보가 LLM 판단 근거가 될 수 있습니다.",
                    "문제 해결 단계에서 검색 결과의 테넌트, 사용자, 리소스, 목적 범위 검증 근거를 보강하십시오.",
                    "재검증 시 권한 범위 밖 문서와 테스트 경로가 최종 프롬프트에 포함되지 않아야 합니다.")),
            Map.entry("RAP", new MetricNarrative(
                    "검색 문서 권한 정합성",
                    "최종 프롬프트에 포함된 검색 문서가 현재 사용자와 리소스 기준으로 허용된 문서인지 확인합니다.",
                    "권한 근거가 없는 문서가 포함되면 프롬프트 품질 보증이 권한 검증을 우회하는 결과가 됩니다.",
                    "문제 해결 단계에서 문서별 허용 근거와 권한 범위 메타데이터를 보강하십시오.",
                    "재검증 시 최종 컨텍스트 문서마다 허용 사유와 권한 범위가 확인되어야 합니다.")),
            Map.entry("RPI", new MetricNarrative(
                    "라운드 진행 일관성",
                    "반복 요청과 재검증 과정에서 이전 라운드의 핵심 사실이 사라지거나 되돌아가지 않았는지 확인합니다.",
                    "라운드 간 사실이 후퇴하면 재검증이 실제 개선인지 우연한 결과인지 구분할 수 없습니다.",
                    "문제 해결 단계에서 이전 증거, 학습 컨텍스트, 재검증 실행 경로가 같은 기준으로 비교되도록 연결하십시오.",
                    "재검증 시 이전 라운드와 현재 라운드의 핵심 사실 차이가 설명 가능해야 합니다.")),
            Map.entry("BMA", new MetricNarrative(
                    "기준선 성숙도",
                    "사용자 기준선이 실제 관찰 일수, 이벤트 수, 커버리지, fallback 비율에 맞게 성숙도로 표현되는지 확인합니다.",
                    "미성숙한 기준선을 완성된 기준선처럼 표현하면 프롬프트가 정상과 예외 판단 근거를 과장합니다.",
                    "문제 해결 단계에서 학습 컨텍스트와 기준선 계산 결과에 관찰 깊이와 임시 상태 사유를 보강하십시오.",
                    "재검증 시 기준선 성숙도와 관찰 근거가 일치하고 과장 표시가 없어야 합니다.")),
            Map.entry("USNS", new MetricNarrative(
                    "사용자별 변화 신호",
                    "시간, 네트워크, 브라우저, 장치, 요청 조합이 개인 기준선과 다른 경우 그 신호가 프롬프트에 반영되는지 확인합니다.",
                    "개인 기준선 변화가 누락되면 LLM은 예외 요청을 일반 요청처럼 해석할 수 있습니다.",
                    "문제 해결 단계에서 사용자 기준선 변화 신호를 같은 이름과 의미로 프롬프트에 반영하십시오.",
                    "재검증 시 기준선 변화와 비교 불가 사유가 최종 프롬프트에 명시되어야 합니다.")),
            Map.entry("BSR", new MetricNarrative(
                    "행동 변화 설명",
                    "세션 흐름, 마찰, 급격한 전환 같은 행동 변화가 프롬프트 안에서 판단 가능한 맥락으로 설명되는지 확인합니다.",
                    "행동 변화 설명이 없으면 프롬프트는 위험 신호와 정상 예외를 구분할 근거를 잃습니다.",
                    "문제 해결 단계에서 행동 변화 신호와 예외 사유를 세션 설명으로 보강하십시오.",
                    "재검증 시 행동 변화 신호와 그 의미가 최종 프롬프트에 설명되어야 합니다.")),
            Map.entry("PRE", new MetricNarrative(
                    "보호 리소스 적격성",
                    "보증서 발급 대상이 실제 @Protectable 리소스이며 템플릿 값과 실제 요청 값이 정확히 분리되어 매핑되는지 확인합니다.",
                    "템플릿 리소스를 실제 리소스로 오인하면 보증서가 잘못된 대상에 발급될 수 있습니다.",
                    "문제 해결 단계에서 @Protectable 템플릿 값과 실제 요청 값을 분리해 저장하고 보증 대상 매핑을 확정하십시오.",
                    "재검증 시 템플릿 리소스와 실제 리소스가 분리되어 있고 URL 변수 매핑이 확인되어야 합니다."))
    );

    public Map<String, OfficialMetricEvaluationResult> enrichResults(
            Map<String, OfficialMetricEvaluationResult> rawResults,
            SealedEvidencePackage evidencePackage,
            String requestPath) {
        if (rawResults == null || rawResults.isEmpty()) {
            return Map.of();
        }
        Map<String, OfficialMetricEvaluationResult> enriched = new LinkedHashMap<>();
        rawResults.forEach((key, result) -> {
            if (result == null) {
                return;
            }
            String metricCode = normalize(result.metricCode());
            if (!StringUtils.hasText(metricCode)) {
                metricCode = normalize(key);
            }
            String finalMetricCode = metricCode;
            List<OfficialMetricCheckObservation> checks = result.checks() == null
                    ? List.of()
                    : result.checks().stream()
                    .map(check -> enrichCheck(finalMetricCode, check, evidencePackage, requestPath))
                    .toList();
            enriched.put(finalMetricCode, new OfficialMetricEvaluationResult(
                    finalMetricCode,
                    result.score(),
                    result.passedChecks(),
                    result.totalChecks(),
                    result.state(),
                    checks));
        });
        return Map.copyOf(enriched);
    }

    public String metricName(String metricCode) {
        return metric(metricCode).name();
    }

    public String metricPurpose(String metricCode) {
        return metric(metricCode).purpose();
    }

    public String metricImpact(String metricCode) {
        return metric(metricCode).impact();
    }

    public String metricDefaultAction(String metricCode) {
        return metric(metricCode).action();
    }

    public String metricDefaultReverify(String metricCode) {
        return metric(metricCode).reverify();
    }

    public static boolean hasPlainOperatorText(String value) {
        return StringUtils.hasText(value)
                && containsHangul(value)
                && !containsBrokenText(value)
                && !containsInternalOnlyText(value);
    }

    public static boolean containsBrokenText(String value) {
        if (value == null) {
            return false;
        }
        return value.contains("\uFFFD")
                || containsQuestionMarkBeforeHangul(value)
                || containsUnexpectedCjkScript(value);
    }

    public static boolean containsInternalOnlyText(String value) {
        if (value == null) {
            return false;
        }
        String text = value.trim();
        String lower = text.toLowerCase(Locale.ROOT);
        return lower.contains("core official sealed evidence metric")
                || lower.contains("threshold_failed")
                || lower.contains("required prompt evidence is missing")
                || lower.contains("finding-eir")
                || lower.contains("agg-source")
                || lower.contains("run-eir-source")
                || lower.contains("pkg-source")
                || lower.contains("cert-source")
                || lower.contains("case-source")
                || lower.contains("issue-eir")
                || lower.equals("success")
                || lower.equals("missing")
                || lower.equals("insufficient")
                || lower.equals("not_applicable")
                || lower.equals("present")
                || lower.equals("absent")
                || lower.equals("unknown")
                || lower.equals("blank")
                || lower.equals("mismatch")
                || lower.startsWith("sealedevidence.")
                || lower.startsWith("source");
    }

    private OfficialMetricCheckObservation enrichCheck(
            String metricCode,
            OfficialMetricCheckObservation check,
            SealedEvidencePackage evidencePackage,
            String requestPath) {
        if (check == null) {
            throw new IllegalStateException("Official metric narrative cannot enrich a null check. metricCode="
                    + metricCode);
        }
        MetricNarrative metric = metric(metricCode);
        CheckNarrative checkNarrative = checkNarrative(metricCode, check, metric);
        String subject = checkNarrative.subject();
        String generatedExpected = "기준: " + subject + " 항목은 " + operatorValue(check.expectedValue()) + " 상태여야 합니다.";
        String generatedActual = check.passed()
                ? "확인 결과: " + subject + " 항목은 기준을 충족했습니다. 확인값은 " + operatorValue(check.actualValue()) + "입니다."
                : "확인 결과: " + subject + " 항목은 기준을 충족하지 못했습니다. 확인값은 " + operatorValue(check.actualValue()) + "입니다.";
        String generatedLabel = check.passed()
                ? subject + " 확인 완료"
                : subject + " 보강 필요";
        String owner = checkNarrative.owner();
        String evidenceLocation = evidenceLocation(check.source(), requestPath);
        String generatedReason = check.passed()
                ? "공식검사는 packageId " + value(evidencePackage == null ? null : evidencePackage.getPackageId())
                + "의 실제 요청 증거에서 " + metric.name() + " 기준을 확인했습니다. 근거 위치는 "
                + evidenceLocation + "이며 현재 항목은 보증 판단 근거로 사용할 수 있습니다."
                : "문제: " + subject + " 항목이 공식 기준을 충족하지 못했습니다. 원인: "
                + checkNarrative.cause() + " 근거 위치는 " + evidenceLocation + "입니다. 대상은 "
                + owner + "입니다.";
        String generatedNextAction = check.passed()
                ? "조치: 추가 보강 없이 같은 기준으로 감사와 재검증 근거에 사용할 수 있습니다."
                : "조치: " + checkNarrative.action();
        String generatedReverify = check.passed()
                ? "재검증 기준: 새 요청 증거에서도 " + subject + " 항목이 같은 기준으로 확인되면 통과 상태를 유지합니다."
                : "재검증 기준: " + checkNarrative.reverify();

        return new OfficialMetricCheckObservation(
                check.checkCode(),
                firstText(check.label(), generatedLabel),
                firstText(check.expectedValue(), generatedExpected),
                firstText(check.actualValue(), generatedActual),
                check.passed(),
                check.source(),
                check.passed() ? "INFO" : safe(check.severity(), "BLOCKING"),
                check.passed() ? "" : safe(check.failureType(), metricCode + "_CHECK_FAILED"),
                owner,
                firstText(check.operatorReason(), generatedReason),
                firstText(check.nextAction(), generatedNextAction),
                firstText(check.reverifyCriterion(), generatedReverify),
                check.issueKey(),
                check.customerVisible(),
                check.readinessScope(),
                check.purposeVersion(),
                check.inputReadinessState(),
                check.purposeResult(),
                check.detectedSignalsJson(),
                check.interpretationLinksJson(),
                check.decisionUtility(),
                check.whyItMatters());
    }

    private CheckNarrative checkNarrative(
            String metricCode,
            OfficialMetricCheckObservation check,
            MetricNarrative metric) {
        String code = normalize(check.checkCode());
        String source = normalize(check.source());
        if (source.contains("BASELINESNAPSHOT.COVERAGE") || code.contains("BMA_COVERAGE")) {
            return new CheckNarrative(
                    "기준선 관찰 범위",
                    "학습 기준선 생산자",
                    "현재 요청을 정상 기준선과 비교할 때 필요한 시간, 네트워크, 브라우저, 리소스 관찰 범위가 저장되지 않았습니다.",
                    "문제 해결 단계에서 학습 기준선 보강 작업을 생성하고 시간, 네트워크, 브라우저, 리소스별 관찰 범위를 기준선 스냅샷과 최종 프롬프트에 반영하십시오.",
                    "다음 요청 증거에서 기준선 관찰 범위 값이 저장되고 기준선 성숙도 지표가 통과해야 합니다.");
        }
        if (source.contains("BASELINESNAPSHOT.OBSERVATION") || code.contains("OBSERVATION_DAYS")) {
            return new CheckNarrative(
                    "기준선 관찰 기간",
                    "학습 기준선 생산자",
                    "사용자의 기준선이 며칠 동안 관찰된 데이터에서 계산됐는지 저장되지 않았습니다.",
                    "문제 해결 단계에서 기준선 관찰 기간을 보강하고 사용자별 관찰 일수와 계산 시점을 기준선 스냅샷에 반영하십시오.",
                    "다음 요청 증거에서 관찰 일수가 숫자로 저장되고 공식 지표가 통과해야 합니다.");
        }
        if (source.contains("BASELINESNAPSHOT.EVENTCOUNT") || code.contains("EVENT_COUNT")) {
            return new CheckNarrative(
                    "기준선 관찰 건수",
                    "학습 기준선 생산자",
                    "기준선이 몇 건의 실제 요청 관찰에서 계산됐는지 저장되지 않았습니다.",
                    "문제 해결 단계에서 기준선 관찰 건수를 보강하고 사용자별 이벤트 수와 표본 크기를 기준선 계산 결과에 반영하십시오.",
                    "다음 요청 증거에서 관찰 건수가 숫자로 저장되고 공식 지표가 통과해야 합니다.");
        }
        if (source.contains("BASELINESNAPSHOT.FALLBACK") || code.contains("FALLBACK")) {
            return new CheckNarrative(
                    "기준선 기본값 의존 비율",
                    "학습 기준선 생산자",
                    "기준선이 실제 관찰값이 아니라 기본값에 얼마나 의존했는지 저장되지 않았습니다.",
                    "문제 해결 단계에서 fallback 비율을 보강하고 임시 기준선과 확정 기준선을 분리해 표시하십시오.",
                    "다음 요청 증거에서 fallback 비율이 저장되고 허용 범위 안에 있어야 합니다.");
        }
        if (source.contains("BASELINESNAPSHOT.PROVISIONAL") || code.contains("PROVISIONAL")) {
            return new CheckNarrative(
                    "임시 기준선 사유",
                    "학습 기준선 생산자",
                    "기준선이 임시 상태인 이유가 저장되지 않아 학습 부족과 프롬프트 결함을 구분할 수 없습니다.",
                    "문제 해결 단계에서 임시 기준선 사유를 등록하고 관찰 부족, 신규 사용자, 신규 조합 여부를 최종 프롬프트에 반영하십시오.",
                    "다음 요청 증거에서 임시 기준선 사유가 저장되고 공식 지표가 통과해야 합니다.");
        }
        if (source.contains("BASELINESNAPSHOT.MATURITY") || code.contains("MATURITY") || source.equals("SEALEDEVIDENCE.BASELINESNAPSHOT")) {
            return new CheckNarrative(
                    "기준선 성숙도",
                    "학습 기준선 생산자",
                    "기준선 상태가 실제 관찰량, 관찰 범위, 기본값 의존 비율과 맞는지 입증되지 않았습니다.",
                    "문제 해결 단계에서 기준선 성숙도 산정 근거를 보강하고 관찰 일수, 관찰 건수, 관찰 범위, fallback 비율을 하나의 기준선 스냅샷으로 묶으십시오.",
                    "다음 요청 증거에서 기준선 상태와 관찰 근거가 같은 수준으로 확인되어야 합니다.");
        }
        if (source.contains("RAGRESULTS") || source.contains("RELATEDDOCUMENTS") || code.contains("RAP_DOC")) {
            return new CheckNarrative(
                    "검색 문서 권한 근거",
                    "검색 문서 권한 필터",
                    "최종 프롬프트에 들어간 검색 문서마다 현재 사용자가 접근할 수 있다는 권한 근거가 충분히 저장되지 않았습니다.",
                    "문제 해결 단계에서 검색 문서 권한 근거를 보강하고 문서별 권한 판정, 권한 범위, 최종 포함 여부를 프롬프트 입력 근거로 확정하십시오.",
                    "다음 요청 증거에서 최종 포함 문서마다 권한 허용 사유와 권한 범위가 확인되어야 합니다.");
        }
        if (source.contains("PROMPTEXECUTIONMETADATA.PROMPTCONTRACTVIOLATIONCOUNT") || code.contains("CONTRACT")) {
            return new CheckNarrative(
                    "프롬프트 계약 위반",
                    "프롬프트 거버넌스 저장소",
                    "최종 프롬프트가 공식 템플릿과 계약 규칙을 위반한 항목을 가지고 있습니다.",
                    "프롬프트 거버넌스 단계에서 템플릿 계약 위반 항목을 정리하고 위반 수가 0인 프롬프트 버전을 승격하십시오.",
                    "다음 요청 증거에서 프롬프트 계약 위반 수가 0으로 저장되어야 합니다.");
        }
        if (source.contains("PROMPTEXECUTIONMETADATA") && (code.contains("BUDGET") || source.contains("TOKEN"))) {
            return new CheckNarrative(
                    "프롬프트 토큰 예산",
                    "프롬프트 조립기",
                    "최종 프롬프트가 허용된 토큰 예산을 넘었거나 예산 계산 근거가 저장되지 않았습니다.",
                    "프롬프트 거버넌스 단계에서 섹션별 토큰 사용량을 조정하고 예산 계산 결과를 봉인 증거에 저장하십시오.",
                    "다음 요청 증거에서 토큰 예산 초과가 없어야 합니다.");
        }
        if (source.contains("CANONICALCONTEXT.FRICTIONPROFILE") || code.contains("FRICTION")) {
            return new CheckNarrative(
                    "행동 마찰 설명",
                    "행동 컨텍스트 생산자",
                    "세션 흐름에서 추가 확인, 지연, 반복 시도 같은 마찰 신호가 설명 가능한 컨텍스트로 저장되지 않았습니다.",
                    "문제 해결 단계에서 행동 마찰 프로필을 보강하고 해당 신호가 정상 예외인지 위험 신호인지 설명한 뒤 최종 프롬프트에 반영하십시오.",
                    "다음 요청 증거에서 행동 마찰 프로필과 설명 문장이 함께 저장되고 행동 변화 설명 지표가 통과해야 합니다.");
        }
        if (source.contains("CANONICALCONTEXT.BEHAVIORALSURPRISE") || code.contains("SURPRISE")) {
            return new CheckNarrative(
                    "행동 변화 신호 설명",
                    "행동 컨텍스트 생산자",
                    "평소 세션 흐름과 다른 행동 변화 신호가 최종 프롬프트에서 해석 가능한 문장으로 설명되지 않았습니다.",
                    "문제 해결 단계에서 행동 변화 신호와 예외 사유를 보강하고 세션 설명 생성 결과를 최종 프롬프트에 반영하십시오.",
                    "다음 요청 증거에서 행동 변화 신호, 예외 사유, 최종 프롬프트 설명이 같은 의미로 확인되어야 합니다.");
        }
        if (code.contains("EXPLICIT_MISSING_KNOWLEDGE")) {
            return new CheckNarrative(
                    "필수 컨텍스트 부족 선언",
                    "컨텍스트 조립기",
                    "프롬프트가 필요한 컨텍스트가 부족하다고 직접 선언하고 있어 보증서 발급 전에 공백을 분리해야 합니다.",
                    "문제 해결 단계에서 부족한 컨텍스트 생산자를 지정하고 허용 가능한 학습 공백인지 보강해야 할 결함인지 확정하십시오.",
                    "재검증 시 필수 컨텍스트 부족 선언이 사라지거나 허용 가능한 공백으로 분류되어야 합니다.");
        }
        if (code.contains("UNCERTAINTY_MARKER")) {
            return new CheckNarrative(
                    "불확실성 표식",
                    "컨텍스트 조립기",
                    "프롬프트 입력에 알 수 없음 또는 근거 부족 표식이 남아 있어 어떤 사실이 확정되지 않았는지 분리해야 합니다.",
                    "문제 해결 단계에서 알 수 없음 또는 근거 부족으로 남은 필드를 분해하고 각 필드를 보강, 예외 승인, 학습 대기 중 하나로 분류하십시오.",
                    "재검증 시 불확실성 표식이 제거되거나 허용 가능한 운영 상태로 분류되어야 합니다.");
        }
        if (code.contains("PROVISIONAL_MARKER")) {
            return new CheckNarrative(
                    "임시 근거 과장 방지",
                    "학습 기준선 생산자",
                    "임시 또는 학습 중 근거가 확정된 근거처럼 프롬프트에 표현될 수 있습니다.",
                    "문제 해결 단계에서 임시 근거를 확정 근거와 분리하고 학습 중 상태와 사유를 프롬프트에 명확히 표시하십시오.",
                    "재검증 시 임시 근거가 확정 근거처럼 표현되지 않아야 합니다.");
        }
        String subject = subject(metricCode, check.checkCode(), check.label(), check.source());
        return new CheckNarrative(
                subject,
                ownerName(check.remediationOwner()),
                failureMeaning(check.failureType(), metric),
                "문제 해결 단계에서 " + ownerName(check.remediationOwner()) + "의 " + subject
                        + " 근거를 보강하고 최종 프롬프트와 봉인 증거에 같은 의미로 반영하십시오.",
                "같은 packageId로 공식검사를 다시 실행했을 때 " + subject
                        + " 항목의 확인 결과가 기준 충족으로 저장되어야 합니다. " + metric.reverify());
    }

    private MetricNarrative metric(String metricCode) {
        return METRICS.getOrDefault(normalize(metricCode), new MetricNarrative(
                "공식 검사 지표",
                "공식검사 지표가 요구하는 증거와 프롬프트 조건을 확인합니다.",
                "이 지표가 실패하면 프롬프트 품질 보증서 발급 근거가 부족합니다.",
                "문제 해결 단계에서 실패 체크의 증거 생산자와 프롬프트 조립 경로를 보강하십시오.",
                "재검증 시 실패 체크가 통과 상태로 저장되어야 합니다."));
    }

    private String subject(String metricCode, String checkCode, String fallback, String source) {
        String code = normalize(checkCode);
        String sourceText = normalize(source);
        if (sourceText.contains("BASELINESNAPSHOT") || code.startsWith("BMA_")) {
            if (sourceText.contains("COVERAGE") || code.contains("COVERAGE")) return "기준선 관찰 범위";
            if (sourceText.contains("OBSERVATION") || code.contains("OBSERVATION_DAYS")) return "기준선 관찰 기간";
            if (sourceText.contains("EVENTCOUNT") || code.contains("EVENT_COUNT")) return "기준선 관찰 건수";
            if (sourceText.contains("FALLBACK") || code.contains("FALLBACK")) return "기준선 기본값 의존 비율";
            if (sourceText.contains("PROVISIONAL") || code.contains("PROVISIONAL")) return "임시 기준선 사유";
            return "기준선 성숙도";
        }
        if (sourceText.contains("RAGRESULTS") || sourceText.contains("RELATEDDOCUMENTS")) {
            return "검색 문서 권한 근거";
        }
        if (code.contains("MFA")) return "MFA 인증 상태 반영";
        if (code.contains("AUTHORIZATION_EFFECT")) return "권한 판정 상태 반영";
        if (code.contains("AUTH_METHOD")) return "인증 방식 반영";
        if (code.contains("EFFECTIVE_ROLE")) return "유효 역할 목록 반영";
        if (code.contains("TENANT")) return "테넌트 식별자 반영";
        if (code.contains("FINAL_USER_PROMPT_NOT_COMPACTED") || code.contains("FINAL_PROMPT_COMPACTED")) {
            return "최종 프롬프트 축약 표식 제거";
        }
        if (code.contains("FINAL_USER_PROMPT_NO_TRUNCATED_FACT_PLACEHOLDER")
                || code.contains("FINAL_PROMPT_TRUNCATED_FACT")) {
            return "잘린 판단 근거 제거";
        }
        if (code.contains("USER_PROMPT_HAS_DECISION_CONTEXT")) return "사용자 프롬프트 판단 맥락";
        if (code.contains("USER") && !code.contains("NEW_USER")) return "사용자 식별자 반영";
        if (code.contains("CLIENT_IP")) return "클라이언트 IP 반영";
        if (code.contains("HTTP_METHOD")) return "HTTP 메서드 반영";
        if (code.contains("REQUEST_PATH")) return "실제 요청 URL 반영";
        if (code.contains("RESOURCE_ID") || code.contains("ACTUAL_RESOURCE")) return "실제 리소스 식별자 반영";
        if (code.contains("URL_TEMPLATE")) return "보호 리소스 URL 템플릿 매핑";
        if (code.contains("PROMPT_HASH")) return "프롬프트 해시 추적";
        if (code.contains("SYSTEM_PROMPT")) return "시스템 프롬프트 캡처";
        if (code.contains("USER_PROMPT")) return "사용자 프롬프트 캡처";
        if (code.contains("CONTEXT_HASH")) return "컨텍스트 해시 상태";
        if (code.contains("PACKAGE_HASH") || code.contains("PACKAGE_ID")) return "봉인 증거 패키지 추적";
        if (code.contains("CONTRACT")) return "프롬프트 계약 준수";
        if (code.contains("BUDGET")) return "프롬프트 토큰 예산 준수";
        if (code.contains("RAW_TRUTH")) return "원시 프롬프트와 최종 프롬프트 일치성";
        if (code.contains("COMPRESSION")) return "프롬프트 압축 추적";
        if (code.contains("BASELINE") || code.contains("MATURITY") || code.contains("OBSERVATION") || code.contains("FALLBACK")) return "학습 기준선 성숙도";
        if (code.contains("RAG") || code.contains("DOCUMENT") || code.contains("DOC_")) return "검색 문서 권한 근거";
        if (code.contains("NOVELTY") || code.contains("TIME") || code.contains("NETWORK")
                || code.contains("BROWSER") || code.contains("DEVICE") || code.contains("REQUEST_COMBINATION")) {
            return "사용자 기준선 변화 신호";
        }
        if (code.contains("FRICTION") || code.contains("SURPRISE") || code.contains("SESSION_NARRATIVE")) return "행동 변화 설명";
        if (code.contains("PROTECTABLE") || code.contains("VERIFICATION_REQUIRED")) return "보호 리소스 적격성";
        if (StringUtils.hasText(fallback) && !containsBrokenText(fallback) && containsHangul(fallback)) {
            return fallback.trim();
        }
        return metric(metricCode).name() + " 체크";
    }

    private String failureMeaning(String failureType, MetricNarrative metric) {
        String type = normalize(failureType);
        if (type.contains("MISSING")) {
            return "필수 증거가 없거나 최종 프롬프트에 반영되지 않았습니다.";
        }
        if (type.contains("MISMATCH")) {
            return "봉인 증거와 최종 프롬프트 또는 공식 원장에 서로 다른 값이 저장되어 있습니다.";
        }
        if (type.contains("CONTAMINATION") || type.contains("FOREIGN") || type.contains("UNAUTHORIZED")) {
            return "권한 범위 밖의 컨텍스트가 최종 판단 근거에 섞일 수 있습니다.";
        }
        if (type.contains("OVERCLAIMED") || type.contains("INSUFFICIENT")) {
            return "관찰 근거보다 높은 신뢰도 또는 성숙도를 주장하고 있습니다.";
        }
        if (type.contains("BLOCKER") || type.contains("VIOLATION")) {
            return "프롬프트 계약상 보증서 발급을 차단해야 하는 조건이 발견되었습니다.";
        }
        return metric.purpose();
    }

    private String ownerName(String owner) {
        String normalized = normalize(owner);
        if (normalized.contains("PROMPT_ASSEMBLER")) return "프롬프트 조립기";
        if (normalized.contains("REQUEST_CONTEXT")) return "요청 컨텍스트 생산자";
        if (normalized.contains("AUTH_CONTEXT")) return "인증 및 권한 컨텍스트 생산자";
        if (normalized.contains("CONTEXT_ASSEMBLER")) return "컨텍스트 조립기";
        if (normalized.contains("PROMPT_CAPTURE")) return "프롬프트 캡처기";
        if (normalized.contains("PROMPT_TEMPLATE")) return "프롬프트 템플릿";
        if (normalized.contains("PROMPT_GOVERNANCE")) return "프롬프트 거버넌스 저장소";
        if (normalized.contains("EVIDENCE")) return "봉인 증거 저장기";
        if (normalized.contains("RAG")) return "RAG 검색 권한 필터";
        if (normalized.contains("LEARNING") || normalized.contains("BASELINE")) return "학습 기준선 생산자";
        if (normalized.contains("BEHAVIOR")) return "행동 컨텍스트 생산자";
        if (normalized.contains("PROTECTABLE")) return "보호 리소스 메타데이터";
        if (normalized.contains("OFFICIAL_LEDGER")) return "공식검사 원장 저장기";
        if (!StringUtils.hasText(owner)) return "공식검사 통합 책임";
        return owner.trim();
    }

    private String operatorValue(String value) {
        if (!StringUtils.hasText(value)) {
            return "값 없음";
        }
        String trimmed = value.trim();
        String lower = trimmed.toLowerCase(Locale.ROOT);
        if (lower.contains("coverage values")) return "시간, 네트워크, 브라우저, 리소스 관찰 범위 값이 저장됨";
        if (lower.contains("observationdays")) return "관찰 일수가 숫자로 저장됨";
        if (lower.contains("eventcount")) return "관찰 건수가 숫자로 저장됨";
        if (lower.contains("fallbackratio")) return "기본값 의존 비율이 저장됨";
        if (lower.contains("authorizationdecision")) return "문서별 권한 판정이 저장됨";
        if (lower.contains("permissionscope")) return "문서별 권한 범위가 저장됨";
        return switch (lower) {
            case "present" -> "값이 존재함";
            case "missing" -> "값이 없음";
            case "absent" -> "값이 없음";
            case "blank" -> "빈 값";
            case "unknown" -> "확인 불가";
            case "true" -> "참";
            case "false" -> "거짓";
            case "success" -> "성공";
            case "threshold_failed" -> "기준 미달";
            case "mismatch" -> "불일치";
            case "not_applicable" -> "적용 대상 아님";
            case "insufficient" -> "근거 부족";
            default -> trimmed;
        };
    }

    private String evidenceLocation(String source, String requestPath) {
        if (StringUtils.hasText(source)) {
            String normalized = normalize(source);
            if (normalized.contains("BASELINESNAPSHOT.COVERAGE")) return "봉인 증거의 기준선 관찰 범위 영역";
            if (normalized.contains("BASELINESNAPSHOT.OBSERVATION")) return "봉인 증거의 기준선 관찰 기간 영역";
            if (normalized.contains("BASELINESNAPSHOT.EVENTCOUNT")) return "봉인 증거의 기준선 관찰 건수 영역";
            if (normalized.contains("BASELINESNAPSHOT.FALLBACK")) return "봉인 증거의 기준선 기본값 의존 비율 영역";
            if (normalized.contains("BASELINESNAPSHOT.PROVISIONAL")) return "봉인 증거의 임시 기준선 사유 영역";
            if (normalized.contains("BASELINESNAPSHOT")) return "봉인 증거의 학습 기준선 영역";
            if (normalized.contains("RAGRESULTS") || normalized.contains("RELATEDDOCUMENTS")) return "봉인 증거의 검색 문서 권한 영역";
            if (normalized.contains("AUTHSTATE")) return "봉인 증거의 인증 및 권한 상태 영역";
            if (normalized.contains("REQUESTFACTS")) return "봉인 증거의 요청 사실 영역";
            if (normalized.contains("PROMPTEXECUTIONMETADATA")) return "봉인 증거의 프롬프트 실행 메타데이터 영역";
            if (normalized.contains("USERPROMPTTEXT") || normalized.contains("SYSTEMPROMPTTEXT")) return "최종 프롬프트 캡처 영역";
            if (normalized.contains("PROTECTABLERESOURCE") || normalized.contains("RESOURCE")) return "보호 리소스 메타데이터 영역";
            return "봉인 증거";
        }
        if (StringUtils.hasText(requestPath)) {
            return "요청 경로 " + requestPath.trim();
        }
        return "봉인 증거";
    }

    private static boolean containsHangul(String value) {
        if (value == null) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            if (isHangul(value.charAt(i))) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsUnexpectedCjkScript(String value) {
        for (int i = 0; i < value.length(); i++) {
            Character.UnicodeScript script = Character.UnicodeScript.of(value.charAt(i));
            if (script == Character.UnicodeScript.HAN
                    || script == Character.UnicodeScript.HIRAGANA
                    || script == Character.UnicodeScript.KATAKANA) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsQuestionMarkBeforeHangul(String value) {
        for (int i = 0; i < value.length() - 1; i++) {
            if (value.charAt(i) == '?' && isHangul(value.charAt(i + 1))) {
                return true;
            }
        }
        return false;
    }

    private static boolean isHangul(char ch) {
        return ch >= 0xAC00 && ch <= 0xD7A3;
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private String firstText(String value, String fallback) {
        return StringUtils.hasText(value) ? value.trim() : fallback;
    }

    private String safe(String value, String fallback) {
        return StringUtils.hasText(value) ? value.trim() : fallback;
    }

    private String value(String value) {
        return StringUtils.hasText(value) ? value.trim() : "확인 불가";
    }

    private record MetricNarrative(
            String name,
            String purpose,
            String impact,
            String action,
            String reverify) {
    }

    private record CheckNarrative(
            String subject,
            String owner,
            String cause,
            String action,
            String reverify) {
    }
}
