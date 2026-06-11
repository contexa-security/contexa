package io.contexa.contexaiam.admin.verification.service.resource;

import io.contexa.contexacore.verification.metric.OfficialVerificationMetricDefinition;
import io.contexa.contexaiam.admin.verification.service.resource.PromptQualityCertificateService.SixWReport;
import org.springframework.util.StringUtils;

import java.util.Locale;

final class PromptQualityCertificateNarrative {

    private PromptQualityCertificateNarrative() {
    }

    static SixWReport sixW(String generatedAt, String resourceUrl, String userId, boolean issued) {
        return new SixWReport(
                valueOrDefault(generatedAt, "검증 시각 없음"),
                valueOrDefault(resourceUrl, "검증 대상 URL 없음"),
                valueOrDefault(userId, "unknown"),
                "LLM 기반 제로트러스트에 투입할 보호 리소스의 프롬프트 품질을 검증했습니다.",
                "공식검증기가 같은 URL 범위에서 11개 프롬프트·컨텍스트 지표와 PRE 리소스 적격성 지표를 실행하고 증거를 대조했습니다.",
                "LLM이 누락, 축소, 오염, 불일치가 있는 요청/학습 컨텍스트를 근거로 판단하지 않도록 사전에 차단하기 위해서입니다.",
                issued
                        ? "12개 프롬프트 품질 지표와 @Protectable 리소스 적격성을 모두 통과했습니다. 해당 URL은 검증된 범위 안에서 LLM 제로트러스트 입력 후보로 사용할 수 있습니다."
                        : "통과하지 못한 지표 또는 리소스 적격성 문제가 남아 있습니다. 해당 URL은 해결 전까지 LLM 제로트러스트 입력으로 승격할 수 없습니다."
        );
    }

    static String certificateSummary(boolean issued) {
        return issued
                ? "공식검증기 기준 12개 프롬프트 품질 지표가 모두 통과했습니다. 이 보증서는 검증된 URL, HTTP method, resourceId 범위에서만 유효합니다."
                : "공식검증기 기준 미통과, 미실행, 실행 실패 또는 @Protectable 적격성 문제가 있어 보증서를 발급하지 않았습니다.";
    }

    static String noBlockingFinding() {
        return "차단 증상 없음";
    }

    static String issueRequiredOutcome() {
        return "12개 프롬프트 품질 지표가 같은 보증서 스코프에서 모두 통과해야 합니다.";
    }

    static String issueCause(String state) {
        return "ISSUED".equalsIgnoreCase(state)
                ? "모든 지표가 통과했습니다."
                : "하나 이상의 지표가 통과하지 못했습니다.";
    }

    static String remediationSummary(boolean passed) {
        return passed
                ? "12개 프롬프트 품질 지표가 통과되어 추가 해결 조치가 없습니다."
                : "차단 사유를 수정한 뒤 같은 보증서 스코프로 공식검증기를 다시 실행해야 합니다.";
    }

    static String reverifyCriteria() {
        return "tenant/resourceUrl/httpMethod/resourceId/promptContractVersion/modelProfile/verifierVersion이 같은 조건에서 12개 프롬프트 품질 지표를 다시 실행해야 합니다.";
    }

    static String metricExecutionFailureSummary(String failureMessage) {
        return "지표 실행 중 오류가 발생했습니다. 실행 상태 원장에서 실패 단계와 재시도 안내를 확인해야 합니다.";
    }

    static String metricExecutionFailureAction() {
        return "실행 오류를 먼저 해결한 뒤 같은 URL과 같은 조건으로 공식검증기를 다시 실행해야 합니다.";
    }

    static String metricExecutionFailureCause() {
        return "공식 지표 실행 오류";
    }

    static String metricExecutionFailureRemediation() {
        return "실행 오류를 제거하고 같은 URL/method/resourceId로 재검증하십시오.";
    }

    static String metricMissingSummary() {
        return "해당 지표의 실행 증거가 없습니다.";
    }

    static String metricMissingAction() {
        return "공식검증기에서 이 지표를 실행하고 requestId가 같은 증거로 연결되는지 확인해야 합니다.";
    }

    static String metricMissingCause() {
        return "지표 실행 증거 누락";
    }

    static String metricMissingRemediation() {
        return "누락 지표를 실행하고 동일 requestId 증거 계보에 연결하십시오.";
    }

    static String metricVerifiedSummary() {
        return "통과했습니다. 이 지표가 요구하는 증거와 체크가 같은 URL 범위에서 충족되었습니다.";
    }

    static String metricVerifiedAction() {
        return "추가 조치는 필요하지 않습니다. 운영 투입 전 12개 프롬프트 품질 지표 전체가 모두 통과했는지 확인해야 합니다.";
    }

    static String metricFailedAction() {
        return "지표 상세 보고서에서 연결된 문제를 확인하고 요청 컨텍스트, 학습 컨텍스트, 프롬프트 생성부를 수정한 뒤 같은 URL로 재검증해야 합니다.";
    }

    static String metricVerifiedCause() {
        return "지표 기준 충족";
    }

    static String metricFailedCause() {
        return "지표 기준 미충족";
    }

    static String metricVerifiedRemediation() {
        return "같은 범위의 보증서 스코프와 증거 계보를 유지하십시오.";
    }

    static String metricFailedRemediation() {
        return "연결된 문제를 만든 데이터 생산자와 전달 경로를 수정하고 동일 조건으로 재검증하십시오.";
    }

    static String metricImpact(boolean verified) {
        return verified
                ? "이 지표는 현재 보증서 발급을 막지 않습니다."
                : "이 지표가 해결될 때까지 해당 URL은 LLM 제로트러스트 운영 투입 대상이 될 수 없습니다.";
    }

    static String metricReverify(boolean verified) {
        return verified
                ? "프롬프트, 학습계약, 모델 프로파일, @Protectable 선언이 바뀌면 다시 검증해야 합니다."
                : "같은 tenant/resourceUrl/httpMethod/resourceId/modelProfile/verifierVersion으로 12개 프롬프트 품질 지표를 다시 실행해야 합니다.";
    }

    static String noExecutionEvidence() {
        return "공식검증 실행 증거 없음";
    }

    static String ownerHint(OfficialVerificationMetricDefinition metric) {
        return switch (metric.category()) {
            case "IMPLEMENTATION_ALIGNMENT" -> "요청 컨텍스트/서버 evidence 생산부";
            case "RAG_AND_BASELINE" -> "학습 컨텍스트/RAG/기준선 생산부";
            case "BEHAVIORAL_CONTEXT" -> "행동 패턴/미세 변화 컨텍스트 생산부";
            case "LLM_DECISION" -> "최종 프롬프트/LLM 판정 evidence 생산부";
            case "RESOURCE_ELIGIBILITY" -> "@Protectable 리소스 레지스트리와 보증서 게이트";
            default -> "공식검증기 지표 실행부";
        };
    }

    static String metricFailureFallback() {
        return "실행 실패 상세 없음";
    }

    static String noRunSummary() {
        return "실행 결과가 없습니다.";
    }

    static String failedRunSummary(int passedChecks, int totalChecks, String state, double score, String message) {
        return "전체 %d개 세부 검사 중 %d개가 기준을 충족했습니다. 점수는 %.1f점이며 공식 기준을 충족하지 못했습니다. 지표 상세에서 연결된 문제의 기준과 확인 결과를 확인해야 합니다.".formatted(
                totalChecks,
                passedChecks,
                score
        );
    }

    static String protectableMissingFinding() {
        return "대상 URL과 일치하는 @Protectable 선언을 찾지 못했습니다.";
    }

    static String verificationDisabledFinding() {
        return "@Protectable은 존재하지만 공식 품질검증 필수 설정이 꺼져 있어 LLM 제로트러스트 품질보증 대상이 아닙니다.";
    }

    static String metricStateFinding(String metricCode, String state, String summary) {
        return metricDisplayName(metricCode) + " 지표가 공식 기준을 충족하지 못했습니다. " + valueOrDefault(summary, "지표 상세에서 연결된 문제의 기준과 확인 결과를 확인해야 합니다.");
    }

    static String metricExecutionFailureFinding(String metricCode, String message) {
        return metricDisplayName(metricCode) + " 지표 실행 중 오류가 발생했습니다. 실행 상태 원장에서 실패 단계와 재시도 안내를 확인해야 합니다.";
    }

    static String protectableMissingAction() {
        return "@Protectable에 resourceId, resourceUrl, httpMethod, criticality를 명시하고 실제 요청 URL과 매핑이 일치하는지 확인하십시오.";
    }

    static String verificationDisabledAction() {
        return "LLM 제로트러스트로 승격할 리소스라면 @Protectable의 공식 품질검증 필수 설정을 켜십시오.";
    }

    static String executionFailureAction() {
        return "실패한 지표의 환경 오류를 먼저 제거한 뒤 같은 URL, 같은 HTTP method, 같은 resourceId로 12개 프롬프트 품질 지표를 다시 실행하십시오.";
    }

    static String defaultSuccessAction() {
        return "보증서 발급 상태를 운영 리소스 관리 화면에 반영하고, 해당 URL을 제로트러스트 허용 리소스로 승격하십시오.";
    }

    static String metricMeaning(OfficialVerificationMetricDefinition metric) {
        return switch (normalizeMetricCode(metric.code())) {
            case "EIR" -> "브라우저와 서버 요청에서 시작된 사건 정보가 중간에 빠지거나 바뀌지 않는지 확인합니다.";
            case "CCR" -> "LLM 판정에 필요한 요청, 세션, 행동, RAG, 프롬프트 필드가 충분히 채워졌는지 확인합니다.";
            case "CCSR" -> "같은 사실이 이벤트, 컨텍스트, 프롬프트, 증거 화면에서 서로 다르게 보이지 않는지 확인합니다.";
            case "PFR" -> "최종 프롬프트가 공식 템플릿과 계약을 지키며 만들어졌는지 확인합니다.";
            case "MTR" -> "요청부터 프롬프트, 판정, 증거까지 추적 가능한 연결고리가 끊기지 않았는지 확인합니다.";
            case "COR" -> "다른 사용자, 다른 목적, 권한 밖 문서가 학습 또는 요청 컨텍스트에 섞이지 않았는지 확인합니다.";
            case "RAP" -> "RAG가 권한 있는 문서만 최종 컨텍스트로 전달했는지 확인합니다.";
            case "RPI" -> "반복 실행 과정에서 기억, 기준선, 검색 증거가 오염되거나 손상되지 않았는지 확인합니다.";
            case "BMA" -> "사용자 기준선의 성숙도가 실제 학습 깊이보다 과장되지 않았는지 확인합니다.";
            case "USNS" -> "겉으로 정상처럼 보이는 상황에서도 사용자 고유의 미세한 불일치를 감지하는지 확인합니다.";
            case "BSR" -> "행동 순서의 점프, 되돌림, 마찰 차이가 최종 판단 근거로 드러나는지 확인합니다.";
            case "PRE" -> "대상 URL이 @Protectable 선언, resourceId, HTTP method, 보증 범위를 갖춘 보호 리소스인지 확인합니다.";
            default -> metric.description();
        };
    }

    static String metricEvidenceScope(OfficialVerificationMetricDefinition metric) {
        return switch (metric.category()) {
            case "IMPLEMENTATION_ALIGNMENT" -> "요청 이벤트, 서버 컨텍스트, 프롬프트 메타데이터, sealed evidence";
            case "RAG_AND_BASELINE" -> "RAG 검색결과, 사용자 기준선, 일운영별 학습/기억 증거";
            case "BEHAVIORAL_CONTEXT" -> "사용자 행동 순서, 미세 변화, 반복 관찰 패턴";
            case "RESOURCE_ELIGIBILITY" -> "@Protectable 리소스 선언, URL, HTTP method, resourceId, 보증서 범위";
            default -> "공식검증기 실행 증거";
        };
    }

    static SixWReport emptySixW() {
        return new SixWReport("정보 없음", "정보 없음", "정보 없음", "정보 없음", "정보 없음", "정보 없음", "정보 없음");
    }

    static String emptyRemediationSummary() {
        return "해결 조치 정보가 없습니다.";
    }

    static String emptyRemediationReverifyCriteria() {
        return "같은 조건으로 재검증하십시오.";
    }

    private static String normalizeMetricCode(String metricCode) {
        return metricCode == null ? "" : metricCode.trim().toUpperCase(Locale.ROOT);
    }

    private static String metricDisplayName(String metricCode) {
        return switch (normalizeMetricCode(metricCode)) {
            case "EIR" -> "요청 사실 보존";
            case "CCR" -> "컨텍스트 완전성";
            case "CCSR" -> "컨텍스트 일관성";
            case "PFR" -> "프롬프트 충실성";
            case "MTR" -> "검사 추적성";
            case "COR" -> "컨텍스트 오염 방지";
            case "RAP" -> "검색 문서 권한 정합성";
            case "RPI" -> "라운드 진행 일관성";
            case "BMA" -> "기준선 성숙도";
            case "USNS" -> "사용자별 변화 신호";
            case "BSR" -> "행동 변화 설명";
            case "PRE" -> "보호 리소스 적격성";
            default -> "공식검사";
        };
    }

    private static String valueOrDefault(String value, String fallback) {
        return StringUtils.hasText(value) ? value.trim() : fallback;
    }
}
