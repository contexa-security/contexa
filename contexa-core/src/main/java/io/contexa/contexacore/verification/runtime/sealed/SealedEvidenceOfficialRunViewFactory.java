package io.contexa.contexacore.verification.runtime.sealed;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.metric.OfficialMetricCheckObservation;
import io.contexa.contexacore.verification.metric.OfficialMetricEvaluationResult;
import io.contexa.contexacore.verification.metric.OfficialPromptQualityMetricContractGate;
import io.contexa.contexacore.verification.metric.OfficialVerificationMetricDefinition;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

class SealedEvidenceOfficialRunViewFactory {

    SealedEvidenceOfficialRunView create(
            String aggregateRunId,
            OfficialVerificationMetricDefinition metric,
            SealedEvidencePackage evidencePackage,
            OfficialMetricEvaluationResult result,
            Map<String, String> requestFacts,
            Map<String, String> promptFacts,
            String requestPath,
            boolean integrityValid,
            String startedAt,
            String completedAt,
            Duration processingTime) {
        List<SealedEvidenceOfficialRunView.SealedEvidenceCheckView> checks = new ArrayList<>();
        if (result == null) {
            checks.add(new SealedEvidenceOfficialRunView.SealedEvidenceCheckView(
                    "OFFICIAL_METRIC_RESULT_PRESENT",
                    "공식 지표 실행 결과 생성 필요",
                    "기준: 12개 공식 지표는 각각 실행 결과와 체크 목록을 생성해야 합니다.",
                    "확인 결과: 이 지표의 실행 결과가 생성되지 않았습니다.",
                    false,
                    "internalGate.officialSealedEvidenceRuntime",
                    "BLOCKING",
                    "MISSING_METRIC_RESULT",
                    "공식검사 런타임",
                    "문제: 공식 지표 실행 결과가 저장 단계까지 전달되지 않았습니다. 원인: 지표 엔진 또는 저장 매핑이 해당 지표 결과를 만들지 못했습니다. 대상: 공식검사 런타임. 결과: 이 상태에서는 12개 지표가 완결된 검사로 인정될 수 없습니다.",
                    "조치: 같은 봉인 증거로 공식검사를 다시 실행하고, 지표 엔진과 원장 저장 매핑에서 누락된 지표 결과 생성 여부를 확인하십시오.",
                    "재검증 기준: 새 공식검사 실행에서 해당 지표의 체크 목록과 실행 결과가 생성되어야 합니다."));
        }
        else {
            safeChecks(result.checks()).forEach(check -> checks.add(new SealedEvidenceOfficialRunView.SealedEvidenceCheckView(
                    safeText(check.checkCode(), "CHECK"),
                    safeText(check.label(), "Official metric check"),
                    safeText(check.expectedValue(), "present"),
                    safeText(check.actualValue(), "missing"),
                    check.passed(),
                    safeText(check.source(), "finalUserPrompt"),
                    safeText(check.severity(), check.passed() ? "INFO" : "BLOCKING"),
                    safeText(check.failureType(), check.passed() ? "" : "OFFICIAL_CHECK_FAILED"),
                    safeText(check.remediationOwner(), "PQA_RUNTIME"),
                    safeText(check.operatorReason(), ""),
                    safeText(check.nextAction(), ""),
                    safeText(check.reverifyCriterion(), ""),
                    safeText(check.issueKey(), check.source()),
                    check.customerVisible(),
                    safeText(check.readinessScope(), check.customerVisible()
                            ? "CUSTOMER_PROMPT_QUALITY"
                            : "INTERNAL_EXECUTION_GATE"),
                    safeText(check.purposeVersion(), ""),
                    safeText(check.inputReadinessState(), "READY"),
                    safeText(check.purposeResult(), check.passed() ? "PASSED" : "FAILED"),
                    safeText(check.detectedSignalsJson(), "[]"),
                    safeText(check.interpretationLinksJson(), "[]"),
                    safeText(check.decisionUtility(), ""),
                    safeText(check.whyItMatters(), ""))));
        }
        int total = result == null ? checks.size() : result.totalChecks();
        int passed = result == null ? 0 : result.passedChecks();
        double score = result == null ? 0.0d : result.score();
        String state = safeText(result == null ? null : result.state(), "missing");
        boolean success = "success".equalsIgnoreCase(state);
        boolean notApplicable = "not_applicable".equalsIgnoreCase(state);
        boolean insufficient = "insufficient".equalsIgnoreCase(state);
        String metricCode = safeText(metric == null ? null : metric.code(),
                result == null ? null : result.metricCode(),
                "UNKNOWN_METRIC");
        Map<String, String> requestFactSource = requestFacts == null ? Map.of() : requestFacts;
        Map<String, String> promptFactSource = promptFacts == null ? Map.of() : promptFacts;
        String requestId = firstNonBlank(requestFactSource.get("requestId"), evidencePackage.getCorrelationId());
        String contextHash = firstNonBlank(promptFactSource.get("contextHash"), promptFactSource.get("canonicalContextHash"));
        String contextHashState = promptFactSource.get("contextHashState");
        Map<String, String> analysisFacts = new LinkedHashMap<>();
        analysisFacts.put("sourceMode", "CORE_OFFICIAL_SEALED_EVIDENCE");
        analysisFacts.put("metricContractVersion", OfficialPromptQualityMetricContractGate.CONTRACT_VERSION);
        analysisFacts.put("metricCode", metricCode);
        analysisFacts.put("sealedEvidenceIntegrity", String.valueOf(integrityValid));
        putIfPresent(analysisFacts, "sealedEvidencePackageId", evidencePackage.getPackageId());
        putIfPresent(analysisFacts, "promptHash", evidencePackage.getPromptHash());
        putIfPresent(analysisFacts, "contextHash", contextHash);
        putIfPresent(analysisFacts, "contextHashState", contextHashState);
        putIfPresent(analysisFacts, "contextHashStateReason", promptFactSource.get("contextHashStateReason"));
        putIfPresent(analysisFacts, "promptTextRef", "sealed_evidence_package#" + evidencePackage.getPackageId());

        Map<String, Object> rawEvidence = new LinkedHashMap<>();
        rawEvidence.put("sourceMode", "CORE_OFFICIAL_SEALED_EVIDENCE");
        rawEvidence.put("metricContractVersion", OfficialPromptQualityMetricContractGate.CONTRACT_VERSION);
        rawEvidence.put("metricState", state);
        rawEvidence.put("sealedEvidenceIntegrity", integrityValid);
        rawEvidence.put("aggregateRunId", aggregateRunId);
        putObjectIfPresent(rawEvidence, "packageId", evidencePackage.getPackageId());
        putObjectIfPresent(rawEvidence, "promptTextRef", "sealed_evidence_package#" + evidencePackage.getPackageId());
        putObjectIfPresent(rawEvidence, "requestId", requestId);
        putObjectIfPresent(rawEvidence, "correlationId", evidencePackage.getCorrelationId());
        putObjectIfPresent(rawEvidence, "promptHash", evidencePackage.getPromptHash());
        putObjectIfPresent(rawEvidence, "contextHash", contextHash);
        putObjectIfPresent(rawEvidence, "contextHashState", contextHashState);
        putObjectIfPresent(rawEvidence, "contextHashStateReason", promptFactSource.get("contextHashStateReason"));
        putObjectIfPresent(rawEvidence, "tenantId", evidencePackage.getTenantId());
        putObjectIfPresent(rawEvidence, "userId", evidencePackage.getUserId());
        putObjectIfPresent(rawEvidence, "rawSystemPromptHash", promptFactSource.get("rawSystemPromptHash"));
        putObjectIfPresent(rawEvidence, "rawUserPromptHash", promptFactSource.get("rawUserPromptHash"));
        putObjectIfPresent(rawEvidence, "systemPromptHash", promptFactSource.get("systemPromptHash"));
        putObjectIfPresent(rawEvidence, "userPromptHash", promptFactSource.get("userPromptHash"));
        putObjectIfPresent(rawEvidence, "rawSystemPromptRef", promptFactSource.get("rawSystemPromptRef"));
        putObjectIfPresent(rawEvidence, "rawUserPromptRef", promptFactSource.get("rawUserPromptRef"));
        putObjectIfPresent(rawEvidence, "systemPromptTextRef", promptFactSource.get("systemPromptTextRef"));
        putObjectIfPresent(rawEvidence, "userPromptTextRef", promptFactSource.get("userPromptTextRef"));
        Map<String, String> eventFacts = new LinkedHashMap<>();
        putIfPresent(eventFacts, "sealedEvidencePackageId", evidencePackage.getPackageId());
        putIfPresent(eventFacts, "requestId", requestId);
        putIfPresent(eventFacts, "correlationId", evidencePackage.getCorrelationId());
        putIfPresent(eventFacts, "promptHash", evidencePackage.getPromptHash());
        putIfPresent(eventFacts, "contextHash", contextHash);
        putIfPresent(eventFacts, "contextHashState", contextHashState);

        return new SealedEvidenceOfficialRunView(
                safeText(aggregateRunId, "official-run") + "-" + metricCode.toLowerCase(),
                1,
                metricCode,
                requestPath,
                requestId,
                score,
                passed,
                total,
                processingTime == null ? null : processingTime.toMillis(),
                state,
                success ? "success" : (notApplicable || insufficient ? "warning" : "danger"),
                messageForState(state),
                startedAt,
                completedAt,
                List.copyOf(checks),
                safeStringMap(requestFactSource),
                safeStringMap(eventFacts),
                safeStringMap(promptFactSource),
                safeStringMap(analysisFacts),
                List.of(new SealedEvidenceOfficialRunView.SealedEvidenceEventView(
                        "SEALED_EVIDENCE_REPLAY",
                        "CORE_OFFICIAL_RUNTIME",
                        success ? "PASS" : (notApplicable ? "NOT_APPLICABLE" : "BLOCKED"),
                        requestPath)),
                safeObjectMap(rawEvidence));
    }

    private List<OfficialMetricCheckObservation> safeChecks(
            List<OfficialMetricCheckObservation> checks) {
        if (checks == null || checks.isEmpty()) {
            return List.of();
        }
        for (int index = 0; index < checks.size(); index++) {
            if (checks.get(index) == null) {
                throw new IllegalStateException("Official sealed evidence run view cannot be created from a null check. checkIndex="
                        + index);
            }
        }
        return List.copyOf(checks);
    }

    private Map<String, String> safeStringMap(Map<String, String> values) {
        if (values == null || values.isEmpty()) {
            return Map.of();
        }
        Map<String, String> sanitized = new LinkedHashMap<>();
        values.forEach((key, value) -> {
            if (key != null && !key.isBlank() && value != null) {
                sanitized.put(key, value);
            }
        });
        return Map.copyOf(sanitized);
    }

    private Map<String, Object> safeObjectMap(Map<String, Object> values) {
        if (values == null || values.isEmpty()) {
            return Map.of();
        }
        Map<String, Object> sanitized = new LinkedHashMap<>();
        values.forEach((key, value) -> {
            if (key != null && !key.isBlank() && value != null) {
                sanitized.put(key, value);
            }
        });
        return Map.copyOf(sanitized);
    }

    private void putIfPresent(Map<String, String> target, String key, String value) {
        if (value != null && !value.isBlank()) {
            target.put(key, value);
        }
    }

    private void putObjectIfPresent(Map<String, Object> target, String key, String value) {
        if (value != null && !value.isBlank()) {
            target.put(key, value);
        }
    }

    private String messageForState(String state) {
        if ("success".equalsIgnoreCase(state)) {
            return "공식검사 지표가 기준을 충족했습니다.";
        }
        if ("not_applicable".equalsIgnoreCase(state)) {
            return "이 요청 증거에는 해당 지표가 적용되지 않습니다.";
        }
        if ("insufficient".equalsIgnoreCase(state)) {
            return "공식검사 지표를 확정하기에는 증거가 부족합니다.";
        }
        return "공식검사 지표가 보증서 발급 기준을 충족하지 못했습니다.";
    }

    private String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return null;
    }

    private String safeText(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value.trim();
    }

    private String safeText(String first, String second, String fallback) {
        String value = firstNonBlank(first, second);
        return value == null ? fallback : value;
    }
}
