package io.contexa.contexacore.verification.runtime.sealed;

import io.contexa.contexacore.verification.runtime.OfficialVerificationCheckResultView;
import io.contexa.contexacore.verification.runtime.OfficialVerificationEventItemView;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;

import java.util.List;
import java.util.Locale;
import java.util.Map;

public record SealedEvidenceOfficialRunView(
        String runId,
        int round,
        String endpointKey,
        String endpointLabel,
        String requestId,
        double score,
        int passedChecks,
        int totalChecks,
        Long processingTimeMs,
        String state,
        String stateTone,
        String message,
        String startedAt,
        String completedAt,
        List<SealedEvidenceCheckView> checks,
        Map<String, String> requestFacts,
        Map<String, String> eventFacts,
        Map<String, String> promptFacts,
        Map<String, String> analysisFacts,
        List<SealedEvidenceEventView> events,
        Map<String, Object> rawEvidence) implements OfficialVerificationRunView {

    public record SealedEvidenceCheckView(
            String checkCode,
            String label,
            String expectedValue,
            String actualValue,
            boolean pass,
            String source,
            String severity,
            String failureType,
            String remediationOwner,
            String operatorReason,
            String nextAction,
            String reverifyCriterion,
            String issueKey,
            boolean customerVisible,
            String readinessScope,
            String purposeVersion,
            String inputReadinessState,
            String purposeResult,
            String detectedSignalsJson,
            String interpretationLinksJson,
            String decisionUtility,
            String whyItMatters) implements OfficialVerificationCheckResultView {

        public SealedEvidenceCheckView(
                String checkCode,
                String label,
                String expectedValue,
                String actualValue,
                boolean pass,
                String source,
                String severity,
                String failureType,
                String remediationOwner,
                String operatorReason,
                String nextAction,
                String reverifyCriterion) {
            this(
                    checkCode,
                    label,
                    expectedValue,
                    actualValue,
                    pass,
                    source,
                    severity,
                    failureType,
                    remediationOwner,
                    operatorReason,
                    nextAction,
                    reverifyCriterion,
                    "",
                    defaultCustomerVisible(source),
                    defaultReadinessScope(source),
                    "",
                    "READY",
                    pass ? "PASSED" : "FAILED",
                    "[]",
                    "[]",
                    "",
                    "");
        }

        public SealedEvidenceCheckView(
                String checkCode,
                String label,
                String expectedValue,
                String actualValue,
                boolean pass,
                String source,
                String severity,
                String failureType,
                String remediationOwner,
                String operatorReason,
                String nextAction,
                String reverifyCriterion,
                boolean customerVisible,
                String readinessScope) {
            this(
                    checkCode,
                    label,
                    expectedValue,
                    actualValue,
                    pass,
                    source,
                    severity,
                    failureType,
                    remediationOwner,
                    operatorReason,
                    nextAction,
                    reverifyCriterion,
                    "",
                    customerVisible,
                    readinessScope);
        }

        public SealedEvidenceCheckView(
                String checkCode,
                String label,
                String expectedValue,
                String actualValue,
                boolean pass,
                String source,
                String severity,
                String failureType,
                String remediationOwner,
                String operatorReason,
                String nextAction,
                String reverifyCriterion,
                String issueKey,
                boolean customerVisible,
                String readinessScope) {
            this(
                    checkCode,
                    label,
                    expectedValue,
                    actualValue,
                    pass,
                    source,
                    severity,
                    failureType,
                    remediationOwner,
                    operatorReason,
                    nextAction,
                    reverifyCriterion,
                    issueKey,
                    customerVisible,
                    readinessScope,
                    "",
                    "READY",
                    pass ? "PASSED" : "FAILED",
                    "[]",
                    "[]",
                    "",
                    "");
        }

        public SealedEvidenceCheckView(
                String label,
                String expectedValue,
                String actualValue,
                boolean pass,
                String source) {
            this(
                    normalizeCheckCode(label),
                    label,
                    expectedValue,
                    actualValue,
                    pass,
                    source,
                    pass ? "INFO" : "BLOCKING",
                    pass ? "" : "OFFICIAL_CHECK_FAILED",
                    "PQA_RUNTIME",
                    "",
                    "",
                    "",
                    "",
                    defaultCustomerVisible(source),
                    defaultReadinessScope(source),
                    "",
                    "READY",
                    pass ? "PASSED" : "FAILED",
                    "[]",
                    "[]",
                    "",
                    "");
        }

        private static String normalizeCheckCode(String label) {
            if (label == null || label.isBlank()) {
                return "CHECK";
            }
            String normalized = label.trim()
                    .replaceAll("[^A-Za-z0-9]+", "_")
                    .replaceAll("^_+|_+$", "")
                    .toUpperCase(Locale.ROOT);
            return normalized.isBlank() ? "CHECK" : normalized;
        }

        private static boolean defaultCustomerVisible(String source) {
            return source == null || !source.trim().startsWith("internalGate.");
        }

        private static String defaultReadinessScope(String source) {
            return defaultCustomerVisible(source) ? "CUSTOMER_PROMPT_QUALITY" : "INTERNAL_EXECUTION_GATE";
        }
    }

    public record SealedEvidenceEventView(
            String type,
            String layer,
            String status,
            String requestPath) implements OfficialVerificationEventItemView {
    }
}
