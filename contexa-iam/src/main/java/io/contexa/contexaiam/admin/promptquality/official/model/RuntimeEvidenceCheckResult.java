package io.contexa.contexaiam.admin.promptquality.official.model;

import java.util.Locale;

public record RuntimeEvidenceCheckResult(
        String metricCode,
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
        String whyItMatters) {

    public RuntimeEvidenceCheckResult(
            String metricCode,
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
                metricCode,
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
                pass ? "PURPOSE_PASSED" : "PURPOSE_FAILED",
                "[]",
                "[]",
                "",
                "");
    }

    public RuntimeEvidenceCheckResult(
            String metricCode,
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
                metricCode,
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
                pass ? "PURPOSE_PASSED" : "PURPOSE_FAILED",
                "[]",
                "[]",
                "",
                "");
    }

    public RuntimeEvidenceCheckResult(
            String metricCode,
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
                metricCode,
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

    public RuntimeEvidenceCheckResult(
            String metricCode,
            String label,
            String expectedValue,
            String actualValue,
            boolean pass,
            String source) {
        this(
                metricCode,
                normalizeCheckCode(label),
                label,
                expectedValue,
                actualValue,
                pass,
                source,
                pass ? "INFO" : "BLOCKING",
                pass ? "" : "OFFICIAL_CHECK_FAILED",
                "",
                "",
                "",
                "",
                "",
                defaultCustomerVisible(source),
                defaultReadinessScope(source),
                "",
                "READY",
                pass ? "PURPOSE_PASSED" : "PURPOSE_FAILED",
                "[]",
                "[]",
                "",
                "");
    }

    private static boolean defaultCustomerVisible(String source) {
        return source == null || !source.trim().startsWith("internalGate.");
    }

    private static String defaultReadinessScope(String source) {
        return defaultCustomerVisible(source) ? "CUSTOMER_PROMPT_QUALITY" : "INTERNAL_EXECUTION_GATE";
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
}
