package io.contexa.contexaiam.admin.promptquality.official.model;

import io.contexa.contexacore.verification.runtime.OfficialVerificationCheckState;

import java.util.Locale;

public record OfficialRunCheckDetail(
        int sequence,
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
        String sourceMeaning,
        String remediationHint,
        String reverifyCriterion,
        String decisionUtility,
        String whyItMatters,
        OfficialVerificationCheckState evaluationState,
        boolean customerVisible,
        boolean operatorVisible,
        String readinessScope,
        String purposeResult) {

    public OfficialRunCheckDetail(
            int sequence,
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
            String sourceMeaning,
            String remediationHint,
            String reverifyCriterion,
            String decisionUtility,
            String whyItMatters) {
        this(
                sequence, checkCode, label, expectedValue, actualValue, pass, source, severity,
                failureType, remediationOwner, operatorReason, nextAction, sourceMeaning,
                remediationHint, reverifyCriterion, decisionUtility, whyItMatters,
                pass ? OfficialVerificationCheckState.PASS : OfficialVerificationCheckState.FAIL,
                defaultCustomerVisible(source), true, defaultReadinessScope(source),
                pass ? "PASSED" : "FAILED");
    }

    public OfficialRunCheckDetail(
            int sequence,
            String label,
            String expectedValue,
            String actualValue,
            boolean pass,
            String source,
            String sourceMeaning,
            String remediationHint,
            String reverifyCriterion) {
        this(
                sequence,
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
                sourceMeaning,
                remediationHint,
                reverifyCriterion,
                "",
                "",
                pass ? OfficialVerificationCheckState.PASS : OfficialVerificationCheckState.FAIL,
                defaultCustomerVisible(source), true, defaultReadinessScope(source),
                pass ? "PASSED" : "FAILED");
    }

    public OfficialRunCheckDetail(
            int sequence,
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
            String sourceMeaning,
            String remediationHint,
            String reverifyCriterion) {
        this(
                sequence,
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
                sourceMeaning,
                remediationHint,
                reverifyCriterion,
                "",
                "",
                pass ? OfficialVerificationCheckState.PASS : OfficialVerificationCheckState.FAIL,
                defaultCustomerVisible(source), true, defaultReadinessScope(source),
                pass ? "PASSED" : "FAILED");
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
