package io.contexa.contexacore.verification.metric;

public record OfficialMetricCheckObservation(
        String checkCode,
        String label,
        String expectedValue,
        String actualValue,
        boolean passed,
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
        String whyItMatters
) {
    public OfficialMetricCheckObservation(
            String checkCode,
            String label,
            String expectedValue,
            String actualValue,
            boolean passed,
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
                passed,
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
                passed ? "PURPOSE_PASSED" : "PURPOSE_FAILED",
                "[]",
                "[]",
                "",
                "");
    }

    public OfficialMetricCheckObservation(
            String checkCode,
            String label,
            String expectedValue,
            String actualValue,
            boolean passed,
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
                passed,
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
                passed ? "PURPOSE_PASSED" : "PURPOSE_FAILED",
                "[]",
                "[]",
                "",
                "");
    }

    public OfficialMetricCheckObservation(String label, boolean passed) {
        this(
                label,
                label,
                passed ? "pass" : "required",
                passed ? "pass" : "missing",
                passed,
                "",
                passed ? "INFO" : "BLOCKING",
                "",
                "",
                "",
                "",
                "",
                "",
                true,
                "CUSTOMER_PROMPT_QUALITY",
                "",
                "READY",
                passed ? "PURPOSE_PASSED" : "PURPOSE_FAILED",
                "[]",
                "[]",
                "",
                "");
    }

    private static boolean defaultCustomerVisible(String source) {
        String normalized = source == null ? "" : source.trim();
        return !normalized.startsWith("internalGate.");
    }

    private static String defaultReadinessScope(String source) {
        return defaultCustomerVisible(source) ? "CUSTOMER_PROMPT_QUALITY" : "INTERNAL_EXECUTION_GATE";
    }
}
