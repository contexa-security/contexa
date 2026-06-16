package io.contexa.contexaiam.admin.promptquality.official.model;

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
        String whyItMatters) {

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
                "");
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
}

