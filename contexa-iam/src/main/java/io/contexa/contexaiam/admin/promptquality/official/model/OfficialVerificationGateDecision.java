package io.contexa.contexaiam.admin.promptquality.official.model;

public record OfficialVerificationGateDecision(
        OfficialVerificationGateCode gateCode,
        String metricCode,
        String checkCode,
        String source,
        String expectedValue,
        String actualValue,
        boolean passed,
        String messageKey,
        String message,
        String nextAction) {

    public OfficialVerificationGateDecision {
        gateCode = gateCode == null ? OfficialVerificationGateCode.UNCLASSIFIED : gateCode;
        messageKey = hasText(messageKey) ? messageKey : gateCode.messageKey();
        metricCode = value(metricCode);
        checkCode = value(checkCode);
        source = value(source);
        expectedValue = value(expectedValue);
        actualValue = value(actualValue);
        message = value(message);
        nextAction = value(nextAction);
    }

    private static String value(String value) {
        return value == null ? "" : value.trim();
    }

    private static boolean hasText(String value) {
        return value != null && !value.trim().isEmpty();
    }
}
