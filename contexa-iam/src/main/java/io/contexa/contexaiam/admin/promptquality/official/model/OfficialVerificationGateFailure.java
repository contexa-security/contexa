package io.contexa.contexaiam.admin.promptquality.official.model;

public record OfficialVerificationGateFailure(
        OfficialVerificationGateCode gateCode,
        String metricCode,
        String checkCode,
        String source,
        String expectedValue,
        String actualValue,
        String messageKey,
        String message,
        String nextAction) {

    public static OfficialVerificationGateFailure from(OfficialVerificationGateDecision decision) {
        if (decision == null || decision.passed()) {
            throw new IllegalArgumentException("A gate failure requires a failed gate decision.");
        }
        return new OfficialVerificationGateFailure(
                decision.gateCode(),
                decision.metricCode(),
                decision.checkCode(),
                decision.source(),
                decision.expectedValue(),
                decision.actualValue(),
                decision.messageKey(),
                decision.message(),
                decision.nextAction());
    }

    public OfficialVerificationGateFailure {
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
