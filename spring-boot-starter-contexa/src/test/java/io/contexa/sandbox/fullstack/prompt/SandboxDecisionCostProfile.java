package io.contexa.sandbox.fullstack.prompt;

public record SandboxDecisionCostProfile(
        String profileKey,
        String displayName,
        String currencyCode,
        double inputCostPer1kTokens,
        double outputCostPer1kTokens,
        boolean configured) {

    public SandboxDecisionCostProfile {
        profileKey = requireText(profileKey, "profileKey");
        displayName = requireText(displayName, "displayName");
        currencyCode = requireText(currencyCode, "currencyCode");
    }

    private static String requireText(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value;
    }
}
