package io.contexa.sandbox.fullstack.prompt;

import java.util.Locale;

final class SandboxDecisionCostCatalog {

    private SandboxDecisionCostCatalog() {
    }

    static SandboxDecisionCostProfile resolve() {
        String profileKey = property("sandbox.decision.cost.profile", "UNCONFIGURED");
        String currencyCode = property("sandbox.decision.cost.currency", "USD");
        double inputCostPer1kTokens = doubleProperty("sandbox.decision.cost.input-per-1k", 0.0d);
        double outputCostPer1kTokens = doubleProperty("sandbox.decision.cost.output-per-1k", 0.0d);
        boolean configured = inputCostPer1kTokens > 0.0d || outputCostPer1kTokens > 0.0d;
        String displayName = configured
                ? profileKey + " reference token pricing"
                : "Unconfigured reference pricing";
        return new SandboxDecisionCostProfile(
                profileKey.trim().toUpperCase(Locale.ROOT),
                displayName,
                currencyCode.trim().toUpperCase(Locale.ROOT),
                Math.max(0.0d, inputCostPer1kTokens),
                Math.max(0.0d, outputCostPer1kTokens),
                configured);
    }

    private static String property(String key, String fallback) {
        String configured = System.getProperty(key);
        return configured != null && !configured.isBlank() ? configured.trim() : fallback;
    }

    private static double doubleProperty(String key, double fallback) {
        String configured = System.getProperty(key);
        if (configured == null || configured.isBlank()) {
            return fallback;
        }
        try {
            return Double.parseDouble(configured.trim());
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }
}
