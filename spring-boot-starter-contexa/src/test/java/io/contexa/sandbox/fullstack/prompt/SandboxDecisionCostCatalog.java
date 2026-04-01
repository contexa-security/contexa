package io.contexa.sandbox.fullstack.prompt;

import java.util.Map;
import java.util.Locale;

final class SandboxDecisionCostCatalog {

    private static final Map<String, SandboxDecisionCostProfile> BUILT_IN_PROFILES = Map.of(
            "OLLAMA_LOCAL_REFERENCE",
            new SandboxDecisionCostProfile(
                    "OLLAMA_LOCAL_REFERENCE",
                    "Local Ollama infrastructure reference pricing",
                    "USD",
                    0.0d,
                    0.0d,
                    1.80d,
                    true),
            "OPENAI_GPT5_HIGH_REFERENCE",
            new SandboxDecisionCostProfile(
                    "OPENAI_GPT5_HIGH_REFERENCE",
                    "OpenAI GPT-5 high reasoning reference pricing",
                    "USD",
                    0.010d,
                    0.030d,
                    0.0d,
                    true),
            "ANTHROPIC_CLAUDE_REFERENCE",
            new SandboxDecisionCostProfile(
                    "ANTHROPIC_CLAUDE_REFERENCE",
                    "Anthropic Claude reference pricing",
                    "USD",
                    0.015d,
                    0.075d,
                    0.0d,
                    true));

    private SandboxDecisionCostCatalog() {
    }

    static SandboxDecisionCostProfile resolve() {
        String defaultProfile = SandboxDecisionBenchmarkSettings.useRealLlm()
                ? "OLLAMA_LOCAL_REFERENCE"
                : "UNCONFIGURED";
        String profileKey = property("sandbox.decision.cost.profile", defaultProfile)
                .trim()
                .toUpperCase(Locale.ROOT);
        SandboxDecisionCostProfile builtInProfile = BUILT_IN_PROFILES.get(profileKey);
        if (builtInProfile != null) {
            return builtInProfile;
        }
        String currencyCode = property("sandbox.decision.cost.currency", "USD");
        double inputCostPer1kTokens = doubleProperty("sandbox.decision.cost.input-per-1k", 0.0d);
        double outputCostPer1kTokens = doubleProperty("sandbox.decision.cost.output-per-1k", 0.0d);
        double infrastructureCostPerHour = doubleProperty("sandbox.decision.cost.infra-per-hour", 0.0d);
        boolean configured = inputCostPer1kTokens > 0.0d
                || outputCostPer1kTokens > 0.0d
                || infrastructureCostPerHour > 0.0d;
        String displayName = displayName(profileKey, configured, infrastructureCostPerHour);
        return new SandboxDecisionCostProfile(
                profileKey,
                displayName,
                currencyCode.trim().toUpperCase(Locale.ROOT),
                Math.max(0.0d, inputCostPer1kTokens),
                Math.max(0.0d, outputCostPer1kTokens),
                Math.max(0.0d, infrastructureCostPerHour),
                configured);
    }

    private static String displayName(String profileKey, boolean configured, double infrastructureCostPerHour) {
        if (!configured) {
            return "Unconfigured reference pricing";
        }
        if (infrastructureCostPerHour > 0.0d) {
            return profileKey + " reference pricing + local infrastructure hourly cost";
        }
        return profileKey + " reference token pricing";
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
