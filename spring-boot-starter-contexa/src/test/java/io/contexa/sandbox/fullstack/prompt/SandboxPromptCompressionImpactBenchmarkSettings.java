package io.contexa.sandbox.fullstack.prompt;

import java.util.Locale;

public final class SandboxPromptCompressionImpactBenchmarkSettings {

    private static final String BASELINE_PROFILE = "sandbox.compression.baseline-profile";
    private static final String CANDIDATE_PROFILE = "sandbox.compression.candidate-profile";
    private static final String COMPARISON_ID = "sandbox.compression.comparison-id";

    private SandboxPromptCompressionImpactBenchmarkSettings() {
    }

    public static String baselineProfile() {
        return sanitizeProfile(System.getProperty(BASELINE_PROFILE), "CORTEX_L1_EXPANDED");
    }

    public static String candidateProfile() {
        String fallback = SandboxDecisionBenchmarkSettings.useRealLlm()
                ? "CORTEX_L1_DECISION_COMPACT"
                : "CORTEX_L1_COMPACT";
        return sanitizeProfile(System.getProperty(CANDIDATE_PROFILE), fallback);
    }

    public static String comparisonId() {
        String configured = System.getProperty(COMPARISON_ID);
        if (configured != null && !configured.isBlank()) {
            return configured.trim();
        }
        return baselineProfile().toLowerCase(Locale.ROOT)
                + "-vs-"
                + candidateProfile().toLowerCase(Locale.ROOT);
    }

    private static String sanitizeProfile(String configured, String fallback) {
        if (configured == null || configured.isBlank()) {
            return fallback;
        }
        return configured.trim().toUpperCase(Locale.ROOT);
    }
}
