package io.contexa.sandbox.fullstack.prompt;

import java.util.Locale;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public final class SandboxPromptCompressionImpactBenchmarkSettings {

    private static final String BASELINE_PROFILE = "sandbox.compression.baseline-profile";
    private static final String CANDIDATE_PROFILE = "sandbox.compression.candidate-profile";
    private static final String COMPARISON_ID = "sandbox.compression.comparison-id";
    private static final String PROFILE_MATRIX = "sandbox.compression.profile-matrix";
    private static final Set<String> KNOWN_PROFILES = Set.of(
            "CORTEX_L1_RAW_IDENTITY",
            "CORTEX_L1_STANDARD",
            "CORTEX_L1_COMPACT",
            "CORTEX_L1_DECISION_COMPACT",
            "CORTEX_L1_EXPANDED");

    private SandboxPromptCompressionImpactBenchmarkSettings() {
    }

    public static String baselineProfile() {
        return sanitizeProfile(System.getProperty(BASELINE_PROFILE), "CORTEX_L1_RAW_IDENTITY");
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

    public static String matrixId() {
        return String.join("-vs-",
                profileMatrix().stream()
                        .map(profile -> profile.toLowerCase(Locale.ROOT))
                        .toList());
    }

    public static List<String> profileMatrix() {
        String configured = System.getProperty(PROFILE_MATRIX);
        List<String> profiles;
        if (configured == null || configured.isBlank()) {
            profiles = SandboxDecisionBenchmarkSettings.useRealLlm()
                    ? List.of(
                    "CORTEX_L1_RAW_IDENTITY",
                    "CORTEX_L1_STANDARD",
                    "CORTEX_L1_COMPACT",
                    "CORTEX_L1_DECISION_COMPACT")
                    : List.of(
                    "CORTEX_L1_RAW_IDENTITY",
                    "CORTEX_L1_STANDARD",
                    "CORTEX_L1_COMPACT");
        } else {
            profiles = Arrays.stream(configured.split(","))
                    .map(String::trim)
                    .filter(value -> !value.isBlank())
                    .map(value -> value.toUpperCase(Locale.ROOT))
                    .filter(KNOWN_PROFILES::contains)
                    .toList();
        }

        LinkedHashSet<String> ordered = new LinkedHashSet<>(profiles);
        ordered.add(baselineProfile());
        ordered.add(candidateProfile());
        return List.copyOf(ordered);
    }

    private static String sanitizeProfile(String configured, String fallback) {
        if (configured == null || configured.isBlank()) {
            return fallback;
        }
        String normalized = configured.trim().toUpperCase(Locale.ROOT);
        return KNOWN_PROFILES.contains(normalized) ? normalized : fallback;
    }
}
