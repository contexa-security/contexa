package io.contexa.contexacore.autonomous.saas.learning;

import org.springframework.util.StringUtils;

/**
 * Common guardrail entry for learning artifacts.
 */
public record LearningArtifactGuardrail(
        String code,
        String summary,
        boolean blocking) {

    public LearningArtifactGuardrail {
        code = normalizeRequired(code, "code");
        summary = normalizeRequired(summary, "summary");
    }

    private static String normalizeRequired(String value, String fieldName) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException(fieldName + " is required");
        }
        return value.trim();
    }
}
