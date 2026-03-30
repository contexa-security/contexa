package io.contexa.contexacore.autonomous.context;

import org.springframework.util.StringUtils;

import java.util.List;

public final class PromptRelevantRequestPathPolicy {

    private static final List<String> NOISE_PATH_FRAGMENTS = List.of(
            "/api/test-action/status",
            "/api/sse/llm-analysis/",
            "/api/security-test/evidence/");

    private PromptRelevantRequestPathPolicy() {
    }

    public static boolean isPromptRelevantPath(String requestPath) {
        return isPromptRelevantText(requestPath);
    }

    public static boolean isPromptRelevantActionSummary(String actionSummary) {
        return isPromptRelevantText(actionSummary);
    }

    private static boolean isPromptRelevantText(String value) {
        if (!StringUtils.hasText(value)) {
            return false;
        }
        String normalized = value.trim().toLowerCase();
        for (String fragment : NOISE_PATH_FRAGMENTS) {
            if (normalized.contains(fragment)) {
                return false;
            }
        }
        return true;
    }
}
