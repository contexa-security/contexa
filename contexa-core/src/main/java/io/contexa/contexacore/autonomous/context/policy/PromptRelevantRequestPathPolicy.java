package io.contexa.contexacore.autonomous.context.policy;

import org.springframework.util.StringUtils;

import java.util.List;

public final class PromptRelevantRequestPathPolicy {

    private static final List<String> NOISE_PATH_FRAGMENTS = List.of(
            "/admin/test/",
            "/test/",
            "/customlogin",
            "/admin/mfa/",
            "/login/mfa",
            "/api/test-action/status",
            "/api/sse/llm-analysis/",
            "/api/security-test/evidence/");

    private PromptRelevantRequestPathPolicy() {
    }

    public static boolean isPromptRelevantPath(String requestPath) {
        return isPromptRelevantText(requestPath);
    }

    public static boolean isPromptRelevantActionSummary(String actionSummary) {
        if (isGeneratedBehaviorSentence(actionSummary)) {
            return false;
        }
        return isPromptRelevantText(actionSummary);
    }

    private static boolean isGeneratedBehaviorSentence(String actionSummary) {
        if (!StringUtils.hasText(actionSummary)) {
            return false;
        }
        String normalized = actionSummary.trim().toLowerCase();
        return normalized.startsWith("user accessed ");
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
