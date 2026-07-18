package io.contexa.contexaiam.admin.promptquality.official.application;

import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Matches normalized prompt text against scalar and list-like evidence values. */
final class RuntimeEvidencePromptValueMatcher {

    private RuntimeEvidencePromptValueMatcher() {
    }
    static boolean containsValue(String prompt, String value) {
        if (!StringUtils.hasText(prompt) || !StringUtils.hasText(value)) {
            return false;
        }
        String normalizedPrompt = prompt.toLowerCase(Locale.ROOT);
        String normalizedValue = value.trim().toLowerCase(Locale.ROOT);
        if (normalizedPrompt.contains(normalizedValue)) {
            return true;
        }
        List<String> tokens = comparableTokens(value);
        return tokens.size() > 1 && tokens.stream()
                .allMatch(token -> normalizedPrompt.contains(token.toLowerCase(Locale.ROOT)));
    }

    static List<String> comparableTokens(String value) {
        if (!StringUtils.hasText(value)) {
            return List.of();
        }
        String normalized = value.trim();
        if (normalized.startsWith("[") && normalized.endsWith("]") && normalized.length() > 1) {
            normalized = normalized.substring(1, normalized.length() - 1);
        }
        String[] parts = normalized.split(",");
        List<String> tokens = new ArrayList<>();
        for (String part : parts) {
            String token = part
                    .replace("\"", "")
                    .replace("'", "")
                    .trim();
            if (StringUtils.hasText(token)) {
                tokens.add(token);
            }
        }
        return tokens;
    }
}
